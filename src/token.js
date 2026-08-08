'use strict'

const crypto = require('crypto')
const { importSecretKey, importPublicKey } = require('./keys')
const {
  LicenseInvalidError,
  LicenseMismatchError,
  LicenseExpiredError,
  ConfigurationError
} = require('./errors')

/**
 * The licence token: a signed statement, small enough to sit in a config file.
 *
 *   lgt1.<base64url(payload JSON)>.<base64url(64-byte Ed25519 signature)>
 *
 * It looks like a JWT and deliberately is not one. JWTs carry an algorithm
 * field inside the part the attacker controls, and the history of that design
 * is a long list of libraries that were talked into `alg: none` or into
 * verifying an RSA public key as an HMAC secret. There is exactly one
 * algorithm here, it is not negotiable, and it is not written down anywhere a
 * forger could edit.
 *
 * The signature covers `lgt1.<payload>` — version prefix included — so a
 * signature issued under this format can never be replayed under a future one.
 */
const VERSION = 'lgt1'

/**
 * Claims, three-letter like JWT's because tokens end up in environment
 * variables and every byte is a byte someone has to paste.
 *
 *   jti    token id, unique per issue — what a revocation list names
 *   iss    issuer, your licence server's host
 *   prd    product id this token unlocks
 *   lic    licence id (the customer's subscription, not their secret key)
 *   cus    customer label, for your own reports
 *   fp     the deployment fingerprint this token is bound to
 *   wm     watermark: a per-licence value the product can stamp into its output
 *   plan   plan name, for feature gating
 *   fea    feature flags this licence includes
 *   seats  how many distinct deployments the licence allows
 *   iat    issued at (seconds)
 *   exp    expires at (seconds) — short, because the heartbeat renews it
 *   grc    seconds of grace *after* exp during which the product keeps running
 *   hbt    how often the client should check in (seconds)
 */
function sign (claims, secretKey) {
  if (!claims || typeof claims !== 'object') {
    throw new ConfigurationError('sign() needs a claims object.')
  }
  for (const required of ['prd', 'lic', 'exp']) {
    if (claims[required] === undefined) {
      throw new ConfigurationError(`Claim "${required}" is required.`)
    }
  }
  const body = base64url(Buffer.from(JSON.stringify(claims), 'utf8'))
  const signingInput = `${VERSION}.${body}`
  const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), importSecretKey(secretKey))
  return `${signingInput}.${base64url(signature)}`
}

/**
 * Read a token without checking anything.
 *
 * Useful for logging and for the CLI's `inspect`, and dangerous everywhere
 * else — the name says so on purpose. Nothing in the runtime path calls it.
 */
function decodeUnverified (token) {
  const parts = split(token)
  return parseClaims(parts.body)
}

/**
 * Verify a token and decide what it means right now.
 *
 * Returns `{ claims, state, expiresAt, graceEndsAt }` where state is one of:
 *
 *   'active'    signature good, inside `exp`
 *   'grace'     past `exp`, inside `exp + grc`. Everything still works; the
 *               caller is expected to keep trying to renew.
 *
 * Anything worse throws, and which error it throws decides whether the product
 * stops — see errors.js. A forged signature is fatal. A token that ran out of
 * road while the server was unreachable is not.
 */
function verify (token, publicKey, {
  now = Date.now(),
  product = null,
  fingerprint = null,
  clockSkewSeconds = 300
} = {}) {
  const { body, signature, signingInput } = split(token)

  let signatureBytes
  try {
    signatureBytes = Buffer.from(signature, 'base64url')
  } catch {
    throw new LicenseInvalidError('The token signature is not valid base64url.')
  }
  if (signatureBytes.length !== 64) {
    throw new LicenseInvalidError(
      `The token signature is ${signatureBytes.length} bytes; an Ed25519 signature is 64.`
    )
  }

  const ok = crypto.verify(
    null,
    Buffer.from(signingInput, 'ascii'),
    importPublicKey(publicKey),
    signatureBytes
  )
  if (!ok) {
    throw new LicenseInvalidError(
      'The token signature does not verify. Either the token was edited, or it was signed by a ' +
      'different key than the one this build trusts.'
    )
  }

  const claims = parseClaims(body)
  const nowSeconds = Math.floor(now / 1000)

  // Binding checks come after the signature, never before: until the signature
  // verifies, every field is attacker-controlled and comparing them is theatre.
  if (product && claims.prd !== product) {
    throw new LicenseMismatchError(
      `This token is for product "${claims.prd}", not "${product}".`,
      { expected: product, actual: claims.prd }
    )
  }
  if (fingerprint && claims.fp && claims.fp !== fingerprint) {
    throw new LicenseMismatchError(
      'This token was issued to a different deployment. Licence tokens are bound to the machine ' +
      'that activated them; copying one to another host does not carry the licence with it.',
      { expected: fingerprint, actual: claims.fp }
    )
  }
  if (claims.nbf && nowSeconds + clockSkewSeconds < claims.nbf) {
    throw new LicenseInvalidError('This token is not valid yet.', { notBefore: claims.nbf })
  }

  const grace = Number(claims.grc) || 0
  const expiredAt = claims.exp + clockSkewSeconds
  const graceEndsAt = claims.exp + grace + clockSkewSeconds

  if (nowSeconds > graceEndsAt) {
    throw new LicenseExpiredError(
      `This licence token expired ${describeAge(nowSeconds - claims.exp)} ago and its grace ` +
      'window has run out.',
      { exp: claims.exp, grace }
    )
  }

  return {
    claims,
    state: nowSeconds > expiredAt ? 'grace' : 'active',
    expiresAt: claims.exp * 1000,
    graceEndsAt: (claims.exp + grace) * 1000
  }
}

function split (token) {
  if (typeof token !== 'string' || token.length === 0) {
    throw new LicenseInvalidError('No licence token was supplied.')
  }
  const parts = token.trim().split('.')
  if (parts.length !== 3) {
    throw new LicenseInvalidError(
      `A licence token has three dot-separated parts; this one has ${parts.length}.`
    )
  }
  const [version, body, signature] = parts
  if (version !== VERSION) {
    throw new LicenseInvalidError(
      `Unknown token version "${version}". This build understands "${VERSION}".`
    )
  }
  return { body, signature, signingInput: `${version}.${body}` }
}

function parseClaims (body) {
  let json
  try {
    json = Buffer.from(body, 'base64url').toString('utf8')
  } catch {
    throw new LicenseInvalidError('The token payload is not valid base64url.')
  }
  let claims
  try {
    claims = JSON.parse(json)
  } catch {
    throw new LicenseInvalidError('The token payload is not valid JSON.')
  }
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new LicenseInvalidError('The token payload is not an object.')
  }
  if (typeof claims.exp !== 'number') {
    throw new LicenseInvalidError('The token has no numeric "exp" claim.')
  }
  return claims
}

function base64url (buffer) {
  return buffer.toString('base64url')
}

function describeAge (seconds) {
  if (seconds < 90) return `${seconds} seconds`
  if (seconds < 5400) return `${Math.round(seconds / 60)} minutes`
  if (seconds < 172800) return `${Math.round(seconds / 3600)} hours`
  return `${Math.round(seconds / 86400)} days`
}

module.exports = { sign, verify, decodeUnverified, VERSION }
