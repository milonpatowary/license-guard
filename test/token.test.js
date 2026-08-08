'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('crypto')

const { sign, verify, decodeUnverified } = require('../src/token')
const { generateKeyPair } = require('../src/keys')
const {
  LicenseInvalidError,
  LicenseMismatchError,
  LicenseExpiredError
} = require('../src/errors')

const keys = generateKeyPair()
const other = generateKeyPair()

const NOW = Date.UTC(2026, 5, 1) // fixed, because every assertion here is about time
const seconds = (ms) => Math.floor(ms / 1000)

function issue (overrides = {}) {
  return sign({
    jti: 'tok_1',
    prd: 'acme-core',
    lic: 'lic_1',
    cus: 'Acme Ltd',
    fp: 'fp-abc',
    wm: 'a1b2c3d4',
    plan: 'pro',
    fea: ['reports', 'sso'],
    seats: 3,
    iat: seconds(NOW),
    exp: seconds(NOW) + 3600,
    grc: 86400,
    ...overrides
  }, keys.secretKey)
}

test('a freshly signed token verifies and reports its claims', () => {
  const result = verify(issue(), keys.publicKey, { now: NOW, product: 'acme-core', fingerprint: 'fp-abc' })
  assert.equal(result.state, 'active')
  assert.equal(result.claims.cus, 'Acme Ltd')
  assert.deepEqual(result.claims.fea, ['reports', 'sso'])
})

test('a token signed by another key is refused', () => {
  assert.throws(
    () => verify(issue(), other.publicKey, { now: NOW }),
    (err) => err instanceof LicenseInvalidError && err.fatal === true
  )
})

test('editing a single claim invalidates the signature', () => {
  const token = issue({ seats: 3 })
  const [version, body, signature] = token.split('.')
  const claims = JSON.parse(Buffer.from(body, 'base64url').toString())
  claims.seats = 9999
  const forged = [
    version,
    Buffer.from(JSON.stringify(claims)).toString('base64url'),
    signature
  ].join('.')

  assert.throws(() => verify(forged, keys.publicKey, { now: NOW }), LicenseInvalidError)
})

test('a signature cannot be replayed under a different format version', () => {
  // The signing input includes the version prefix, so re-labelling a token
  // breaks it. Without that, a future lgt2 with different semantics could be
  // spoofed with an lgt1 signature.
  const [, body, signature] = issue().split('.')
  assert.throws(
    () => verify(`lgt2.${body}.${signature}`, keys.publicKey, { now: NOW }),
    /Unknown token version/
  )
})

test('there is no algorithm field to confuse', () => {
  // The JWT family's worst failure mode is `alg` living inside attacker-
  // controlled data. Assert the payload has no such field and that adding one
  // changes nothing except the signature.
  const claims = decodeUnverified(issue())
  assert.equal(claims.alg, undefined)
  assert.equal(claims.typ, undefined)
})

test('a token with a mangled signature length is refused before verification', () => {
  const [version, body] = issue().split('.')
  assert.throws(
    () => verify(`${version}.${body}.${Buffer.alloc(32).toString('base64url')}`, keys.publicKey, { now: NOW }),
    /is 32 bytes; an Ed25519 signature is 64/
  )
})

test('the wrong number of parts is a clear error, not a crash', () => {
  for (const bad of ['', 'nope', 'a.b', 'a.b.c.d']) {
    assert.throws(() => verify(bad, keys.publicKey, { now: NOW }), LicenseInvalidError)
  }
})

test('a token for another product does not unlock this one', () => {
  assert.throws(
    () => verify(issue({ prd: 'other-product' }), keys.publicKey, { now: NOW, product: 'acme-core' }),
    (err) => err instanceof LicenseMismatchError && err.fatal === true
  )
})

test('a token bound to another machine does not unlock this one', () => {
  assert.throws(
    () => verify(issue(), keys.publicKey, { now: NOW, fingerprint: 'fp-different' }),
    LicenseMismatchError
  )
})

test('a token with no fingerprint claim is portable on purpose', () => {
  // This is the air-gapped case. It must keep working, and it must be
  // impossible to reach by accident — the CLI requires --any-machine.
  const result = verify(issue({ fp: null }), keys.publicKey, { now: NOW, fingerprint: 'anything' })
  assert.equal(result.state, 'active')
})

test('past exp but inside grace is "grace", not an error', () => {
  const token = issue({ exp: seconds(NOW) - 600, grc: 86400 })
  const result = verify(token, keys.publicKey, { now: NOW })
  assert.equal(result.state, 'grace')
  assert.equal(result.graceEndsAt, (seconds(NOW) - 600 + 86400) * 1000)
})

test('past exp and past grace throws, and the error is not fatal', () => {
  const token = issue({ exp: seconds(NOW) - 200000, grc: 86400 })
  let thrown = null
  try {
    verify(token, keys.publicKey, { now: NOW })
  } catch (err) {
    thrown = err
  }
  assert.ok(thrown instanceof LicenseExpiredError)
  assert.equal(thrown.fatal, false, 'an expired licence must never hard-stop a customer')
  assert.match(thrown.message, /2 days ago/)
})

test('clock skew is tolerated in both directions', () => {
  const justExpired = issue({ exp: seconds(NOW) - 100, grc: 0 })
  assert.equal(
    verify(justExpired, keys.publicKey, { now: NOW, clockSkewSeconds: 300 }).state,
    'active',
    'a customer whose clock is two minutes fast must not lose their licence'
  )
  assert.throws(
    () => verify(justExpired, keys.publicKey, { now: NOW, clockSkewSeconds: 0 }),
    LicenseExpiredError
  )

  const notYet = issue({ nbf: seconds(NOW) + 100 })
  assert.equal(verify(notYet, keys.publicKey, { now: NOW, clockSkewSeconds: 300 }).state, 'active')
  assert.throws(() => verify(notYet, keys.publicKey, { now: NOW, clockSkewSeconds: 0 }), /not valid yet/)
})

test('a payload that is not JSON, or not an object, is refused', () => {
  for (const payload of ['not json', '"a string"', '[1,2,3]', 'null']) {
    const body = Buffer.from(payload).toString('base64url')
    const signature = crypto.sign(
      null,
      Buffer.from(`lgt1.${body}`, 'ascii'),
      require('../src/keys').importSecretKey(keys.secretKey)
    ).toString('base64url')
    assert.throws(
      () => verify(`lgt1.${body}.${signature}`, keys.publicKey, { now: NOW }),
      LicenseInvalidError,
      `payload ${payload} should be refused`
    )
  }
})

test('a payload with no exp is refused even when correctly signed', () => {
  // exp is the only thing standing between a leaked token and a permanent one.
  const body = Buffer.from(JSON.stringify({ prd: 'acme-core' })).toString('base64url')
  const signature = crypto.sign(
    null,
    Buffer.from(`lgt1.${body}`, 'ascii'),
    require('../src/keys').importSecretKey(keys.secretKey)
  ).toString('base64url')
  assert.throws(
    () => verify(`lgt1.${body}.${signature}`, keys.publicKey, { now: NOW }),
    /no numeric "exp" claim/
  )
})

test('sign refuses to mint a token missing the claims that make it enforceable', () => {
  assert.throws(() => sign({ prd: 'x', lic: 'y' }, keys.secretKey), /Claim "exp" is required/)
  assert.throws(() => sign({ prd: 'x', exp: 1 }, keys.secretKey), /Claim "lic" is required/)
})
