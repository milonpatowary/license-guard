'use strict'

const crypto = require('crypto')
const { ConfigurationError } = require('./errors')

/**
 * Ed25519 keys, carried around as short strings instead of PEM blocks.
 *
 * Ed25519 keys are 32 bytes. PEM wraps them in ASN.1 and line breaks, which is
 * the correct interchange format and a terrible thing to paste into a config
 * file or embed in a source file. So the strings here are the raw 32 bytes in
 * base64url with a prefix that says which half it is:
 *
 *   lgpk1_…   public  — embedded in the client, ships to every customer
 *   lgsk1_…   secret  — never leaves your signing machine or Worker secret
 *
 * The prefix is not decoration. A public and a secret Ed25519 key are both 32
 * base64url-ish characters, and the failure mode of confusing them is
 * committing your signing key to a public repository. Anything that takes a
 * public key here rejects a string beginning `lgsk1_` outright.
 *
 * ASN.1 is still what node:crypto wants, so the two fixed prefixes below turn
 * raw bytes into DER. They are constant because the algorithm identifier and
 * every length in an Ed25519 key structure are constant.
 */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

const PUBLIC_PREFIX = 'lgpk1_'
const SECRET_PREFIX = 'lgsk1_'

/** A fresh signing keypair. Run once, ever, per product line. */
function generateKeyPair () {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  const jwk = privateKey.export({ format: 'jwk' })
  return {
    publicKey: PUBLIC_PREFIX + publicKey.export({ format: 'jwk' }).x,
    secretKey: SECRET_PREFIX + jwk.d,
    // Cloudflare Workers' WebCrypto imports PKCS8 or JWK, not raw private
    // bytes, so the Worker secret is handed over pre-encoded.
    workerSecret: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  }
}

function seedToPrivateKey (seed) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8'
  })
}

/** `lgsk1_…` → a KeyObject that can sign. */
function importSecretKey (value) {
  if (value && typeof value === 'object' && value.type === 'private') return value
  if (typeof value !== 'string' || !value.startsWith(SECRET_PREFIX)) {
    throw new ConfigurationError(`A secret key must be a string beginning "${SECRET_PREFIX}".`)
  }
  const seed = decode32(value.slice(SECRET_PREFIX.length), 'secret key')
  return seedToPrivateKey(seed)
}

/** `lgpk1_…` → a KeyObject that can verify. */
function importPublicKey (value) {
  if (value && typeof value === 'object' && value.type === 'public') return value
  if (typeof value !== 'string') {
    throw new ConfigurationError(`A public key must be a string beginning "${PUBLIC_PREFIX}".`)
  }
  if (value.startsWith(SECRET_PREFIX)) {
    throw new ConfigurationError(
      'That is a secret key, not a public key. The public key is the one that gets embedded in ' +
      'the code you ship; if a secret key has reached a place that wanted a public one, treat it ' +
      'as disclosed and rotate it.'
    )
  }
  if (!value.startsWith(PUBLIC_PREFIX)) {
    throw new ConfigurationError(`A public key must be a string beginning "${PUBLIC_PREFIX}".`)
  }
  const raw = decode32(value.slice(PUBLIC_PREFIX.length), 'public key')
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki'
  })
}

/** The public half of a secret key, so an issuer never has to store both. */
function publicKeyFor (secretKey) {
  const jwk = crypto.createPublicKey(importSecretKey(secretKey)).export({ format: 'jwk' })
  return PUBLIC_PREFIX + jwk.x
}

function decode32 (encoded, what) {
  let bytes
  try {
    bytes = Buffer.from(encoded, 'base64url')
  } catch {
    throw new ConfigurationError(`This ${what} is not valid base64url.`)
  }
  if (bytes.length !== 32) {
    throw new ConfigurationError(
      `This ${what} decodes to ${bytes.length} bytes; an Ed25519 key is 32. It is probably truncated.`
    )
  }
  return bytes
}

module.exports = {
  generateKeyPair,
  importSecretKey,
  importPublicKey,
  publicKeyFor,
  PUBLIC_PREFIX,
  SECRET_PREFIX
}
