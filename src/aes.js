'use strict'

const crypto = require('crypto')
const { CoreIntegrityError, ConfigurationError } = require('./errors')

/**
 * AES-256-GCM, with the associated data actually used.
 *
 * GCM is authenticated encryption, which matters more here than the secrecy
 * does. An attacker who cannot read your core module can still try to *edit*
 * it — flip the bytes of the licence check, splice in a different payload — and
 * a plain AES-CTR blob would decrypt the tampered ciphertext into tampered
 * source and hand it straight to the module loader. GCM's tag makes that fail
 * loudly instead.
 *
 * The AAD parameter is what binds a ciphertext to its header. The core bundle's
 * metadata (which product, which version, which customer) sits in the clear so
 * the loader can read it before it has a key; passing that same metadata as
 * associated data means an attacker cannot take a v2 payload, relabel the
 * header as v1, and get anything but an authentication failure.
 */
const IV_BYTES = 12
const TAG_BYTES = 16

function normalizeKey (key, what = 'key') {
  const bytes = typeof key === 'string' ? Buffer.from(key, 'base64') : Buffer.from(key)
  if (bytes.length !== 32) {
    throw new ConfigurationError(
      `An AES-256 ${what} is 32 bytes; this one is ${bytes.length}.`
    )
  }
  return bytes
}

function seal (plaintext, key, aad = Buffer.alloc(0)) {
  const iv = crypto.randomBytes(IV_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', normalizeKey(key), iv)
  if (aad.length) cipher.setAAD(aad)
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()])
  return { iv, tag: cipher.getAuthTag(), body }
}

function open ({ iv, tag, body }, key, aad = Buffer.alloc(0), what = 'payload') {
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new CoreIntegrityError(`The ${what} header is malformed.`)
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', normalizeKey(key), iv)
  if (aad.length) decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    // node:crypto reports every GCM failure as "Unsupported state or unable to
    // authenticate data", which tells the operator nothing. The two things it
    // actually means are worth saying.
    throw new CoreIntegrityError(
      `The ${what} failed authentication. Either the key is wrong, or the bytes have been altered ` +
      'since they were written.'
    )
  }
}

function randomKey () {
  return crypto.randomBytes(32)
}

module.exports = { seal, open, randomKey, normalizeKey, IV_BYTES, TAG_BYTES }
