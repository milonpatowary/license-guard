'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('crypto')

const {
  generateKeyPair, importPublicKey, importSecretKey, publicKeyFor, workerSecretFor
} = require('../src/keys')
const { ConfigurationError } = require('../src/errors')

test('a generated pair round-trips through node:crypto', () => {
  const { publicKey, secretKey } = generateKeyPair()
  const message = Buffer.from('anything')
  const signature = crypto.sign(null, message, importSecretKey(secretKey))
  assert.equal(crypto.verify(null, message, importPublicKey(publicKey), signature), true)
})

test('the public key can be recovered from the secret key', () => {
  const { publicKey, secretKey } = generateKeyPair()
  assert.equal(publicKeyFor(secretKey), publicKey)
})

test('the worker secret is the same key in the format WebCrypto imports', async () => {
  // This is the interop that decides whether the Worker can sign tokens the
  // client accepts. Both halves are exercised here rather than assumed.
  const { publicKey, workerSecret } = generateKeyPair()
  const pkcs8 = Uint8Array.from(Buffer.from(workerSecret, 'base64'))
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])

  const message = new TextEncoder().encode('lgt1.payload')
  const signature = await crypto.subtle.sign('Ed25519', key, message)

  assert.equal(new Uint8Array(signature).length, 64)
  assert.equal(
    crypto.verify(null, Buffer.from(message), importPublicKey(publicKey), Buffer.from(signature)),
    true,
    'a Worker-signed token must verify against the embedded public key'
  )
})

test('passing a secret key where a public one belongs is refused loudly', () => {
  // The two are indistinguishable by shape — 32 bytes of base64url — and the
  // consequence of mixing them up is a signing key in a public repository.
  const { secretKey } = generateKeyPair()
  assert.throws(
    () => importPublicKey(secretKey),
    (err) => err instanceof ConfigurationError && /treat it as disclosed and rotate it/.test(err.message)
  )
})

test('a truncated key says so instead of failing somewhere deeper', () => {
  const { publicKey } = generateKeyPair()
  assert.throws(
    () => importPublicKey(publicKey.slice(0, 20)),
    /decodes to \d+ bytes; an Ed25519 key is 32/
  )
})

test('an unprefixed key is refused', () => {
  assert.throws(() => importPublicKey(crypto.randomBytes(32).toString('base64url')), ConfigurationError)
  assert.throws(() => importSecretKey('lgpk1_' + crypto.randomBytes(32).toString('base64url')), ConfigurationError)
})

test('an already-imported KeyObject passes straight through', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  assert.equal(importSecretKey(privateKey), privateKey)
  assert.equal(importPublicKey(publicKey), publicKey)
})

test('the whole keypair can be rebuilt from the secret key alone', () => {
  // This is what lets you keep exactly one value in a password manager. If it
  // ever stopped holding, the stored secret would silently no longer match the
  // deployed Worker, and every token issued would fail verification on every
  // customer's machine at once.
  const original = generateKeyPair()

  assert.equal(publicKeyFor(original.secretKey), original.publicKey)
  assert.equal(workerSecretFor(original.secretKey), original.workerSecret)
})

test('a re-derived Worker secret really signs for the original public key', () => {
  // Equal strings are not quite proof; the point is that the derived bytes
  // still work as a signing key, through the same WebCrypto path the Worker
  // uses.
  const { publicKey, secretKey } = generateKeyPair()
  const pkcs8 = Uint8Array.from(Buffer.from(workerSecretFor(secretKey), 'base64'))

  return crypto.subtle
    .importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
    .then((key) => crypto.subtle.sign('Ed25519', key, new TextEncoder().encode('lgt1.x')))
    .then((signature) => {
      assert.equal(
        crypto.verify(
          null,
          Buffer.from('lgt1.x'),
          importPublicKey(publicKey),
          Buffer.from(signature)
        ),
        true
      )
    })
})

test('deriving from a public key, or from a truncated one, is refused', () => {
  // Note the asymmetry, which is deliberate. A secret key handed to
  // importPublicKey is an incident and says so; a public key handed to
  // importSecretKey is a harmless mix-up and only needs to say which prefix
  // it wanted.
  const { publicKey } = generateKeyPair()
  assert.throws(() => workerSecretFor(publicKey), /must be a string beginning "lgsk1_"/)
  assert.throws(() => workerSecretFor('lgsk1_tooshort'), /an Ed25519 key is 32/)
})
