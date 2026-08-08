'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { createVault } = require('../src/vault')

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lg-vault-'))

test('what goes in comes back out', () => {
  const vault = createVault({ stateDir: tempDir(), fingerprintId: 'fp-1' })
  assert.equal(vault.write({ token: 'lgt1.x.y', coreKey: 'AAAA' }), true)
  assert.deepEqual(vault.read(), { token: 'lgt1.x.y', coreKey: 'AAAA' })
})

test('the core key is not sitting on disk in the clear', () => {
  const stateDir = tempDir()
  const vault = createVault({ stateDir, fingerprintId: 'fp-1' })
  vault.write({ token: 'lgt1.header.signature', coreKey: 'S3CR3TC0REKEY' })

  const raw = fs.readFileSync(vault.file).toString('latin1')
  assert.equal(raw.includes('S3CR3TC0REKEY'), false)
  assert.equal(raw.includes('lgt1.header'), false)
  assert.equal(raw.slice(0, 4), 'LGV1', 'but it is still identifiable, for support')
})

test('the cache is inert on a different machine', () => {
  // The realistic theft: copy the whole state directory — vault key included —
  // off a licensed host and onto an unlicensed one. The fingerprint is half the
  // derivation, so the file does not open there.
  const stateDir = tempDir()
  createVault({ stateDir, fingerprintId: 'fp-original' }).write({ token: 't', coreKey: 'k' })

  const thief = createVault({ stateDir, fingerprintId: 'fp-other-machine' })
  assert.equal(thief.read(), null)
})

test('the cache is inert without the vault key', () => {
  // The other realistic theft: copy just cache.bin, which is the file whose
  // name makes it look interesting.
  const original = tempDir()
  createVault({ stateDir: original, fingerprintId: 'fp-1' }).write({ token: 't', coreKey: 'k' })

  const elsewhere = tempDir()
  fs.copyFileSync(path.join(original, 'cache.bin'), path.join(elsewhere, 'cache.bin'))
  assert.equal(createVault({ stateDir: elsewhere, fingerprintId: 'fp-1' }).read(), null)
})

test('a corrupt or truncated cache is a miss, never a crash', () => {
  const stateDir = tempDir()
  const vault = createVault({ stateDir, fingerprintId: 'fp-1' })
  vault.write({ token: 't', coreKey: 'k' })

  const good = fs.readFileSync(vault.file)
  for (const broken of [Buffer.alloc(0), Buffer.from('junk'), good.subarray(0, 20)]) {
    fs.writeFileSync(vault.file, broken)
    assert.equal(vault.read(), null)
  }

  // A single flipped byte in the ciphertext is caught by the tag, not ignored.
  const flipped = Buffer.from(good)
  flipped[flipped.length - 1] ^= 0xff
  fs.writeFileSync(vault.file, flipped)
  assert.equal(vault.read(), null)
})

test('a missing cache is a miss, not an error', () => {
  const vault = createVault({ stateDir: tempDir(), fingerprintId: 'fp-1' })
  assert.equal(vault.read(), null)
  assert.equal(vault.clear(), false)
})

test('an unwritable state directory does not stop the product starting', () => {
  const file = path.join(tempDir(), 'not-a-directory')
  fs.writeFileSync(file, '')
  const vault = createVault({ stateDir: path.join(file, 'state'), fingerprintId: 'fp-1' })

  assert.equal(vault.write({ token: 't' }), false, 'reports failure')
  assert.equal(vault.read(), null, 'and reads as a miss')
})

test('writing is atomic, so a crash cannot leave a half-file behind', () => {
  const stateDir = tempDir()
  const vault = createVault({ stateDir, fingerprintId: 'fp-1' })
  vault.write({ token: 'first' })
  vault.write({ token: 'second' })

  assert.deepEqual(vault.read(), { token: 'second' })
  assert.deepEqual(
    fs.readdirSync(stateDir).filter((f) => f.includes('tmp')), [],
    'no temporary files left over'
  )
})

test('clear removes the cache', () => {
  const vault = createVault({ stateDir: tempDir(), fingerprintId: 'fp-1' })
  vault.write({ token: 't' })
  assert.equal(vault.clear(), true)
  assert.equal(vault.read(), null)
})

test('the vault key file is not world-readable', { skip: process.platform === 'win32' }, () => {
  const stateDir = tempDir()
  createVault({ stateDir, fingerprintId: 'fp-1' }).write({ token: 't' })
  assert.equal(fs.statSync(path.join(stateDir, 'vault-key')).mode & 0o077, 0)
})
