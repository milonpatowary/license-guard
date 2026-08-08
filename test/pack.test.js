'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const crypto = require('crypto')

const { packCore, unpackCore, readCoreMeta } = require('../src/pack')
const { CoreIntegrityError } = require('../src/errors')

const SOURCE = 'module.exports = { answer: () => 42 }\n'

test('a packed core round-trips', () => {
  const { file, key, meta } = packCore({
    source: SOURCE,
    meta: { product: 'acme-core', version: '1.2.3', watermark: 'deadbeef' }
  })
  const opened = unpackCore(file, key)
  assert.equal(opened.source, SOURCE)
  assert.equal(opened.meta.product, 'acme-core')
  assert.equal(opened.meta.buildId, meta.buildId)
})

test('the label is readable without the key, and the payload is not', () => {
  const { file } = packCore({ source: SOURCE, meta: { product: 'acme-core', version: '1.2.3' } })

  assert.equal(readCoreMeta(file).product, 'acme-core')
  assert.ok(
    !file.toString('latin1').includes('answer'),
    'the plaintext must not be recoverable from the packed file'
  )
})

test('the wrong key fails authentication rather than producing garbage', () => {
  const { file } = packCore({ source: SOURCE })
  assert.throws(
    () => unpackCore(file, crypto.randomBytes(32)),
    (err) => err instanceof CoreIntegrityError && err.fatal === true
  )
})

test('flipping one byte of the ciphertext is detected', () => {
  const { file, key } = packCore({ source: SOURCE })
  const tampered = Buffer.from(file)
  tampered[tampered.length - 1] ^= 0x01
  assert.throws(() => unpackCore(tampered, key), CoreIntegrityError)
})

test('relabelling the header is detected, because the header is the AAD', () => {
  // The attack this stops: take a build the customer is licensed for, edit the
  // clear-text metadata to claim it is a different product or version, and see
  // whether the loader's expectation checks can be walked past. They cannot,
  // because the tag covers the header.
  const { file, key } = packCore({ source: SOURCE, meta: { product: 'acme-core', version: '1.0.0' } })
  const text = file.toString('latin1')
  // Same length, so the metaLength field still agrees and the file stays
  // well-formed. A length-changing edit would be caught by the parser instead,
  // which proves nothing about the tag.
  const swapped = Buffer.from(text.replace('acme-core', 'acme-fake'), 'latin1')

  assert.equal(readCoreMeta(swapped).product, 'acme-fake', 'the edit did land')
  assert.throws(() => unpackCore(swapped, key), /failed authentication/)
})

test('a file that is not a core file says so', () => {
  assert.throws(() => readCoreMeta(Buffer.from('#!/usr/bin/env node\n')), /magic bytes are missing/)
  assert.throws(() => unpackCore(Buffer.alloc(3), 'x'), /magic bytes are missing/)
})

test('a truncated core file is reported as truncated', () => {
  const { file } = packCore({ source: SOURCE, meta: { product: 'p' } })
  assert.throws(() => readCoreMeta(file.subarray(0, 12)), /truncated/)
})

test('the build id is a function of the source, so two builds are distinguishable', () => {
  const a = packCore({ source: SOURCE })
  const b = packCore({ source: SOURCE })
  const c = packCore({ source: SOURCE + '// tweak\n' })

  assert.equal(a.meta.buildId, b.meta.buildId, 'same source, same build id')
  assert.notEqual(a.meta.buildId, c.meta.buildId)
  assert.notEqual(
    a.file.toString('base64'), b.file.toString('base64'),
    'but the ciphertext differs — a fresh IV every time'
  )
})

test('an explicit key is honoured, which is what lets one key serve every customer', () => {
  const key = crypto.randomBytes(32)
  const first = packCore({ source: SOURCE, key, meta: { version: '1' } })
  const second = packCore({ source: SOURCE + '\n', key, meta: { version: '2' } })

  assert.equal(first.key, key.toString('base64'))
  assert.equal(unpackCore(second.file, first.key).meta.version, '2')
})

test('a key of the wrong length is rejected before anything is encrypted', () => {
  assert.throws(() => packCore({ source: SOURCE, key: Buffer.alloc(16) }), /is 32 bytes; this one is 16/)
})
