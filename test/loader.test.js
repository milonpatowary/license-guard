'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const { packCore } = require('../src/pack')
const { loadEncryptedModule, inspectCore } = require('../src/loader')
const { CoreIntegrityError, ConfigurationError } = require('../src/errors')

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lg-load-'))

function packTo (source, meta = {}) {
  const dir = tempDir()
  const { file, key } = packCore({ source, meta: { product: 'acme-core', version: '1.0.0', ...meta } })
  const target = path.join(dir, 'core.lgc')
  fs.writeFileSync(target, file)
  return { file: target, key, dir }
}

test('an encrypted module loads and exports', () => {
  const { file, key } = packTo('module.exports = { add: (a, b) => a + b }')
  const { exports, meta } = loadEncryptedModule({ file, key })
  assert.equal(exports.add(2, 3), 5)
  assert.equal(meta.product, 'acme-core')
})

test('the module can require its own dependencies', () => {
  const { file, key, dir } = packTo(
    "const path = require('path')\nmodule.exports = () => path.basename('/a/b.txt')"
  )
  const { exports } = loadEncryptedModule({ file, key, resolveFrom: dir })
  assert.equal(exports(), 'b.txt')
})

test('__filename and __dirname are the ones the core would expect', () => {
  const { file, key, dir } = packTo('module.exports = { where: () => [__filename, __dirname] }')
  const [filename, dirname] = loadEncryptedModule({ file, key }).exports.where()
  assert.equal(filename, 'core.lgc')
  assert.equal(dirname, dir)
})

test('a stack trace from inside the core names the file, not <anonymous>', () => {
  // The reason for vm.compileFunction over new Function. Debugging a
  // customer's production incident through anonymous eval frames is what makes
  // people give up on encrypted cores.
  const { file, key } = packTo("module.exports = { boom () { throw new Error('inside') } }")
  const { exports } = loadEncryptedModule({ file, key })
  try {
    exports.boom()
    assert.fail('should have thrown')
  } catch (err) {
    assert.match(err.stack, /core\.lgc:\d+/)
  }
})

test('extra context is injected as real bindings', () => {
  const { file, key } = packTo('module.exports = () => license.customer')
  const { exports } = loadEncryptedModule({
    file, key, context: { license: { customer: 'Acme Ltd' } }
  })
  assert.equal(exports(), 'Acme Ltd')
})

test('the wrong key is a fatal integrity error', () => {
  const { file } = packTo('module.exports = 1')
  assert.throws(
    () => loadEncryptedModule({ file, key: crypto.randomBytes(32) }),
    (err) => err instanceof CoreIntegrityError && err.fatal === true
  )
})

test('a tampered file never reaches the compiler', () => {
  const { file, key } = packTo('module.exports = { licensed: () => true }')
  const bytes = fs.readFileSync(file)
  bytes[bytes.length - 5] ^= 0x40
  fs.writeFileSync(file, bytes)
  assert.throws(() => loadEncryptedModule({ file, key }), /failed authentication/)
})

test('a core for another product is refused even with a valid key', () => {
  const { file, key } = packTo('module.exports = 1', { product: 'other-product' })
  assert.throws(
    () => loadEncryptedModule({ file, key, expect: { product: 'acme-core' } }),
    /is for "other-product", but the guard is licensed for "acme-core"/
  )
})

test('a version mismatch points at a partial upgrade', () => {
  const { file, key } = packTo('module.exports = 1', { version: '1.0.0' })
  assert.throws(
    () => loadEncryptedModule({ file, key, expect: { version: '2.0.0' } }),
    /usually means a partial upgrade/
  )
})

test('a core that decrypts to broken JavaScript says it is a packaging problem', () => {
  const { file, key } = packTo('module.exports = { unclosed: ')
  assert.throws(
    () => loadEncryptedModule({ file, key }),
    /packaging problem rather than a licensing one/
  )
})

test('a missing file reports the path, not a stack from fs', () => {
  assert.throws(
    () => loadEncryptedModule({ file: '/nope/core.lgc', key: crypto.randomBytes(32) }),
    /could not be read from \/nope\/core\.lgc: ENOENT/
  )
})

test('calling without a key explains where the key comes from', () => {
  const { file } = packTo('module.exports = 1')
  assert.throws(() => loadEncryptedModule({ file }), ConfigurationError)
  assert.throws(() => loadEncryptedModule({ file }), /returned by guard\.activate\(\)/)
})

test('a buffer works as well as a path, for cores fetched over the network', () => {
  const { file, key } = packTo('module.exports = 7')
  const { exports } = loadEncryptedModule({ buffer: fs.readFileSync(file), key })
  assert.equal(exports, 7)
})

test('inspectCore reads the label with no key at all', () => {
  const { file } = packTo('module.exports = 1', { version: '3.1.4' })
  assert.equal(inspectCore(file).version, '3.1.4')
})
