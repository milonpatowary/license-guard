'use strict'

const fs = require('fs')
const path = require('path')
const vm = require('vm')
const Module = require('module')
const { unpackCore, readCoreMeta } = require('./pack')
const { CoreIntegrityError, ConfigurationError } = require('./errors')

/**
 * Decrypt a `.lgc` file and run it as a CommonJS module, without it ever
 * touching disk in the clear.
 *
 * `vm.compileFunction` rather than `new Function`, for one reason that matters
 * in production: it takes a `filename`, so a stack trace from inside the core
 * says `at doTheThing (acme-core.lgc:214:9)` instead of `at eval (<anonymous>)`.
 * Debugging a customer's incident through anonymous eval frames is its own
 * punishment, and it is the reason most people who try this abandon it.
 *
 * The module is given a real `require` resolved against `resolveFrom`, so the
 * encrypted core can depend on the package's own dependencies exactly as an
 * ordinary file in that directory would.
 *
 * What this does not do — and no amount of care would — is keep the source out
 * of a determined reader's hands at runtime. Once decrypted it is a string in
 * this process's heap, and `--inspect` plus a heap snapshot will find it. The
 * bar this clears is "cannot read the tarball", not "cannot ever read it".
 */
function loadEncryptedModule ({
  file,
  buffer,
  key,
  resolveFrom = file ? path.dirname(file) : process.cwd(),
  expect = {},
  context = {}
} = {}) {
  if (!file && !buffer) {
    throw new ConfigurationError('loadEncryptedModule() needs a `file` path or a `buffer`.')
  }
  if (!key) {
    throw new ConfigurationError(
      'No decryption key. The key comes from a successful activation — read it from the object ' +
      'returned by guard.activate().'
    )
  }

  let bytes
  if (buffer) {
    bytes = Buffer.from(buffer)
  } else {
    try {
      bytes = fs.readFileSync(file)
    } catch (err) {
      throw new CoreIntegrityError(
        `The encrypted core could not be read from ${file}: ${err.code || err.message}`
      )
    }
  }

  const { source, meta } = unpackCore(bytes, key)

  // Checked after decryption, because before it the metadata is only a claim.
  // The authentication tag covers the header, so by this point the label and
  // the payload are known to belong together.
  if (expect.product && meta.product && meta.product !== expect.product) {
    throw new CoreIntegrityError(
      `This core file is for "${meta.product}", but the guard is licensed for "${expect.product}".`
    )
  }
  if (expect.version && meta.version && meta.version !== expect.version) {
    throw new CoreIntegrityError(
      `This core file is build ${meta.version}, but the package expects ${expect.version}. ` +
      'A mismatched pair usually means a partial upgrade.'
    )
  }

  const filename = file ? `${path.basename(file)}` : `${meta.product || 'core'}.lgc`
  const dirname = resolveFrom
  const moduleObject = { exports: {} }

  // A require that behaves like one in `resolveFrom`, so the core's own
  // dependencies resolve the way its author wrote them.
  const requireFrom = Module.createRequire(path.join(resolveFrom, 'noop.js'))

  const names = ['exports', 'require', 'module', '__filename', '__dirname', ...Object.keys(context)]
  const values = [moduleObject.exports, requireFrom, moduleObject, filename, dirname,
    ...Object.values(context)]

  let compiled
  try {
    compiled = vm.compileFunction(source, names, { filename })
  } catch (err) {
    throw new CoreIntegrityError(
      `The decrypted core is not valid JavaScript (${err.message}). The key was accepted, so this ` +
      'is a packaging problem rather than a licensing one — repack from the original source.'
    )
  }

  compiled(...values)
  return { exports: moduleObject.exports, meta }
}

/** The label on a core file, without needing a key. Handy in support scripts. */
function inspectCore (file) {
  return readCoreMeta(fs.readFileSync(file))
}

module.exports = { loadEncryptedModule, inspectCore }
