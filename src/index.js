'use strict'

const path = require('path')
const { createGuard, SDK_VERSION } = require('./guard')
const { loadEncryptedModule, inspectCore } = require('./loader')
const { computeFingerprint, resolveStateDir } = require('./fingerprint')
const { packCore, unpackCore, readCoreMeta } = require('./pack')
const { sign, verify, decodeUnverified } = require('./token')
const {
  generateKeyPair, importPublicKey, importSecretKey, publicKeyFor, workerSecretFor
} = require('./keys')
const { createTransport } = require('./transport')
const { createVault } = require('./vault')
const errors = require('./errors')

/**
 * The whole thing in one call, for the common case.
 *
 *   const { core, license } = await protect({
 *     product: 'acme-core',
 *     version: require('./package.json').version,
 *     publicKey: 'lgpk1_…',                        // safe to commit
 *     endpoint: 'https://licence.acme.example',
 *     licenseKey: process.env.ACME_LICENSE_KEY,
 *     coreFile: require.resolve('./core.lgc')
 *   })
 *
 *   module.exports = core
 *
 * `core` is your real module. `license` is the snapshot — status, customer,
 * features, watermark — which you will want for feature gating and for
 * stamping the watermark into anything the product generates.
 *
 * Note the shape: activation happens once, at load, and the result is the
 * module. There is no per-call licence check, no `if (!licensed) return` in
 * your hot path. That is intentional. A check scattered through the code is a
 * check an attacker can delete in twenty places or in one; if the code is
 * encrypted, the only leverage is the key, and the key is only ever obtained
 * once.
 */
async function protect (options = {}) {
  const { coreFile, resolveFrom, context, ...guardOptions } = options
  const guard = createGuard(guardOptions)
  const license = await guard.activate()

  if (!coreFile) return { core: null, license, guard }

  if (!license.coreKey) {
    throw new errors.LicenseError(
      'Activation succeeded but returned no core key, so the encrypted module cannot be opened. ' +
      'The licence server issues the key alongside the token — check that the product id in the ' +
      'server matches "' + guardOptions.product + '".',
      'missing_core_key'
    )
  }

  const { exports, meta } = loadEncryptedModule({
    file: coreFile,
    key: license.coreKey,
    resolveFrom: resolveFrom || path.dirname(coreFile),
    expect: { product: guardOptions.product },
    context
  })

  return { core: exports, license, guard, build: meta }
}

module.exports = {
  protect,
  createGuard,
  loadEncryptedModule,
  inspectCore,
  computeFingerprint,
  resolveStateDir,
  packCore,
  unpackCore,
  readCoreMeta,
  sign,
  verify,
  decodeUnverified,
  generateKeyPair,
  publicKeyFor,
  workerSecretFor,
  importPublicKey,
  importSecretKey,
  createTransport,
  createVault,
  SDK_VERSION,
  ...errors
}
