'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { protect, packCore, generateKeyPair, computeFingerprint } = require('../src/index')
const { createTransport } = require('../src/transport')

let createD1, applySchema, makeRequest
let sqliteAvailable = true
try {
  ({ createD1, applySchema, makeRequest } = require('./helpers/d1-sqlite'))
  createD1().close()
} catch {
  sqliteAvailable = false
}

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lg-e2e-'))
const silent = { warn () {}, error () {}, log () {} }

/**
 * The whole chain, with nothing faked but the wire and the disk.
 *
 * Real keygen, real AES packing, the real Worker handler over a real SQLite
 * database, the real client, the real module loader. If this passes, a
 * customer can install the package and it works; if it fails, one of the eight
 * pieces disagrees with another about a format, which is the failure mode that
 * unit tests are worst at catching.
 */
const CORE_SOURCE = `
const { createHash } = require('crypto')

module.exports = {
  // The thing worth protecting: pretend this took two years to get right.
  score (input) {
    return createHash('sha256').update(String(input)).digest('hex').slice(0, 8)
  },
  // Watermarking in practice — every artefact the product emits carries the
  // per-customer mark, so a leaked export identifies its source.
  stamp (document) {
    return { ...document, issuedTo: license.customer, mark: license.watermark }
  }
}
`

async function scenario ({ seats = 2 } = {}) {
  const { handle } = await import('../server/worker.js')
  const keys = generateKeyPair()
  const d1 = applySchema(createD1())

  const env = {
    DB: d1,
    SIGNING_KEY: keys.workerSecret,
    ADMIN_TOKEN: 'admin',
    IP_SALT: 'pepper',
    ISSUER: 'licence.test'
  }

  // A fetch that speaks straight to the Worker handler.
  const fetchImpl = async (url, init) => {
    const response = await handle(makeRequest(init.method, url, {
      body: init.body,
      headers: { 'cf-connecting-ip': '198.51.100.9', ...init.headers },
      cf: { asn: 64500, asOrganization: 'Test Net', country: 'GB', colo: 'LHR' }
    }), env)
    const text = await response.text()
    return { status: response.status, headers: { get: () => null }, async text () { return text } }
  }

  const admin = async (method, url, body) => {
    const response = await handle(makeRequest(method, url, {
      body, headers: { authorization: 'Bearer admin' }, cf: {}
    }), env)
    return JSON.parse(await response.text())
  }

  // Build: encrypt the core, register the product with its key.
  const buildDir = tempDir()
  const { file, key: coreKey } = packCore({
    source: CORE_SOURCE,
    meta: { product: 'acme-core', version: '2.0.0' }
  })
  const coreFile = path.join(buildDir, 'core.lgc')
  fs.writeFileSync(coreFile, file)

  await admin('POST', '/v1/admin/products', { id: 'acme-core', name: 'Acme Core', coreKey })
  const license = await admin('POST', '/v1/admin/licenses', {
    product: 'acme-core', customer: 'Acme Ltd', seats, features: ['reports']
  })

  const load = (stateDir, overrides = {}) => protect({
    product: 'acme-core',
    version: '2.0.0',
    publicKey: keys.publicKey,
    endpoint: 'https://licence.test',
    licenseKey: license.licenseKey,
    stateDir,
    coreFile,
    logger: silent,
    transport: createTransport({
      endpoint: 'https://licence.test',
      fetchImpl,
      sleep: async () => {}
    }),
    setIntervalImpl: () => ({ unref () {} }),
    ...overrides
  })

  return { keys, license, coreFile, coreKey, load, admin, fetchImpl, env, d1 }
}

test('a licensed install activates, decrypts and runs', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load } = await scenario()
  const stateDir = tempDir()

  const { core, license, build } = await load(stateDir, {
    context: { license: { customer: 'Acme Ltd', watermark: 'set below' } }
  })

  assert.equal(license.status, 'active')
  assert.equal(license.customer, 'Acme Ltd')
  assert.equal(build.version, '2.0.0')
  assert.equal(core.score('hello').length, 8)
  assert.equal(core.score('hello'), core.score('hello'), 'and it actually works')
})

test('the per-customer watermark reaches the code that stamps output', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load } = await scenario()
  const stateDir = tempDir()

  // Two-step, because the watermark only exists after activation: activate,
  // then hand the licence into the core as context.
  const first = await load(stateDir)
  const { core } = await load(stateDir, { context: { license: first.license } })

  const stamped = core.stamp({ total: 100 })
  assert.equal(stamped.issuedTo, 'Acme Ltd')
  assert.match(stamped.mark, /^[0-9a-f]{8}$/)
  assert.equal(stamped.mark, first.license.watermark)
})

test('an unlicensed copy of the package cannot open the core', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  // The scenario the whole design is for: the private repository leaks. The
  // attacker has the package, the .lgc file, and the embedded public key. What
  // they do not have is a licence key, so the server never hands over the
  // decryption key.
  const { load } = await scenario()

  await assert.rejects(
    load(tempDir(), { licenseKey: 'STOLEN-BUILD-NO-KEY' }),
    /not recognised/
  )
})

test('a licence key stolen along with the code still runs out of seats', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load } = await scenario({ seats: 1 })
  await load(tempDir())

  await assert.rejects(load(tempDir()), /already active/)
})

test('the deployment shows up in the report, with enough to identify it', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load, admin, license } = await scenario()
  await load(tempDir())

  const { instances } = await admin('GET', `/v1/admin/deployments?license=${license.id}`)
  assert.equal(instances.length, 1)
  assert.equal(instances[0].hostname, os.hostname())
  assert.equal(instances[0].app_version, '2.0.0')
  assert.equal(instances[0].country, 'GB')
  assert.equal(instances[0].platform, process.platform)
})

test('the same host restarting is one deployment, not many', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load, admin, license } = await scenario({ seats: 1 })
  const stateDir = tempDir()

  for (let i = 0; i < 5; i++) await load(stateDir)

  const { instances } = await admin('GET', `/v1/admin/deployments?license=${license.id}`)
  assert.equal(instances.length, 1)
})

test('the fingerprint the client computes is the one the server records', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load, admin, license } = await scenario()
  const stateDir = tempDir()
  await load(stateDir)

  const expected = computeFingerprint({ product: 'acme-core', stateDir })
  const { instances } = await admin('GET', `/v1/admin/deployments?license=${license.id}`)
  assert.equal(instances[0].fingerprint, expected.id)
})

test('revoking mid-life stops the next start', {
  skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+'
}, async () => {
  const { load, admin, license } = await scenario()
  const stateDir = tempDir()
  const running = await load(stateDir)
  assert.equal(running.license.status, 'active')

  await admin('POST', '/v1/admin/revoke', { id: license.id, reason: 'non-payment' })

  // The cached token is still valid, so the running process is untouched and
  // a restart still comes up — see the guard tests for why. The heartbeat is
  // what carries the news, and after it the cache is gone.
  const restarted = await load(stateDir)
  await assert.rejects(restarted.guard.heartbeat(), /revoked/)
  await assert.rejects(load(stateDir), /revoked/)
})
