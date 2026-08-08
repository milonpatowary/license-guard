'use strict'

/**
 * The whole system, end to end, on one machine, in about a second.
 *
 *   npm run demo
 *
 * It generates a keypair, encrypts a core module, runs the real Cloudflare
 * Worker against a real SQLite database in-process, activates two deployments,
 * refuses a third, and prints the sharing report. Nothing is stubbed except the
 * network hop between the client and the Worker.
 *
 * Read it as the tutorial. Every step here has a real counterpart:
 *
 *   step 1  →  `license-guard keygen`, once, ever
 *   step 2  →  a build step in your private repo
 *   step 3  →  `wrangler deploy` and `POST /v1/admin/products`
 *   step 4  →  `POST /v1/admin/licenses`, one per customer
 *   step 5  →  what happens inside your published package on require()
 */

const fs = require('fs')
const os = require('os')
const path = require('path')

const { protect, packCore, generateKeyPair } = require('../../src/index')
const { createTransport } = require('../../src/transport')

async function main () {
  let DatabaseSync
  try {
    ({ DatabaseSync } = require('node:sqlite'))
  } catch {
    console.error(
      'This demo runs the licence server against node:sqlite, which arrived in Node 22.\n' +
      `You are on ${process.version}. The library itself supports Node 18+.`
    )
    process.exit(1)
  }

  const { handle } = await import('../../server/worker.js')
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-guard-demo-'))

  /* 1 ── keys ------------------------------------------------------------ */

  const keys = generateKeyPair()
  say('1', 'Generated a signing keypair')
  console.log(`     public  ${keys.publicKey}   ← embedded in the shipped package`)
  console.log('     secret  lgsk1_…                                        ← never leaves your Worker\n')

  /* 2 ── build ----------------------------------------------------------- */

  const source = fs.readFileSync(path.join(__dirname, 'core', 'scoring.js'), 'utf8')
  const { file, key: coreKey, meta } = packCore({
    source,
    meta: { product: 'credit-scorer', version: '2.0.0' }
  })
  const coreFile = path.join(workDir, 'core.lgc')
  fs.writeFileSync(coreFile, file)

  say('2', 'Packed the core module')
  console.log(`     ${source.length} bytes of source → ${file.length} bytes encrypted, build ${meta.buildId}`)
  console.log('     the word "missedPayments" appears in the packed file: ' +
    `${file.toString('latin1').includes('missedPayments')}\n`)

  /* 3 ── licence server -------------------------------------------------- */

  const db = new DatabaseSync(':memory:')
  db.exec(fs.readFileSync(path.join(__dirname, '..', '..', 'server', 'schema.sql'), 'utf8'))
  const env = {
    DB: d1(db),
    SIGNING_KEY: keys.workerSecret,
    ADMIN_TOKEN: 'demo-admin',
    IP_SALT: 'demo',
    ISSUER: 'licence.demo'
  }
  const call = caller(handle, env)

  await call('POST', '/v1/admin/products', {
    admin: true,
    body: { id: 'credit-scorer', name: 'Credit Scorer', coreKey }
  })
  say('3', 'Deployed the licence server and registered the product\n')

  /* 4 ── a customer ------------------------------------------------------ */

  const license = (await call('POST', '/v1/admin/licenses', {
    admin: true,
    body: {
      product: 'credit-scorer',
      customer: 'Northwind Bank',
      email: 'ops@northwind.example',
      seats: 2,
      plan: 'enterprise',
      features: ['explanations']
    }
  })).data

  say('4', `Issued a licence to Northwind Bank: ${license.licenseKey}`)
  console.log('     shown once, stored only as a hash\n')

  /* 5 ── the customer runs it ------------------------------------------- */

  const install = (name, cf) => protect({
    product: 'credit-scorer',
    version: '2.0.0',
    publicKey: keys.publicKey,
    endpoint: 'https://licence.demo',
    licenseKey: license.licenseKey,
    stateDir: path.join(workDir, name),
    coreFile,
    logger: { warn () {}, error () {} },
    setIntervalImpl: () => ({ unref () {} }),
    transport: createTransport({
      endpoint: 'https://licence.demo',
      fetchImpl: fetchTo(handle, env, cf),
      sleep: async () => {}
    })
  })

  // Two-pass, because the core wants the licence injected as context and the
  // licence only exists once activation has happened.
  const first = await install('prod-1', { asn: 64500, asOrganization: 'Northwind DC', country: 'GB' })
  const { core } = await protect({
    product: 'credit-scorer',
    version: '2.0.0',
    publicKey: keys.publicKey,
    endpoint: 'https://licence.demo',
    licenseKey: license.licenseKey,
    stateDir: path.join(workDir, 'prod-1'),
    coreFile,
    context: { license: first.license, guard: first.guard },
    logger: { warn () {}, error () {} },
    setIntervalImpl: () => ({ unref () {} }),
    transport: createTransport({
      endpoint: 'https://licence.demo',
      fetchImpl: fetchTo(handle, env, { asn: 64500, country: 'GB' }),
      sleep: async () => {}
    })
  })

  say('5', `Deployment 1 activated — status ${first.license.status}, watermark ${first.license.watermark}`)
  const scored = core.report([
    { id: 'A-1', income: 90000, debt: 20000, missedPayments: 0 },
    { id: 'A-2', income: 40000, debt: 35000, missedPayments: 3 }
  ])
  console.log(`     the decrypted core ran: ${JSON.stringify(scored.rows)}`)
  console.log(`     every report it emits is stamped: issuedTo=${scored.issuedTo} mark=${scored.mark}\n`)

  /* 6 ── a second deployment, then a third ------------------------------- */

  const second = await install('prod-2', { asn: 64500, asOrganization: 'Northwind DC', country: 'GB' })
  say('6', `Deployment 2 activated — ${second.license.status} (2 of 2 seats)`)

  try {
    await install('prod-3', { asn: 64999, asOrganization: 'Somewhere Else', country: 'DE' })
    console.log('     deployment 3: unexpectedly allowed')
  } catch (err) {
    console.log(`     deployment 3 refused: ${err.code} — ${err.message}\n`)
  }

  /* 7 ── restarts are free ----------------------------------------------- */

  for (let i = 0; i < 5; i++) await install('prod-1', { asn: 64500, country: 'GB' })
  const deployments = (await call('GET', '/v1/admin/deployments?license=' + license.id, { admin: true })).data
  say('7', `Five restarts later, the server still counts ${deployments.instances.length} deployments`)
  for (const instance of deployments.instances) {
    console.log(`     ${instance.fingerprint}  ${instance.hostname}  ${instance.platform}` +
      `  ${instance.country}  activated ${instance.activations}×`)
  }
  console.log('     the restarts came up from cache and only checked in, so no seat was re-claimed\n')

  /* 8 ── what a leak looks like ------------------------------------------ */

  try {
    await protect({
      product: 'credit-scorer',
      version: '2.0.0',
      publicKey: keys.publicKey,
      endpoint: 'https://licence.demo',
      licenseKey: 'NOT-A-REAL-KEY',
      stateDir: path.join(workDir, 'pirate'),
      coreFile,
      logger: { warn () {}, error () {} },
      transport: createTransport({
        endpoint: 'https://licence.demo',
        fetchImpl: fetchTo(handle, env, { asn: 65001, country: 'RU' }),
        sleep: async () => {}
      })
    })
  } catch (err) {
    say('8', 'Someone with the package but no licence key')
    console.log(`     ${err.code}: ${err.message}`)
    console.log('     they hold core.lgc and the public key, and neither opens anything\n')
  }

  /* 9 ── the report ------------------------------------------------------ */

  const shared = (await call('POST', '/v1/admin/licenses', {
    admin: true,
    body: { product: 'credit-scorer', customer: 'Someone Who Shares', seats: 3 }
  })).data
  for (const [i, cf] of [
    { asn: 64500, asOrganization: 'Their Office', country: 'GB' },
    { asn: 64700, asOrganization: 'A Different Company', country: 'DE' },
    { asn: 64800, asOrganization: 'A Third Company', country: 'BR' }
  ].entries()) {
    await activateAs(handle, env, cf, shared, i)
  }

  const report = (await call('GET', '/v1/admin/report', { admin: true })).data
  say('9', 'The sharing report — the signal that actually catches leaks')
  for (const row of report.licenses) {
    console.log(
      `     ${row.customer.padEnd(22)} ${row.instances} instance(s) ` +
      `across ${row.networks} network(s), ${row.countries} countr(ies)` +
      (row.sharingSuspected ? '   ← flagged' : '')
    )
  }

  console.log(`\n     One customer, many networks, several countries is the pattern worth a phone
     call. A quiet single-machine pirate is invisible here and always will be —
     see SECURITY.md for what this design does and does not buy.\n`)

  db.close()
}

/* ------------------------------------------------------------------ *
 * Demo plumbing — none of this is part of the library
 * ------------------------------------------------------------------ */

function d1 (db) {
  const statement = (sql, params = []) => ({
    bind: (...values) => statement(sql, values.map((v) =>
      v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v)),
    async first (column) {
      const row = db.prepare(sql).get(...params)
      return row === undefined ? null : (column ? row[column] : row)
    },
    async all () { return { results: db.prepare(sql).all(...params), success: true, meta: {} } },
    async run () {
      const r = db.prepare(sql).run(...params)
      return { success: true, meta: { changes: Number(r.changes) } }
    }
  })
  return { prepare: (sql) => statement(sql) }
}

function request (method, url, { body = null, headers = {}, cf = {} } = {}) {
  const map = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  return {
    method,
    url: url.startsWith('http') ? url : `https://licence.demo${url}`,
    headers: { get: (n) => map.get(String(n).toLowerCase()) ?? null },
    cf,
    async json () { return typeof body === 'string' ? JSON.parse(body) : body }
  }
}

function caller (handle, env) {
  return async (method, url, { body, admin = false, cf = {} } = {}) => {
    const headers = { 'cf-connecting-ip': '198.51.100.1' }
    if (admin) headers.authorization = 'Bearer demo-admin'
    const response = await handle(request(method, url, { body, headers, cf }), env)
    return { status: response.status, data: JSON.parse(await response.text()) }
  }
}

function fetchTo (handle, env, cf) {
  return async (url, init) => {
    const response = await handle(request(init.method, url, {
      body: init.body,
      headers: { 'cf-connecting-ip': '198.51.100.1', ...init.headers },
      cf
    }), env)
    const text = await response.text()
    return { status: response.status, headers: { get: () => null }, async text () { return text } }
  }
}

/** One licence key checking in from somebody else's network. */
async function activateAs (handle, env, cf, shared, index) {
  const response = await handle(request('POST', '/v1/activate', {
    body: {
      product: 'credit-scorer',
      version: '2.0.0',
      licenseKey: shared.licenseKey,
      fingerprint: `shared-fp-${index}`,
      telemetry: { hostname: `their-box-${index}`, platform: 'linux', arch: 'x64' }
    },
    headers: { 'cf-connecting-ip': `198.51.100.${index + 10}` },
    cf
  }), env)
  await response.text()
}

function say (step, message) {
  console.log(`\n[${step}] ${message}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
