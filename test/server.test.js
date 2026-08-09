'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')

const { generateKeyPair } = require('../src/keys')
const { verify, decodeUnverified } = require('../src/token')
const { LicenseExpiredError } = require('../src/errors')

let createD1, applySchema, makeRequest
let sqliteAvailable = true
try {
  ({ createD1, applySchema, makeRequest } = require('./helpers/d1-sqlite'))
  createD1().close()
} catch {
  // node:sqlite arrived in Node 22. On 18 and 20 the client tests still run;
  // this file is the part that needs a database.
  sqliteAvailable = false
}

const keys = generateKeyPair()
const ADMIN = 'admin-token-for-tests'
const CORE_KEY = Buffer.alloc(32, 3).toString('base64')

const suite = test.describe ?? ((name, fn) => fn())

async function loadWorker () {
  return import('../server/worker.js')
}

function makeEnv (d1, overrides = {}) {
  return {
    DB: d1,
    SIGNING_KEY: keys.workerSecret,
    ADMIN_TOKEN: ADMIN,
    IP_SALT: 'pepper',
    ISSUER: 'licence.test',
    TOKEN_TTL_DAYS: '7',
    GRACE_DAYS: '14',
    HEARTBEAT_HOURS: '6',
    STALE_DAYS: '45',
    EPHEMERAL_STALE_HOURS: '36',
    ...overrides
  }
}

async function setup (overrides = {}) {
  const { handle } = await loadWorker()
  const d1 = applySchema(createD1())
  const env = makeEnv(d1, overrides)

  const call = async (method, url, { body, admin = false, cf, ip = '203.0.113.7' } = {}) => {
    const headers = { 'cf-connecting-ip': ip }
    if (admin) headers.authorization = `Bearer ${ADMIN}`
    const response = await handle(makeRequest(method, url, {
      body,
      headers,
      cf: { asn: 64512, asOrganization: 'Example ISP', country: 'GB', colo: 'LHR', ...cf }
    }), env)
    let data = null
    try { data = JSON.parse(await response.text()) } catch { /* non-JSON */ }
    return { status: response.status, data }
  }

  await call('POST', '/v1/admin/products', {
    admin: true,
    body: { id: 'acme-core', name: 'Acme Core', coreKey: CORE_KEY }
  })

  const created = await call('POST', '/v1/admin/licenses', {
    admin: true,
    body: { product: 'acme-core', customer: 'Acme Ltd', seats: 2, features: ['reports', 'sso'] }
  })

  return { call, env, d1, license: created.data }
}

const activation = (fingerprint, licenseKey, telemetry = {}) => ({
  product: 'acme-core',
  version: '1.4.0',
  licenseKey,
  fingerprint,
  sdk: '0.1.0',
  telemetry: { hostname: `host-${fingerprint}`, platform: 'linux', arch: 'x64', ...telemetry }
})

suite('licence server', { skip: sqliteAvailable ? false : 'node:sqlite requires Node 22+' }, () => {
  test('a valid activation returns a token this build can verify', async () => {
    const { call, license } = await setup()
    const response = await call('POST', '/v1/activate', { body: activation('fp-a', license.licenseKey) })

    assert.equal(response.status, 200)
    assert.equal(response.data.coreKey, CORE_KEY)

    // The point of the whole exercise: a token minted by the Worker's WebCrypto
    // must verify against the public key compiled into the client.
    const result = verify(response.data.token, keys.publicKey, {
      product: 'acme-core',
      fingerprint: 'fp-a'
    })
    assert.equal(result.state, 'active')
    assert.equal(result.claims.cus, 'Acme Ltd')
    assert.equal(result.claims.iss, 'licence.test')
    assert.deepEqual(result.claims.fea, ['reports', 'sso'])
    assert.equal(result.claims.seats, 2)
    assert.match(result.claims.wm, /^[0-9a-f]{8}$/)
  })

  test('the licence key is stored hashed and cannot be read back', async () => {
    const { d1, license } = await setup()
    const rows = d1._raw.prepare('SELECT * FROM licenses').all()
    assert.equal(rows.length, 1)
    assert.equal(rows[0].key_hash.length, 64)
    assert.equal(
      JSON.stringify(rows[0]).includes(license.licenseKey), false,
      'a dump of the database must not yield working keys'
    )
  })

  test('an unknown key, the wrong product, and a revoked licence are all refused', async () => {
    const { call, license } = await setup()

    assert.equal((await call('POST', '/v1/activate', {
      body: activation('fp-a', 'NOT-A-REAL-KEY')
    })).data.error, 'unknown_license')

    assert.equal((await call('POST', '/v1/activate', {
      body: { ...activation('fp-a', license.licenseKey), product: 'some-other-product' }
    })).data.error, 'wrong_product')

    await call('POST', '/v1/admin/revoke', { admin: true, body: { id: license.id, reason: 'chargeback' } })
    const revoked = await call('POST', '/v1/activate', { body: activation('fp-a', license.licenseKey) })
    assert.equal(revoked.status, 403)
    assert.equal(revoked.data.error, 'revoked')
  })

  test('an incomplete request is a 400, not a 500', async () => {
    const { call } = await setup()
    for (const body of [{}, { product: 'acme-core' }, { licenseKey: 'x', fingerprint: 'y' }]) {
      const response = await call('POST', '/v1/activate', { body })
      assert.equal(response.status, 400)
    }
  })

  test('seats are counted by distinct deployment, and the limit holds', async () => {
    const { call, license } = await setup()

    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })).status, 200)
    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-2', license.licenseKey) })).status, 200)

    const third = await call('POST', '/v1/activate', { body: activation('fp-3', license.licenseKey) })
    assert.equal(third.status, 409)
    assert.equal(third.data.error, 'seat_limit')
    assert.equal(third.data.used, 2)
    assert.equal(third.data.seats, 2)
  })

  test('re-activating an existing deployment does not consume a second seat', async () => {
    // Restart loops are the normal case. If every restart claimed a seat, a
    // customer on a two-seat licence would be locked out by lunchtime.
    const { call, license } = await setup()
    for (let i = 0; i < 20; i++) {
      assert.equal((await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })).status, 200)
    }
    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-2', license.licenseKey) })).status, 200)
  })

  test('releasing a seat frees it, and heart-beating afterwards does not sneak it back', async () => {
    const { call, license } = await setup()
    await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })
    await call('POST', '/v1/activate', { body: activation('fp-2', license.licenseKey) })

    await call('POST', '/v1/release', { body: activation('fp-1', license.licenseKey) })
    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-3', license.licenseKey) })).status, 200)

    // fp-1 was released and the seats are now full, so its heartbeat must be
    // re-checked against the limit rather than silently reinstated.
    const sneaky = await call('POST', '/v1/heartbeat', { body: activation('fp-1', license.licenseKey) })
    assert.equal(sneaky.status, 409)
  })

  test('a heartbeat from a known deployment renews without re-checking seats', async () => {
    const { call, license } = await setup()
    await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })
    const beat = await call('POST', '/v1/heartbeat', { body: activation('fp-1', license.licenseKey) })

    assert.equal(beat.status, 200)
    assert.equal(decodeUnverified(beat.data.token).fp, 'fp-1')
  })

  test('a stale deployment loses its seat, and an ephemeral one loses it sooner', async () => {
    const { call, d1, license } = await setup()
    await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })
    await call('POST', '/v1/activate', { body: activation('fp-2', license.licenseKey) })
    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-3', license.licenseKey) })).status, 409)

    // Two days of silence. Not enough for a real host (45 days), plenty for a
    // container that could not persist an identity (36 hours).
    const twoDaysAgo = Math.floor(Date.now() / 1000) - 2 * 86400
    d1._raw.prepare('UPDATE instances SET last_seen = ?, ephemeral = 1 WHERE fingerprint = ?')
      .run(twoDaysAgo, 'fp-1')
    assert.equal((await call('POST', '/v1/activate', { body: activation('fp-3', license.licenseKey) })).status, 200)

    d1._raw.prepare('UPDATE instances SET last_seen = ?, ephemeral = 0 WHERE fingerprint = ?')
      .run(twoDaysAgo, 'fp-2')
    assert.equal(
      (await call('POST', '/v1/activate', { body: activation('fp-4', license.licenseKey) })).status, 409,
      'a real host that has been off for two days keeps its seat'
    )
  })

  test('a token never outlives the subscription', async () => {
    const { call, d1, license } = await setup()
    // Subscription ends in two days; the default token TTL is seven.
    // Plus a minute, so the floor division cannot land on 1 if the test takes
    // a second to get here.
    const endsAt = Math.floor(Date.now() / 1000) + 2 * 86400 + 60
    d1._raw.prepare('UPDATE licenses SET expires_at = ? WHERE id = ?').run(endsAt, license.id)

    const response = await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })
    assert.equal(decodeUnverified(response.data.token).exp, endsAt)
    assert.match(response.data.notice, /expires in 2 days/)
  })

  test('an expired subscription is refused outright', async () => {
    const { call, d1, license } = await setup()
    d1._raw.prepare('UPDATE licenses SET expires_at = ? WHERE id = ?')
      .run(Math.floor(Date.now() / 1000) - 60, license.id)

    const response = await call('POST', '/v1/activate', { body: activation('fp-1', license.licenseKey) })
    assert.equal(response.data.error, 'expired')
  })

  test('the deployment log records where each instance came from', async () => {
    const { call, license } = await setup()
    await call('POST', '/v1/activate', {
      body: activation('fp-uk', license.licenseKey),
      cf: { asn: 64512, asOrganization: 'Example ISP', country: 'GB' },
      ip: '203.0.113.7'
    })

    const report = await call('GET', `/v1/admin/deployments?license=${license.id}`, { admin: true })
    const [instance] = report.data.instances

    assert.equal(instance.fingerprint, 'fp-uk')
    assert.equal(instance.hostname, 'host-fp-uk')
    assert.equal(instance.app_version, '1.4.0')
    assert.equal(instance.country, 'GB')
    assert.equal(instance.as_org, 'Example ISP')
    assert.ok(instance.ip_hash, 'correlatable')
    assert.equal(
      JSON.stringify(report.data).includes('203.0.113.7'), false,
      'but the address itself is not stored'
    )
    assert.equal(report.data.events[0].kind, 'activate')
  })

  test('one key across unrelated networks is what the sharing report flags', async () => {
    const { call, d1 } = await setup()
    const solo = (await call('POST', '/v1/admin/licenses', {
      admin: true, body: { product: 'acme-core', customer: 'Solo Dev', seats: 1 }
    })).data

    await call('POST', '/v1/activate', {
      body: activation('fp-home', solo.licenseKey),
      cf: { asn: 64512, asOrganization: 'Home ISP', country: 'GB' }
    })
    // The same key turning up on a different network in a different country.
    // Seats are still 1, so this is refused — but it is recorded, and the
    // record is the product.
    await call('POST', '/v1/activate', {
      body: activation('fp-office', solo.licenseKey),
      cf: { asn: 64513, asOrganization: 'Other Corp', country: 'DE' }
    })
    // Force the second instance in, as if the customer had bought a seat.
    d1._raw.prepare('UPDATE licenses SET seats = 2 WHERE id = ?').run(solo.id)
    await call('POST', '/v1/activate', {
      body: activation('fp-office', solo.licenseKey),
      cf: { asn: 64513, asOrganization: 'Other Corp', country: 'DE' }
    })

    const report = await call('GET', '/v1/admin/report', { admin: true })
    const row = report.data.licenses.find((l) => l.id === solo.id)

    assert.equal(row.instances, 2)
    assert.equal(row.networks, 2)
    assert.equal(row.countries, 2)
    assert.equal(row.sharingSuspected, true)
    assert.ok(report.data.flagged.includes(solo.id))
  })

  test('an ordinary customer growing inside one network is not flagged', async () => {
    const { call, license } = await setup()
    for (const fp of ['fp-1', 'fp-2']) {
      await call('POST', '/v1/activate', {
        body: activation(fp, license.licenseKey),
        cf: { asn: 64512, asOrganization: 'Acme Hosting', country: 'GB' }
      })
    }
    const report = await call('GET', '/v1/admin/report', { admin: true })
    const row = report.data.licenses.find((l) => l.id === license.id)

    assert.equal(row.instances, 2)
    assert.equal(row.sharingSuspected, false, 'two boxes in one datacentre is a customer, not a leak')
    assert.equal(row.overSeats, false)
  })

  test('admin routes are closed without the bearer token', async () => {
    const { call } = await setup()
    for (const route of ['/v1/admin/report', '/v1/admin/deployments']) {
      assert.equal((await call('GET', route)).status, 401)
    }
    assert.equal((await call('POST', '/v1/admin/licenses', {
      body: { product: 'acme-core', customer: 'x' }
    })).status, 401)
  })

  test('an unset ADMIN_TOKEN locks the admin routes rather than opening them', async () => {
    const { handle } = await loadWorker()
    const env = makeEnv(applySchema(createD1()), { ADMIN_TOKEN: undefined })
    const response = await handle(makeRequest('GET', '/v1/admin/report', {
      headers: { authorization: 'Bearer ' }
    }), env)
    assert.equal(response.status, 401)
  })

  test('a licence for a product that does not exist is refused at creation', async () => {
    const { call } = await setup()
    const response = await call('POST', '/v1/admin/licenses', {
      admin: true, body: { product: 'ghost', customer: 'Nobody' }
    })
    assert.equal(response.status, 400)
  })

  test('health needs nothing and unknown routes 404', async () => {
    const { call } = await setup()
    assert.equal((await call('GET', '/v1/health')).data.ok, true)
    assert.equal((await call('GET', '/v1/nope')).status, 404)
  })

  test('an internal failure is a 500 with nothing leaked, which makes the client fall back', async () => {
    const { handle } = await loadWorker()
    const env = makeEnv({
      prepare () { throw new Error('D1_ERROR: connection to /var/db/xyz refused') }
    })
    const response = await handle(makeRequest('POST', '/v1/activate', {
      body: activation('fp-1', 'KEY')
    }), env)
    const text = await response.text()

    assert.equal(response.status, 500)
    assert.equal(text.includes('/var/db/xyz'), false)
  })

  test('minted keys are unique and prefixed by product', async () => {
    const { _internals } = await loadWorker()
    const keysSeen = new Set()
    for (let i = 0; i < 200; i++) keysSeen.add(_internals.mintKey('acme-core'))
    assert.equal(keysSeen.size, 200)
    assert.match([...keysSeen][0], /^ACMECO(-[0-9A-F]{5}){5}$/)
  })

  test('the admin token comparison does not short-circuit on length', async () => {
    const { _internals } = await loadWorker()
    assert.equal(_internals.timingSafeEqual('abc', 'abc'), true)
    assert.equal(_internals.timingSafeEqual('abc', 'abd'), false)
    assert.equal(_internals.timingSafeEqual('abc', 'abcd'), false)
    assert.equal(_internals.timingSafeEqual('', 'abcd'), false)
  })

  test('a token minted here is rejected by a client that trusts a different key', async () => {
    const { call, license } = await setup()
    const response = await call('POST', '/v1/activate', { body: activation('fp-a', license.licenseKey) })
    const stranger = generateKeyPair()
    assert.throws(
      () => verify(response.data.token, stranger.publicKey),
      /signature does not verify/
    )
  })

  test('rotating SIGNING_KEY takes effect at once, even on an isolate that is already warm', async () => {
    // A regression test for a bug the end-to-end run found. The obvious
    // memoisation — import the key once, keep it in a module-level variable —
    // survives across requests in a Worker isolate, so after
    // `wrangler secret put SIGNING_KEY` the warm isolates carry on signing with
    // the old key. Nothing errors. Clients that have the new public key simply
    // start seeing invalid signatures, at a rate that depends on which isolate
    // answered, which is close to undiagnosable from the outside.
    const { call, env, license } = await setup()

    const before = await call('POST', '/v1/activate', { body: activation('fp-a', license.licenseKey) })
    assert.equal(verify(before.data.token, keys.publicKey).state, 'active')

    const rotated = generateKeyPair()
    env.SIGNING_KEY = rotated.workerSecret

    const after = await call('POST', '/v1/heartbeat', { body: activation('fp-a', license.licenseKey) })
    assert.equal(verify(after.data.token, rotated.publicKey).state, 'active', 'signed with the new key')
    assert.throws(() => verify(after.data.token, keys.publicKey), /signature does not verify/)
  })

  test('a short token TTL is honoured, for products that need fast revocation', async () => {
    const { call, license } = await setup({ TOKEN_TTL_DAYS: '0.0001' }) // ~8.6 seconds
    const response = await call('POST', '/v1/activate', { body: activation('fp-a', license.licenseKey) })
    const claims = decodeUnverified(response.data.token)
    assert.ok(claims.exp - claims.iat <= 9)

    assert.throws(
      () => verify(response.data.token, keys.publicKey, {
        now: Date.now() + 40 * 86400 * 1000, clockSkewSeconds: 0
      }),
      LicenseExpiredError
    )
  })

  test('health signs something, so a bad SIGNING_KEY is one curl away', async () => {
    // The bug this exists for: a key that will not import used to surface as
    // an opaque 500 on a customer's first activation, findable only in
    // `wrangler tail`. Health now fails loudly and says which mistake it was.
    const { handle } = await loadWorker()
    const d1 = applySchema(createD1())

    const good = await handle(makeRequest('GET', '/v1/health'), makeEnv(d1))
    assert.equal(good.status, 200)
    assert.deepEqual(
      { ...JSON.parse(await good.text()), now: undefined },
      { ok: true, signing: 'ok', now: undefined }
    )

    const cases = [
      [undefined, /not set/],
      // The actual mistake: the lgsk1_ key pasted where PKCS8 belongs. Its
      // base64url characters make atob throw somewhere unhelpful.
      ['lgsk1_' + 'a'.repeat(43), /right key in the wrong encoding/],
      ['lgpk1_' + 'a'.repeat(43), /cannot sign anything/],
      ['not base64 at all !!', /not valid base64/],
      [Buffer.alloc(20).toString('base64'), /decodes to 20 bytes; a PKCS8 Ed25519 private key is 48/]
    ]

    for (const [value, expected] of cases) {
      const response = await handle(
        makeRequest('GET', '/v1/health'),
        makeEnv(applySchema(createD1()), { SIGNING_KEY: value })
      )
      const body = JSON.parse(await response.text())
      assert.equal(response.status, 503, `${value} should be a 503`)
      assert.equal(body.ok, false)
      assert.equal(body.signing, 'unavailable')
      assert.match(body.detail, expected)
    }
  })

  test('a misconfigured signing key never leaks the key into the response', async () => {
    const { handle } = await loadWorker()
    const secret = 'lgsk1_' + 'S3CRET'.repeat(7) + 'x'
    const response = await handle(
      makeRequest('GET', '/v1/health'),
      makeEnv(applySchema(createD1()), { SIGNING_KEY: secret })
    )
    const text = await response.text()
    assert.equal(text.includes('S3CRET'), false)
    assert.equal(text.includes(secret), false)
  })
})
