'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { createGuard } = require('../src/guard')
const { sign } = require('../src/token')
const { generateKeyPair } = require('../src/keys')
const {
  LicenseRevokedError, SeatLimitError, LicenseServerError, LicenseMismatchError
} = require('../src/errors')

const keys = generateKeyPair()
const PRODUCT = 'acme-core'
const CORE_KEY = Buffer.alloc(32, 7).toString('base64')

const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lg-guard-'))
const silent = { warn () {}, error () {}, log () {} }

/**
 * A clock the test drives, and a licence server the test scripts.
 *
 * Everything interesting about this library happens across days: a token
 * expires, grace runs out, a heartbeat renews. Testing that with real time is
 * not testing it, so the clock is a variable and the transport is a function.
 */
function harness ({ ttlSeconds = 3600, graceSeconds = 86400, stateDir = tempDir() } = {}) {
  let now = Date.UTC(2026, 0, 1)
  const requests = []
  let respond = () => ({ ok: true })

  function issue (overrides = {}) {
    return sign({
      jti: `tok_${now}`,
      prd: PRODUCT,
      lic: 'lic_1',
      cus: 'Acme Ltd',
      fp: fingerprint.id,
      wm: 'w4t3rm4rk',
      plan: 'pro',
      fea: ['reports'],
      seats: 2,
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + ttlSeconds,
      grc: graceSeconds,
      hbt: 3600,
      ...overrides
    }, keys.secretKey)
  }

  const fingerprint = {
    id: 'fp-test-machine',
    ephemeral: false,
    stateDir,
    components: { hostname: 'test-host', platform: 'linux', arch: 'x64' }
  }

  const transport = {
    endpoint: 'https://licence.test',
    async post (pathname, body) {
      requests.push({ pathname, body })
      const outcome = respond({ pathname, body, issue })
      if (outcome instanceof Error) throw outcome
      if (outcome.status && outcome.status >= 400) return { status: outcome.status, data: outcome.data }
      return {
        status: 200,
        data: { token: outcome.token || issue(), coreKey: CORE_KEY, ...outcome.extra }
      }
    }
  }

  const states = []
  const degradations = []

  function build (options = {}) {
    return createGuard({
      product: PRODUCT,
      version: '1.0.0',
      publicKey: keys.publicKey,
      endpoint: 'https://licence.test',
      licenseKey: 'ACME-XXXXX',
      transport,
      fingerprint,
      logger: silent,
      now: () => now,
      onStateChange: (change) => states.push(`${change.from}->${change.to}`),
      onDegrade: (detail) => degradations.push(detail),
      setIntervalImpl: () => ({ unref () {} }),
      clearIntervalImpl: () => {},
      ...options
    })
  }

  return {
    build,
    issue,
    requests,
    states,
    degradations,
    fingerprint,
    stateDir,
    get now () { return now },
    advance (seconds) { now += seconds * 1000 },
    serve (fn) { respond = fn }
  }
}

test('a first activation calls the server and returns a usable session', async () => {
  const h = harness()
  h.serve(() => ({}))

  const session = await h.build().activate()

  assert.equal(session.status, 'active')
  assert.equal(session.customer, 'Acme Ltd')
  assert.equal(session.coreKey, CORE_KEY)
  assert.equal(session.watermark, 'w4t3rm4rk')
  assert.deepEqual(session.features, ['reports'])
  assert.equal(h.requests[0].pathname, '/v1/activate')
  assert.equal(h.requests[0].body.fingerprint, 'fp-test-machine')
})

test('telemetry is sent by default, trimmed on request, and never mandatory', async () => {
  const h = harness()
  h.serve(() => ({}))

  await h.build().activate()
  assert.equal(h.requests[0].body.telemetry.hostname, 'test-host')

  await h.build({ telemetry: 'minimal', stateDir: tempDir() }).activate()
  assert.equal(h.requests[1].body.telemetry.hostname, undefined)
  assert.equal(h.requests[1].body.telemetry.platform, 'linux')

  await h.build({ telemetry: false }).activate()
  assert.deepEqual(h.requests[2].body.telemetry, {})
})

test('a second start uses the cache and does not block on the network', async () => {
  const h = harness()
  h.serve(() => ({}))
  await h.build().activate()
  const afterFirst = h.requests.length

  // The server is now down. A restart must still come up.
  h.serve(() => new Error('down'))
  const session = await h.build().activate()

  assert.equal(session.status, 'active')
  assert.equal(session.coreKey, CORE_KEY, 'the core key came back from the cache')
  assert.ok(h.requests.length > afterFirst, 'it still tried to check in, in the background')
})

test('the server going down after expiry moves to grace, not to a stop', async () => {
  const h = harness({ ttlSeconds: 3600, graceSeconds: 7 * 86400 })
  h.serve(() => ({}))
  await h.build().activate()

  h.advance(2 * 3600) // past exp, well inside grace
  h.serve(() => new Error('connect ECONNREFUSED'))

  const session = await h.build().activate()
  assert.equal(session.status, 'grace')
  assert.equal(session.coreKey, CORE_KEY, 'still fully functional')
})

test('grace running out degrades and calls back — it does not throw', async () => {
  const h = harness({ ttlSeconds: 3600, graceSeconds: 86400 })
  h.serve(() => ({}))
  await h.build().activate()

  h.advance(30 * 86400)
  h.serve(() => new Error('still down'))

  const session = await h.build().activate()
  assert.equal(session.status, 'degraded')
  assert.equal(h.degradations.length, 1)
  assert.equal(h.degradations[0].product, PRODUCT)
  assert.equal(
    session.coreKey, CORE_KEY,
    'the product keeps running: this library never decides to stop a customer'
  )
})

test('a revocation is the one thing that does stop it', async () => {
  const h = harness()
  h.serve(() => ({ status: 403, data: { error: 'revoked', message: 'Licence withdrawn.' } }))

  await assert.rejects(
    h.build().activate(),
    (err) => err instanceof LicenseRevokedError && err.fatal
  )
})

test('a revocation takes one check-in to bite, and that is the honest cost of caching', async () => {
  // Worth stating plainly rather than discovering in an argument with a
  // customer: a cached token is a signed statement that was true when it was
  // issued, and nothing this process can do makes it untrue early. Revoking a
  // licence stops it within one token lifetime — seven days by default, or the
  // next heartbeat, whichever comes first. If you need same-minute revocation,
  // shorten TOKEN_TTL_DAYS and accept the extra traffic.
  const h = harness()
  h.serve(() => ({}))
  await h.build().activate()

  h.serve(() => ({ status: 403, data: { error: 'revoked', message: 'Chargeback.' } }))
  const restarted = h.build()

  const session = await restarted.activate()
  assert.equal(session.status, 'active', 'the cached token is still cryptographically valid')

  // The check-in is what carries the news. Awaited here; in production it runs
  // in the background on the heartbeat interval.
  await assert.rejects(restarted.heartbeat(), LicenseRevokedError)

  // From here the cache is gone, so the next start has nothing to fall back on.
  h.serve(() => new Error('down'))
  await assert.rejects(h.build().activate(), LicenseServerError)
})

test('a seat limit is refused clearly and reports the numbers', async () => {
  const h = harness()
  h.serve(() => ({
    status: 409,
    data: { error: 'seat_limit', message: '2 of 2 in use.', seats: 2, used: 2 }
  }))

  let thrown = null
  try { await h.build().activate() } catch (err) { thrown = err }
  assert.ok(thrown instanceof SeatLimitError)
  assert.equal(thrown.seats, 2)
  assert.equal(thrown.used, 2)
})

test('an unrecognised 4xx degrades rather than taking every customer down', async () => {
  // A future server bug that answers 400 to everything must not become an
  // outage across the installed base.
  const h = harness()
  h.serve(() => ({ status: 400, data: { error: 'some_new_code', message: 'huh' } }))

  let thrown = null
  try { await h.build().activate() } catch (err) { thrown = err }
  assert.ok(thrown instanceof LicenseServerError)
  assert.equal(thrown.fatal, false)
})

test('a first ever start with no network fails, and explains why', async () => {
  const h = harness()
  h.serve(() => new Error('ENOTFOUND'))

  await assert.rejects(
    h.build().activate(),
    /has not been activated on this machine yet.*first activation needs\s+network access/s
  )
})

test('a token minted for a different machine is discarded, not trusted', async () => {
  const h = harness()
  h.serve(({ issue }) => ({ token: issue({ fp: 'someone-elses-machine' }) }))

  await assert.rejects(h.build().activate(), LicenseMismatchError)
})

test('a token signed by the wrong key never becomes a session', async () => {
  const attacker = generateKeyPair()
  const h = harness()
  h.serve(() => ({
    token: sign({
      prd: PRODUCT,
      lic: 'lic_1',
      fp: 'fp-test-machine',
      seats: 99,
      exp: Math.floor(Date.UTC(2027, 0, 1) / 1000),
      fea: ['everything']
    }, attacker.secretKey)
  }))

  // This is the DNS-hijack / mitm-with-a-trusted-CA case: the client is talking
  // to something that is not your server. The embedded public key is what
  // stops it, and nothing else would.
  await assert.rejects(h.build().activate(), /signature does not verify/)
})

test('a heartbeat renews the token and clears grace', async () => {
  const h = harness({ ttlSeconds: 3600, graceSeconds: 86400 })
  h.serve(() => ({}))
  const guard = h.build()
  await guard.activate()

  h.advance(2 * 3600)
  h.serve(() => new Error('down'))
  await guard.heartbeat()
  assert.equal(guard.status, 'grace')

  h.serve(() => ({}))
  await guard.heartbeat()
  assert.equal(guard.status, 'active')
  assert.deepEqual(h.states, ['inactive->active', 'active->grace', 'grace->active'])
})

test('a revocation arriving mid-run is the remote kill switch', async () => {
  const h = harness()
  h.serve(() => ({}))
  const guard = h.build()
  await guard.activate()

  h.serve(() => ({ status: 403, data: { error: 'revoked', message: 'Chargeback.' } }))
  await assert.rejects(guard.heartbeat(), LicenseRevokedError)
  assert.equal(guard.status, 'inactive')
})

test('concurrent activate() calls make one request, not one per caller', async () => {
  const h = harness()
  h.serve(() => ({}))
  const guard = h.build()

  const sessions = await Promise.all([guard.activate(), guard.activate(), guard.activate()])
  assert.equal(h.requests.length, 1)
  assert.equal(new Set(sessions.map((s) => s.claims.jti)).size, 1)
})

test('feature gating reads the token, and require() is the only thing that throws', async () => {
  const h = harness()
  h.serve(() => ({}))
  const guard = h.build()
  await guard.activate()

  assert.equal(guard.has('reports'), true)
  assert.equal(guard.has('sso'), false)
  guard.require('reports')
  assert.throws(() => guard.require('sso'), /does not include "sso"/)
})

test('an air-gapped licence needs no server at all', async () => {
  const h = harness()
  const portable = h.issue({ fp: null, exp: Math.floor(Date.UTC(2027, 0, 1) / 1000) })

  const guard = createGuard({
    product: PRODUCT,
    publicKey: keys.publicKey,
    offlineLicense: { token: portable, coreKey: CORE_KEY },
    fingerprint: h.fingerprint,
    logger: silent,
    now: () => h.now
  })

  const session = await guard.activate()
  assert.equal(session.status, 'active')
  assert.equal(session.coreKey, CORE_KEY)
  assert.equal(h.requests.length, 0)
})

test('an offline licence that has genuinely expired is still refused', async () => {
  const h = harness()
  const stale = h.issue({ fp: null, exp: Math.floor(Date.UTC(2025, 0, 1) / 1000), grc: 0 })

  await assert.rejects(
    createGuard({
      product: PRODUCT,
      publicKey: keys.publicKey,
      offlineLicense: { token: stale, coreKey: CORE_KEY },
      fingerprint: h.fingerprint,
      logger: silent,
      now: () => h.now
    }).activate(),
    /grace window has run out/
  )
})

test('reset forgets the machine, which is what an uninstaller needs', async () => {
  const h = harness()
  h.serve(() => ({}))
  const guard = h.build()
  await guard.activate()
  guard.reset()

  assert.equal(guard.status, 'inactive')
  h.serve(() => new Error('down'))
  await assert.rejects(h.build().activate(), /has not been activated on this machine yet/)
})

test('the heartbeat timer never keeps the process alive', async () => {
  const timers = []
  const h = harness()
  h.serve(() => ({}))
  await h.build({
    setIntervalImpl: (fn, ms) => {
      const handle = { ms, unrefCalled: false, unref () { this.unrefCalled = true } }
      timers.push(handle)
      return handle
    }
  }).activate()

  assert.equal(timers.length, 1)
  assert.equal(timers[0].unrefCalled, true, 'a licensing library must not hold node open')
  assert.equal(timers[0].ms, 3600 * 1000)
})

test('missing configuration is refused at construction, not at first use', () => {
  assert.throws(() => createGuard({}), /requires a `product` id/)
  assert.throws(() => createGuard({ product: 'p' }), /requires the `publicKey`/)
  assert.throws(
    () => createGuard({ product: 'p', publicKey: keys.publicKey }),
    /requires an `endpoint`, or an `offlineLicense`/
  )
})
