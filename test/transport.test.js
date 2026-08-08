'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')

const { createTransport } = require('../src/transport')
const { LicenseServerError, ConfigurationError } = require('../src/errors')

/** A fetch that plays a scripted list of outcomes and records what it was sent. */
function scriptedFetch (script) {
  const calls = []
  let index = 0
  const impl = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) })
    const step = script[Math.min(index++, script.length - 1)]
    if (typeof step === 'function') return step(url, init)
    if (step instanceof Error) throw step
    return {
      status: step.status,
      headers: { get: (name) => step.headers?.[name.toLowerCase()] ?? null },
      async text () { return JSON.stringify(step.body ?? {}) }
    }
  }
  impl.calls = calls
  return impl
}

const instant = { sleep: async () => {}, random: () => 0.5 }

test('a 200 comes back parsed', async () => {
  const fetchImpl = scriptedFetch([{ status: 200, body: { token: 'lgt1.a.b' } }])
  const transport = createTransport({ endpoint: 'https://licence.test/', fetchImpl, ...instant })

  const result = await transport.post('/v1/activate', { product: 'acme' })
  assert.equal(result.status, 200)
  assert.equal(result.data.token, 'lgt1.a.b')
  assert.equal(fetchImpl.calls[0].url, 'https://licence.test/v1/activate', 'the trailing slash is normalised away')
  assert.equal(fetchImpl.calls[0].body.product, 'acme')
})

test('a 4xx is an answer and is not retried', async () => {
  // The server has made a decision about this licence. Hammering it will not
  // change the decision and will make an incident out of a rejection.
  const fetchImpl = scriptedFetch([{ status: 403, body: { error: 'revoked' } }])
  const transport = createTransport({ endpoint: 'https://licence.test', fetchImpl, ...instant })

  const result = await transport.post('/v1/activate', {})
  assert.equal(result.status, 403)
  assert.equal(result.data.error, 'revoked')
  assert.equal(fetchImpl.calls.length, 1)
})

test('a 5xx is retried and then reported', async () => {
  const fetchImpl = scriptedFetch([{ status: 502 }])
  const transport = createTransport({ endpoint: 'https://licence.test', fetchImpl, retries: 2, ...instant })

  await assert.rejects(transport.post('/v1/activate', {}), LicenseServerError)
  assert.equal(fetchImpl.calls.length, 3, 'the first attempt plus two retries')
})

test('a transient 5xx that recovers is not surfaced at all', async () => {
  const fetchImpl = scriptedFetch([
    { status: 503 },
    { status: 200, body: { token: 't' } }
  ])
  const transport = createTransport({ endpoint: 'https://licence.test', fetchImpl, ...instant })
  assert.equal((await transport.post('/v1/heartbeat', {})).data.token, 't')
})

test('a 429 with Retry-After waits the interval it was given', async () => {
  const waits = []
  const fetchImpl = scriptedFetch([
    { status: 429, headers: { 'retry-after': '2' } },
    { status: 200, body: { token: 't' } }
  ])
  const transport = createTransport({
    endpoint: 'https://licence.test',
    fetchImpl,
    sleep: async (ms) => { waits.push(ms) },
    random: () => 0.5
  })

  await transport.post('/v1/activate', {})
  assert.deepEqual(waits, [2000])
})

test('a network error is a non-fatal server error', async () => {
  const fetchImpl = scriptedFetch([Object.assign(new Error('getaddrinfo ENOTFOUND'), { name: 'TypeError' })])
  const transport = createTransport({ endpoint: 'https://licence.test', fetchImpl, retries: 0, ...instant })

  let thrown = null
  try { await transport.post('/v1/activate', {}) } catch (err) { thrown = err }
  assert.ok(thrown instanceof LicenseServerError)
  assert.equal(thrown.fatal, false)
  assert.match(thrown.message, /could not be reached/)
})

test('a hanging server is abandoned, not waited on', async () => {
  // The failure that costs the most goodwill: an un-timed request in a
  // customer's cold-start path during your outage.
  let aborted = false
  const fetchImpl = (url, init) => new Promise((resolve, reject) => {
    // A real fetch holds the event loop open with its socket; this fake has to
    // say so explicitly, or Node drains the loop and the test is cancelled
    // before the abort it is testing ever fires.
    const keepAlive = setInterval(() => {}, 1000)
    init.signal.addEventListener('abort', () => {
      clearInterval(keepAlive)
      aborted = true
      reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))
    })
  })
  const transport = createTransport({
    endpoint: 'https://licence.test', fetchImpl, timeoutMs: 20, retries: 0, ...instant
  })

  await assert.rejects(transport.post('/v1/activate', {}), /did not respond within 20ms/)
  assert.equal(aborted, true)
})

test('the total deadline caps the whole sequence, not each attempt', async () => {
  const fetchImpl = scriptedFetch([{ status: 500 }])
  const transport = createTransport({
    endpoint: 'https://licence.test',
    fetchImpl,
    retries: 20,
    timeoutMs: 5,
    totalTimeoutMs: 40,
    sleep: async (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    random: () => 1
  })

  const started = Date.now()
  await assert.rejects(transport.post('/v1/activate', {}), LicenseServerError)
  assert.ok(Date.now() - started < 1000, 'gave up quickly rather than retrying twenty times')
  assert.ok(fetchImpl.calls.length < 20)
})

test('a non-JSON body does not throw, it just yields no data', async () => {
  const fetchImpl = scriptedFetch([(url, init) => ({
    status: 200,
    headers: { get: () => null },
    async text () { return '<html>504 Gateway Timeout</html>' }
  })])
  const transport = createTransport({ endpoint: 'https://licence.test', fetchImpl, ...instant })
  const result = await transport.post('/v1/activate', {})
  assert.equal(result.data, null)
  assert.match(result.raw, /Gateway Timeout/)
})

test('constructing without an endpoint or without fetch fails immediately', () => {
  assert.throws(() => createTransport({}), ConfigurationError)
  assert.throws(
    () => createTransport({ endpoint: 'https://x', fetchImpl: null }),
    /Node 18\+ has one built in/
  )
})
