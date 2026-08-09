/**
 * The licence server: one Cloudflare Worker, one D1 database, no bill.
 *
 * Workers' free tier is 100,000 requests a day. A customer fleet of a thousand
 * instances checking in every six hours is four thousand requests a day, so the
 * ceiling here is not a real constraint — which is the point. The alternative
 * on offer is a licensing SaaS at a few dollars per active install per month,
 * charging you for the privilege of being told about your own customers.
 *
 * Endpoints
 *
 *   POST /v1/activate     first contact from a deployment; claims a seat
 *   POST /v1/heartbeat    renewal; extends the token and updates last_seen
 *   POST /v1/release      voluntarily give a seat back (uninstallers)
 *   GET  /v1/health       liveness
 *
 *   POST /v1/admin/products     ─┐
 *   POST /v1/admin/licenses      │ bearer ADMIN_TOKEN
 *   POST /v1/admin/revoke        │
 *   GET  /v1/admin/report        │
 *   GET  /v1/admin/deployments  ─┘
 *
 * Bindings: DB (D1). Secrets: SIGNING_KEY (base64 PKCS8 Ed25519), ADMIN_TOKEN,
 * IP_SALT.
 */

const DEFAULTS = {
  TOKEN_TTL_DAYS: 7,
  GRACE_DAYS: 14,
  HEARTBEAT_HOURS: 6,
  // How long an instance keeps its seat without checking in. Long for real
  // hosts, short for ephemeral ones — a customer whose containers are recreated
  // hourly should not accumulate seats, and a customer whose on-premise box is
  // off for a fortnight's holiday should not lose one.
  STALE_DAYS: 45,
  EPHEMERAL_STALE_HOURS: 36
}

export default {
  async fetch (request, env, ctx) {
    return handle(request, env, ctx)
  }
}

export async function handle (request, env) {
  const url = new URL(request.url)
  const route = `${request.method} ${url.pathname}`

  try {
    switch (route) {
      case 'GET /v1/health': return await health(env)
      case 'POST /v1/activate': return await activate(request, env)
      case 'POST /v1/heartbeat': return await heartbeat(request, env)
      case 'POST /v1/release': return await release(request, env)

      case 'POST /v1/admin/products': return await admin(request, env, createProduct)
      case 'POST /v1/admin/licenses': return await admin(request, env, createLicense)
      case 'POST /v1/admin/revoke': return await admin(request, env, revokeLicense)
      case 'GET /v1/admin/report': return await admin(request, env, report)
      case 'GET /v1/admin/deployments': return await admin(request, env, deployments)

      default:
        return json({ error: 'not_found', message: `No route for ${route}.` }, 404)
    }
  } catch (err) {
    // Never leak an internal message to a customer's log. The 500 is what makes
    // the client fall back to cache, which is the correct outcome for a bug on
    // this side of the wire.
    console.error('license-guard', route, err?.stack || err)
    return json({ error: 'server_error', message: 'The licence server hit an internal error.' }, 500)
  }
}

/* ------------------------------------------------------------------ *
 * Customer-facing
 * ------------------------------------------------------------------ */

/**
 * Liveness that actually asserts the thing this server exists to do.
 *
 * A health check that only proves the Worker is running is worth very little
 * here. The failure that matters is a signing key that will not import, and
 * with a bare `{ok:true}` the first thing to notice is a customer's first
 * activation, returning an opaque 500, diagnosable only through `wrangler
 * tail`. That happened. So health signs something, and answers 503 when it
 * cannot, which is both a truthful status for an uptime monitor and one curl
 * away from the operator after every deploy.
 *
 * Nothing secret goes in the response. `detail` is only ever set from a
 * ConfigError, whose messages are written for this.
 */
async function health (env) {
  try {
    const key = await signingKey(env)
    await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode('license-guard health'))
  } catch (err) {
    if (!err?.configuration) console.error('license-guard health', err?.stack || err)
    return json({
      ok: false,
      now: nowSeconds(),
      signing: 'unavailable',
      detail: err?.configuration
        ? err.message
        : 'The signing key could not be used. See the Worker logs.'
    }, 503)
  }
  return json({ ok: true, now: nowSeconds(), signing: 'ok' })
}

async function activate (request, env) {
  const body = await readJson(request)
  const context = requestContext(request, env, body)

  const found = await resolveLicense(env, body)
  if (found.error) {
    await logEvent(env, { kind: 'activate', outcome: 'denied', detail: found.error, ...context })
    return json(found, found.status)
  }
  const { license, product } = found

  const instanceId = `${license.id}:${body.fingerprint}`
  const existing = await env.DB
    .prepare('SELECT * FROM instances WHERE id = ?')
    .bind(instanceId)
    .first()

  if (!existing || existing.released_at) {
    const used = await countActiveInstances(env, license.id, instanceId)
    if (used >= license.seats) {
      await logEvent(env, {
        kind: 'activate',
        outcome: 'denied',
        detail: `seat_limit ${used}/${license.seats}`,
        license_id: license.id,
        ...context
      })
      return json({
        error: 'seat_limit',
        message:
          `This licence covers ${license.seats} deployment${license.seats === 1 ? '' : 's'} and ` +
          `${used} are already active. Release one, or ask for more seats.`,
        seats: license.seats,
        used
      }, 409)
    }
  }

  await upsertInstance(env, { instanceId, license, body, context, activation: true })
  const token = await issueToken(env, { license, product, fingerprint: body.fingerprint })

  await logEvent(env, {
    kind: 'activate',
    outcome: 'ok',
    license_id: license.id,
    product_id: product.id,
    ...context
  })

  return json({
    token,
    coreKey: product.core_key,
    heartbeatSeconds: intEnv(env, 'HEARTBEAT_HOURS') * 3600,
    notice: expiryNotice(license)
  })
}

async function heartbeat (request, env) {
  const body = await readJson(request)
  const context = requestContext(request, env, body)

  const found = await resolveLicense(env, body)
  if (found.error) {
    await logEvent(env, { kind: 'heartbeat', outcome: 'denied', detail: found.error, ...context })
    return json(found, found.status)
  }
  const { license, product } = found

  const instanceId = `${license.id}:${body.fingerprint}`
  // A heartbeat from an instance that was released, or that this server has
  // never seen, is treated as a fresh activation and re-checked against the
  // seat limit. Otherwise "release then keep heart-beating" is a free seat.
  const existing = await env.DB
    .prepare('SELECT * FROM instances WHERE id = ? AND released_at IS NULL')
    .bind(instanceId)
    .first()

  if (!existing) return activate(request, env)

  await upsertInstance(env, { instanceId, license, body, context, activation: false })
  const token = await issueToken(env, { license, product, fingerprint: body.fingerprint })

  await logEvent(env, {
    kind: 'heartbeat',
    outcome: 'ok',
    license_id: license.id,
    product_id: product.id,
    ...context
  })

  return json({
    token,
    coreKey: product.core_key,
    heartbeatSeconds: intEnv(env, 'HEARTBEAT_HOURS') * 3600,
    notice: expiryNotice(license)
  })
}

async function release (request, env) {
  const body = await readJson(request)
  const found = await resolveLicense(env, body)
  if (found.error) return json(found, found.status)

  await env.DB
    .prepare('UPDATE instances SET released_at = ? WHERE id = ? AND released_at IS NULL')
    .bind(nowSeconds(), `${found.license.id}:${body.fingerprint}`)
    .run()

  await logEvent(env, {
    kind: 'release',
    outcome: 'ok',
    license_id: found.license.id,
    ...requestContext(request, env, body)
  })
  return json({ released: true })
}

/* ------------------------------------------------------------------ *
 * Licence resolution
 * ------------------------------------------------------------------ */

async function resolveLicense (env, body) {
  if (!body?.licenseKey || !body?.fingerprint || !body?.product) {
    return {
      error: 'invalid_request',
      status: 400,
      message: 'product, licenseKey and fingerprint are all required.'
    }
  }

  const license = await env.DB
    .prepare('SELECT * FROM licenses WHERE key_hash = ?')
    .bind(await sha256hex(String(body.licenseKey)))
    .first()

  if (!license) {
    return {
      error: 'unknown_license',
      status: 403,
      message: 'This licence key is not recognised.'
    }
  }
  if (license.status === 'revoked') {
    return {
      error: 'revoked',
      status: 403,
      message: 'This licence has been revoked. Contact your supplier.'
    }
  }
  if (license.status !== 'active') {
    return {
      error: 'invalid_license',
      status: 403,
      message: `This licence is ${license.status}.`
    }
  }
  if (license.product_id !== body.product) {
    return {
      error: 'wrong_product',
      status: 403,
      message: `This licence is for "${license.product_id}", not "${body.product}".`
    }
  }
  if (license.expires_at && license.expires_at < nowSeconds()) {
    return {
      error: 'expired',
      status: 403,
      message: 'This licence expired. Renew it to continue receiving updates.'
    }
  }

  const product = await env.DB
    .prepare('SELECT * FROM products WHERE id = ?')
    .bind(license.product_id)
    .first()

  if (!product) {
    return {
      error: 'invalid_license',
      status: 500,
      message: 'This licence points at a product that no longer exists.'
    }
  }
  return { license, product }
}

/**
 * Seats in use, not counting the caller's own instance.
 *
 * "In use" means seen recently, and how recently depends on whether the client
 * could persist an identity. Without that split, one customer running your
 * product in a container that cannot write to disk would exhaust any seat count
 * you sell them within a day.
 */
async function countActiveInstances (env, licenseId, excludeId) {
  const now = nowSeconds()
  const row = await env.DB.prepare(`
    SELECT COUNT(*) AS n FROM instances
     WHERE license_id = ?
       AND id != ?
       AND released_at IS NULL
       AND last_seen > (CASE WHEN ephemeral = 1 THEN ? ELSE ? END)
  `).bind(
    licenseId,
    excludeId,
    now - intEnv(env, 'EPHEMERAL_STALE_HOURS') * 3600,
    now - intEnv(env, 'STALE_DAYS') * 86400
  ).first()
  return row?.n ?? 0
}

async function upsertInstance (env, { instanceId, license, body, context, activation }) {
  const now = nowSeconds()
  const t = body.telemetry || {}
  await env.DB.prepare(`
    INSERT INTO instances (
      id, license_id, fingerprint, first_seen, last_seen, released_at, ephemeral, activations,
      hostname, platform, arch, container, mac_hash, node_version, app_version,
      ip_hash, asn, as_org, country, colo
    ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      last_seen = excluded.last_seen,
      released_at = NULL,
      ephemeral = excluded.ephemeral,
      activations = instances.activations + excluded.activations,
      hostname = excluded.hostname,
      platform = excluded.platform,
      arch = excluded.arch,
      container = excluded.container,
      mac_hash = excluded.mac_hash,
      node_version = excluded.node_version,
      app_version = excluded.app_version,
      ip_hash = excluded.ip_hash,
      asn = excluded.asn,
      as_org = excluded.as_org,
      country = excluded.country,
      colo = excluded.colo
  `).bind(
    instanceId, license.id, body.fingerprint, now, now,
    t.ephemeral ? 1 : 0, activation ? 1 : 0,
    t.hostname ?? null, t.platform ?? null, t.arch ?? null, t.container ?? null,
    t.macHash ?? null, t.node ?? null, body.version ?? null,
    context.ip_hash, context.asn, context.as_org, context.country, context.colo ?? null
  ).run()
}

/* ------------------------------------------------------------------ *
 * Token issuing
 * ------------------------------------------------------------------ */

async function issueToken (env, { license, product, fingerprint }) {
  const now = nowSeconds()
  const ttl = intEnv(env, 'TOKEN_TTL_DAYS') * 86400

  // Never issue a token that outlives the subscription. The client honours exp
  // without asking anyone, so this is the only place the renewal date is
  // actually enforced.
  const exp = license.expires_at ? Math.min(now + ttl, license.expires_at) : now + ttl

  const claims = {
    jti: crypto.randomUUID(),
    iss: env.ISSUER || 'license-guard',
    prd: product.id,
    lic: license.id,
    cus: license.customer,
    fp: fingerprint,
    wm: license.watermark,
    plan: license.plan,
    fea: license.features ? String(license.features).split(',').filter(Boolean) : [],
    seats: license.seats,
    iat: now,
    exp,
    grc: intEnv(env, 'GRACE_DAYS') * 86400,
    hbt: intEnv(env, 'HEARTBEAT_HOURS') * 3600
  }

  const body = base64url(new TextEncoder().encode(JSON.stringify(claims)))
  const signingInput = `lgt1.${body}`
  const key = await signingKey(env)
  const signature = await crypto.subtle.sign(
    'Ed25519', key, new TextEncoder().encode(signingInput)
  )
  return `${signingInput}.${base64url(new Uint8Array(signature))}`
}

/**
 * Importing a key costs a millisecond, and a Worker isolate serves thousands of
 * requests, so it is memoised — but memoised *against the secret it came from*,
 * not simply held.
 *
 * The plain `if (cachedKey) return cachedKey` version is the obvious one and it
 * is wrong in a way that only shows up on the day it matters: after
 * `wrangler secret put SIGNING_KEY`, every warm isolate keeps signing with the
 * old key. Rotation appears to succeed, no error is logged anywhere, and
 * clients that have already picked up the new public key start rejecting
 * tokens at random depending on which isolate answered.
 */
let cached = { secret: null, key: null }
async function signingKey (env) {
  if (cached.key && cached.secret === env.SIGNING_KEY) return cached.key
  const pkcs8 = decodeSigningKey(env.SIGNING_KEY)
  let key
  try {
    key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign'])
  } catch (err) {
    throw new ConfigError(`SIGNING_KEY is well-formed base64 but WebCrypto refused it: ${err.message}`)
  }
  cached = { secret: env.SIGNING_KEY, key }
  return key
}

/**
 * Every way SIGNING_KEY gets set wrong, named.
 *
 * `keygen` prints three values and two of them are the same key, so pasting
 * the wrong one is the obvious mistake — and it used to surface as
 * `InvalidCharacterError: atob() called with invalid base64-encoded data`
 * from deep inside the runtime, on a customer's first activation, visible
 * only in `wrangler tail`. The value that causes it is the one starting
 * `lgsk1_`, whose `-` and `_` are base64url characters that atob rejects,
 * which is a very long way from "you pasted the wrong line".
 */
function decodeSigningKey (value) {
  const secret = typeof value === 'string' ? value.trim() : ''

  if (!secret) {
    throw new ConfigError(
      'SIGNING_KEY is not set. Install it with: wrangler secret put SIGNING_KEY'
    )
  }
  if (secret.startsWith('lgsk1_')) {
    throw new ConfigError(
      'SIGNING_KEY holds the lgsk1_ secret key. That is the right key in the wrong encoding — ' +
      'WebCrypto needs it as base64 PKCS8. Run `license-guard derive --worker-only` on the same ' +
      'secret to print the form this wants, then set it again.'
    )
  }
  if (secret.startsWith('lgpk1_')) {
    throw new ConfigError(
      'SIGNING_KEY holds a public key, which cannot sign anything. It needs the secret key in ' +
      'base64 PKCS8 form — `license-guard derive --worker-only`.'
    )
  }

  let bytes
  try {
    bytes = Uint8Array.from(atob(secret), (c) => c.charCodeAt(0))
  } catch {
    throw new ConfigError(
      'SIGNING_KEY is not valid base64. It should be the "Worker secret" line from ' +
      '`license-guard keygen`, or the output of `license-guard derive --worker-only`.'
    )
  }
  if (bytes.length !== 48) {
    throw new ConfigError(
      `SIGNING_KEY decodes to ${bytes.length} bytes; a PKCS8 Ed25519 private key is 48. ` +
      'It is probably truncated, or it is a different kind of key.'
    )
  }
  return bytes
}

/**
 * A misconfiguration, as opposed to a bug.
 *
 * The distinction earns its keep in two places: the message is safe to show an
 * operator (it never contains key material), and /v1/health can report it
 * rather than the generic "internal error" that a real bug gets.
 */
class ConfigError extends Error {
  constructor (message) {
    super(message)
    this.name = 'ConfigError'
    this.configuration = true
  }
}

/* ------------------------------------------------------------------ *
 * Admin
 * ------------------------------------------------------------------ */

async function admin (request, env, handler) {
  const header = request.headers.get('authorization') || ''
  const supplied = header.startsWith('Bearer ') ? header.slice(7) : ''
  if (!env.ADMIN_TOKEN || !timingSafeEqual(supplied, env.ADMIN_TOKEN)) {
    return json({ error: 'unauthorized' }, 401)
  }
  return handler(request, env)
}

async function createProduct (request, env) {
  const body = await readJson(request)
  if (!body?.id || !body?.coreKey) {
    return json({ error: 'invalid_request', message: 'id and coreKey are required.' }, 400)
  }
  await env.DB.prepare(`
    INSERT INTO products (id, name, core_key, min_version, created_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, core_key = excluded.core_key, min_version = excluded.min_version
  `).bind(body.id, body.name ?? body.id, body.coreKey, body.minVersion ?? null, nowSeconds()).run()
  return json({ product: body.id, updated: true })
}

/**
 * Mints a licence key and returns it exactly once.
 *
 * The key itself is never stored — only its hash — so there is no "show me the
 * key again" endpoint and cannot be one. That is a deliberate trade: it costs
 * you a support path and it means a compromised D1 database yields no working
 * keys.
 */
async function createLicense (request, env) {
  const body = await readJson(request)
  if (!body?.product || !body?.customer) {
    return json({ error: 'invalid_request', message: 'product and customer are required.' }, 400)
  }
  const product = await env.DB.prepare('SELECT id FROM products WHERE id = ?').bind(body.product).first()
  if (!product) {
    return json({ error: 'invalid_request', message: `No product "${body.product}".` }, 400)
  }

  const licenseKey = body.licenseKey || mintKey(body.product)
  const id = body.id || `lic_${randomHex(8)}`
  await env.DB.prepare(`
    INSERT INTO licenses (
      id, key_hash, product_id, customer, email, plan, features, seats, watermark,
      status, expires_at, notes, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
  `).bind(
    id,
    await sha256hex(licenseKey),
    body.product,
    body.customer,
    body.email ?? null,
    body.plan ?? 'standard',
    Array.isArray(body.features) ? body.features.join(',') : (body.features ?? ''),
    Number(body.seats) || 1,
    body.watermark || randomHex(4),
    body.expiresAt ?? null,
    body.notes ?? null,
    nowSeconds()
  ).run()

  return json({
    id,
    licenseKey,
    warning: 'This key is shown once and is not recoverable. Send it to the customer now.'
  }, 201)
}

async function revokeLicense (request, env) {
  const body = await readJson(request)
  if (!body?.id) return json({ error: 'invalid_request', message: 'id is required.' }, 400)
  const result = await env.DB
    .prepare('UPDATE licenses SET status = ?, notes = COALESCE(?, notes) WHERE id = ?')
    .bind(body.status || 'revoked', body.reason ?? null, body.id)
    .run()
  await logEvent(env, {
    kind: 'admin',
    outcome: body.status || 'revoked',
    license_id: body.id,
    detail: body.reason ?? null
  })
  return json({ id: body.id, changed: result?.meta?.changes ?? null })
}

/**
 * The sharing report — the thing this whole system is actually for.
 *
 * A leaked build that someone runs quietly on one machine is invisible here and
 * always will be. What is very visible is a licence key that has been passed
 * around: one key, many fingerprints, on networks belonging to different
 * companies in different countries. `networks` is the column to sort by. One
 * customer with eight instances inside one AS is a customer who grew. One
 * customer with eight instances across six ASes in four countries is a key
 * doing the rounds.
 */
async function report (request, env) {
  const url = new URL(request.url)
  const sinceDays = Number(url.searchParams.get('days')) || 30
  const since = nowSeconds() - sinceDays * 86400

  const { results } = await env.DB.prepare(`
    SELECT
      l.id, l.customer, l.plan, l.seats, l.status, l.product_id,
      COUNT(DISTINCT i.fingerprint)               AS instances,
      COUNT(DISTINCT i.asn)                       AS networks,
      COUNT(DISTINCT i.country)                   AS countries,
      COUNT(DISTINCT i.hostname)                  AS hostnames,
      MAX(i.last_seen)                            AS last_seen,
      SUM(CASE WHEN i.ephemeral = 1 THEN 1 ELSE 0 END) AS ephemeral_instances
    FROM licenses l
    LEFT JOIN instances i
      ON i.license_id = l.id AND i.released_at IS NULL AND i.last_seen > ?
    GROUP BY l.id
    ORDER BY networks DESC, instances DESC
  `).bind(since).all()

  const rows = (results || []).map((row) => ({
    ...row,
    overSeats: row.instances > row.seats,
    // Two independent networks for a single-seat licence is the cheapest
    // signal there is, and in practice it is the one that fires.
    sharingSuspected: row.networks > Math.max(1, row.seats) || row.countries > 1
  }))

  return json({
    windowDays: sinceDays,
    licenses: rows,
    flagged: rows.filter((r) => r.sharingSuspected || r.overSeats).map((r) => r.id)
  })
}

async function deployments (request, env) {
  const url = new URL(request.url)
  const licenseId = url.searchParams.get('license')
  const limit = Math.min(Number(url.searchParams.get('limit')) || 100, 500)

  const instances = await env.DB.prepare(`
    SELECT * FROM instances
     WHERE (? IS NULL OR license_id = ?)
     ORDER BY last_seen DESC LIMIT ?
  `).bind(licenseId, licenseId, limit).all()

  const events = await env.DB.prepare(`
    SELECT * FROM events
     WHERE (? IS NULL OR license_id = ?)
     ORDER BY at DESC LIMIT ?
  `).bind(licenseId, licenseId, limit).all()

  return json({
    instances: instances.results || [],
    events: events.results || []
  })
}

/* ------------------------------------------------------------------ *
 * Plumbing
 * ------------------------------------------------------------------ */

async function logEvent (env, fields) {
  await env.DB.prepare(`
    INSERT INTO events (
      at, kind, outcome, product_id, license_id, fingerprint, detail,
      hostname, app_version, ip_hash, asn, as_org, country
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    nowSeconds(),
    fields.kind,
    fields.outcome,
    fields.product_id ?? null,
    fields.license_id ?? null,
    fields.fingerprint ?? null,
    fields.detail ?? null,
    fields.hostname ?? null,
    fields.app_version ?? null,
    fields.ip_hash ?? null,
    fields.asn ?? null,
    fields.as_org ?? null,
    fields.country ?? null
  ).run()
}

/**
 * What Cloudflare knows about the caller, minus the part that is personal data.
 *
 * The IP is hashed with a salt that lives in a secret, so the table can
 * correlate ("these two instances came from the same address") without storing
 * an address. The ASN and country are not personal data and are the fields the
 * sharing report actually reads.
 */
function requestContext (request, env, body) {
  const cf = request.cf || {}
  const ip = request.headers.get('cf-connecting-ip') || ''
  return {
    ip_hash: ip ? syncHash(ip + (env.IP_SALT || '')) : null,
    asn: cf.asn ?? null,
    as_org: cf.asOrganization ?? null,
    country: cf.country ?? null,
    colo: cf.colo ?? null,
    fingerprint: body?.fingerprint ?? null,
    product_id: body?.product ?? null,
    hostname: body?.telemetry?.hostname ?? null,
    app_version: body?.version ?? null
  }
}

function expiryNotice (license) {
  if (!license.expires_at) return null
  const days = Math.floor((license.expires_at - nowSeconds()) / 86400)
  if (days > 14) return null
  return `This licence expires in ${days} day${days === 1 ? '' : 's'}.`
}

async function readJson (request) {
  try {
    return await request.json()
  } catch {
    return null
  }
}

function json (value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  })
}

function nowSeconds () {
  return Math.floor(Date.now() / 1000)
}

function intEnv (env, name) {
  const value = Number(env?.[name])
  return Number.isFinite(value) && value > 0 ? value : DEFAULTS[name]
}

async function sha256hex (value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Non-cryptographic, and only ever used for correlation of already-public IPs. */
function syncHash (value) {
  let h1 = 0xdeadbeef
  let h2 = 0x41c6ce57
  for (let i = 0; i < value.length; i++) {
    const ch = value.charCodeAt(i)
    h1 = Math.imul(h1 ^ ch, 2654435761)
    h2 = Math.imul(h2 ^ ch, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0')
}

function base64url (bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomHex (bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))]
    .map((b) => b.toString(16).padStart(2, '0')).join('')
}

function mintKey (product) {
  const prefix = String(product).replace(/[^a-z0-9]/gi, '').slice(0, 6).toUpperCase() || 'LIC'
  const body = randomHex(16).toUpperCase().match(/.{1,5}/g).slice(0, 5).join('-')
  return `${prefix}-${body}`
}

/**
 * Constant-time-ish string compare for the admin token.
 *
 * `a === b` on a secret leaks its length and its prefix through timing. Over
 * the public internet that is close to unexploitable, but the fix is four lines
 * and the alternative is explaining why you did not bother.
 */
function timingSafeEqual (a, b) {
  const x = new TextEncoder().encode(a)
  const y = new TextEncoder().encode(b)
  let diff = x.length ^ y.length
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0)
  }
  return diff === 0
}

export const _internals = {
  issueToken, resolveLicense, countActiveInstances, report, mintKey, timingSafeEqual, DEFAULTS
}
