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

import { dashboardPage } from './dashboard.js'
import { verifyRegistration, verifyAssertion, WebAuthnError, fromBase64url } from './webauthn.js'

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
      case 'GET /v1/admin/products': return await admin(request, env, listProducts)
      case 'POST /v1/admin/products/key': return await admin(request, env, revealCoreKey)
      case 'POST /v1/admin/licenses': return await admin(request, env, createLicense)
      case 'GET /v1/admin/licenses': return await admin(request, env, listLicenses)
      case 'PATCH /v1/admin/licenses': return await admin(request, env, updateLicense)
      case 'POST /v1/admin/revoke': return await admin(request, env, revokeLicense)
      case 'POST /v1/admin/release': return await admin(request, env, adminRelease)
      case 'GET /v1/admin/report': return await admin(request, env, report)
      case 'GET /v1/admin/deployments': return await admin(request, env, deployments)

      // The dashboard, and the session it runs on. Logging in is the one admin
      // route that cannot require an existing session.
      case 'GET /admin': return dashboard(request)
      case 'POST /v1/admin/session': return await openSession(request, env)
      case 'GET /v1/admin/session': return await admin(request, env, () => json({ ok: true }))
      case 'DELETE /v1/admin/session': return closeSession()

      // Passkeys. Registering one proves you are already an admin; using one is
      // how you become an admin, so the two login routes are necessarily public.
      case 'POST /v1/admin/passkeys/challenge': return await admin(request, env, registerChallenge)
      case 'POST /v1/admin/passkeys': return await admin(request, env, registerPasskey)
      case 'GET /v1/admin/passkeys': return await admin(request, env, listPasskeys)
      case 'DELETE /v1/admin/passkeys': return await admin(request, env, deletePasskey)
      case 'POST /v1/admin/passkey/challenge': return await loginChallenge(request, env)
      case 'POST /v1/admin/passkey/session': return await passkeySession(request, env)

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

/**
 * `preread` is the already-parsed body, passed in when heartbeat falls through
 * to here. A Request body is a stream and can only be read once, so re-reading
 * it would yield null and turn a legitimate re-activation into
 * `invalid_request` — which is exactly what it did until this was a parameter.
 */
async function activate (request, env, preread) {
  const body = preread !== undefined ? preread : await readJson(request)
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

  // Sign first, write second. The other order looks harmless and is not: if
  // signing throws — a mis-pasted SIGNING_KEY is how that happens — the seat
  // has already been claimed and `activations` already incremented for a
  // deployment that receives a 500 and no token. It then retries, and every
  // retry costs another activation while the events table records nothing at
  // all, because the log line is on the far side of the throw. Three real
  // instance rows with five activations and zero `ok` events is what that
  // looks like afterwards, and it is not a state you can read backwards.
  const token = await signOrLog(env, { license, product, fingerprint: body.fingerprint, kind: 'activate', context })

  await upsertInstance(env, { instanceId, license, body, context, activation: true })

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

  if (!existing) return activate(request, env, body)

  const token = await signOrLog(env, { license, product, fingerprint: body.fingerprint, kind: 'heartbeat', context })

  await upsertInstance(env, { instanceId, license, body, context, activation: false })

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
      -- COALESCE, not plain assignment. The telemetry block is optional, and a
      -- client may send it on activation then omit it from every heartbeat
      -- after — which with a plain assignment blanks the row six hours later,
      -- so the fleet view that exists to tell you which machine this is shows
      -- "(not reported)" for a deployment that reported perfectly well. An
      -- absent field means "not sent", never "cleared".
      --
      -- Note for anyone editing this string: it is a JS template literal, so a
      -- backtick anywhere in these comments ends it and the build fails with a
      -- syntax error pointing at the next word.
      hostname = COALESCE(excluded.hostname, instances.hostname),
      platform = COALESCE(excluded.platform, instances.platform),
      arch = COALESCE(excluded.arch, instances.arch),
      container = COALESCE(excluded.container, instances.container),
      mac_hash = COALESCE(excluded.mac_hash, instances.mac_hash),
      node_version = COALESCE(excluded.node_version, instances.node_version),
      app_version = COALESCE(excluded.app_version, instances.app_version),
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

/**
 * Sign, and if that fails leave a row saying so before rethrowing.
 *
 * The events table is the only thing that answers "what happened" without a
 * `wrangler tail` session that was running at the time. A signing failure is
 * precisely the case where nobody is tailing — it happens on the first
 * activation after a deploy — so it is the one failure that most needs to be
 * written down. The rethrow is what still produces the 500.
 */
async function signOrLog (env, { license, product, fingerprint, kind, context }) {
  try {
    return await issueToken(env, { license, product, fingerprint })
  } catch (err) {
    await logEvent(env, {
      kind,
      outcome: 'error',
      detail: `signing_failed: ${err?.message || err}`.slice(0, 300),
      license_id: license.id,
      product_id: product.id,
      ...context
    }).catch(() => {})
    throw err
  }
}

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

/**
 * Two ways in, for two different callers.
 *
 * The CLI sends the admin token as a bearer header, which is right for a
 * program: it holds the token already, and there is no browser to trick.
 *
 * The dashboard cannot do that. Keeping a bearer token in a page means keeping
 * it somewhere JavaScript can read, and then any script that gets injected into
 * that page — or any browser extension — can read it too, and unlike a session
 * a leaked admin token cannot be expired. So the dashboard trades the token
 * once for an HttpOnly cookie and never sees it again.
 *
 * A cookie brings CSRF with it, because the browser attaches it to requests the
 * page did not make. Two things stop that here: SameSite=Strict, which keeps
 * the cookie off cross-site requests entirely, and a required custom header,
 * which no cross-origin form or img tag can set and which forces a preflight
 * that this Worker answers for nobody.
 */
async function admin (request, env, handler) {
  if (!env.ADMIN_TOKEN) return json({ error: 'unauthorized' }, 401)

  const header = request.headers.get('authorization') || ''
  if (header.startsWith('Bearer ')) {
    if (!timingSafeEqual(header.slice(7), env.ADMIN_TOKEN)) {
      return json({ error: 'unauthorized' }, 401)
    }
    return handler(request, env)
  }

  const cookie = readCookie(request, SESSION_COOKIE)
  if (cookie && await validSession(cookie, env)) {
    if (request.method !== 'GET' && request.headers.get(CSRF_HEADER) !== '1') {
      return json({
        error: 'unauthorized',
        message: `A cookie-authenticated write needs the ${CSRF_HEADER} header.`
      }, 401)
    }
    return handler(request, env)
  }

  return json({ error: 'unauthorized' }, 401)
}

/**
 * The dashboard page. Public, and deliberately so — it contains no data and no
 * credential, and every byte it later fetches goes through `admin()`. Hiding
 * the HTML behind the session would only mean writing a second login page.
 *
 * The nonce is what makes the Content-Security-Policy worth having: without it
 * the inline script and style need 'unsafe-inline', which permits every other
 * inline script too, which is most of what a CSP is for. `default-src 'none'`
 * then means an injected tag cannot load, connect or send anything anywhere,
 * and `form-action 'none'` means it cannot exfiltrate by submitting a form.
 */
function dashboard (request) {
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)))
  return new Response(dashboardPage(nonce), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        `style-src 'nonce-${nonce}'`,
        "connect-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "base-uri 'none'"
      ].join('; '),
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      // The admin surface has no business in a search index.
      'x-robots-tag': 'noindex, nofollow'
    }
  })
}

const SESSION_COOKIE = 'lg_admin'
const CSRF_HEADER = 'x-lg-dashboard'
const SESSION_SECONDS = 12 * 3600

/**
 * Trade the admin token for a session cookie.
 *
 * The session is signed with the admin token as the HMAC key, which has a
 * property worth having for free: rotating ADMIN_TOKEN invalidates every
 * outstanding session. There is no session table to clear and no way for a
 * session to outlive the credential it came from.
 */
async function openSession (request, env) {
  const body = await readJson(request)
  const supplied = typeof body?.token === 'string' ? body.token : ''
  if (!env.ADMIN_TOKEN || !timingSafeEqual(supplied, env.ADMIN_TOKEN)) {
    return json({ error: 'unauthorized', message: 'That is not the admin token.' }, 401)
  }

  return await grantSession(env, 'token')
}

/**
 * The session cookie itself, shared by both ways of proving you are the admin.
 *
 * A passkey login and a token login are deliberately indistinguishable
 * afterwards: same cookie, same lifetime, same signature. Everything
 * downstream of here checks a session, not how the session was earned.
 */
async function grantSession (env, method) {
  const expires = nowSeconds() + SESSION_SECONDS
  const value = `${expires}.${await sessionSignature(String(expires), env)}`
  return new Response(JSON.stringify({ ok: true, expires, method }), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      // Secure is unconditional. The dashboard is served over HTTPS in every
      // deployment that matters, and a cookie that will travel over plain HTTP
      // is one packet capture away from being the admin token itself. Local
      // http://127.0.0.1 is exempt in every browser's definition of a secure
      // context, so development still works.
      'set-cookie': `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Strict; ` +
        `Path=/; Max-Age=${SESSION_SECONDS}`
    }
  })
}

function closeSession () {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'set-cookie': `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
    }
  })
}

async function validSession (value, env) {
  const dot = value.indexOf('.')
  if (dot < 1) return false
  const expires = value.slice(0, dot)
  if (!/^\d+$/.test(expires) || Number(expires) < nowSeconds()) return false
  return timingSafeEqual(value.slice(dot + 1), await sessionSignature(expires, env))
}

let sessionKeyCache = { token: null, key: null }
async function sessionSignature (expires, env) {
  if (!sessionKeyCache.key || sessionKeyCache.token !== env.ADMIN_TOKEN) {
    sessionKeyCache = {
      token: env.ADMIN_TOKEN,
      key: await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(env.ADMIN_TOKEN),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      )
    }
  }
  const mac = await crypto.subtle.sign(
    'HMAC', sessionKeyCache.key, new TextEncoder().encode(`lgs1.${expires}`)
  )
  return base64url(new Uint8Array(mac))
}

function readCookie (request, name) {
  const header = request.headers.get('cookie') || ''
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=')
    if (eq > 0 && pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim()
  }
  return ''
}

/* ------------------------------------------------------------------ *
 * Passkeys
 *
 * The admin token is a shared secret that has to travel from a Keychain to a
 * clipboard to a text field to reach this server, and every one of those hops
 * is somewhere it can be read or left behind. A passkey never leaves the
 * authenticator: what arrives here is a signature over a challenge this server
 * chose, and the worst a stolen copy of this database yields is a public key.
 *
 * The token stays, for two reasons that are not sentiment. It is what the CLI
 * uses, and it is what authorises registering the first passkey — a passkey
 * cannot bootstrap itself, and if the only credential lives on one laptop then
 * losing the laptop loses the server.
 * ------------------------------------------------------------------ */

const CHALLENGE_SECONDS = 300

/**
 * Who the browser thinks it is talking to.
 *
 * Both values come from the request by default, which is what makes this work
 * unchanged on workers.dev, on a custom domain and on localhost. A passkey is
 * bound to the rp id it was registered under, so overriding these after
 * registering means the existing passkeys stop matching — that is WebAuthn
 * working, not a bug, and it is why the overrides exist at all: moving the
 * dashboard to a new hostname is a deliberate act with a known cost.
 */
function relyingParty (request, env) {
  const url = new URL(request.url)
  return {
    id: env.WEBAUTHN_RP_ID || url.hostname,
    origin: env.WEBAUTHN_ORIGIN || url.origin,
    name: env.ISSUER || 'license-guard'
  }
}

/**
 * Challenges live in D1 so that using one can delete it.
 *
 * Expired rows are swept on every issue rather than by a cron: the table is
 * only ever written by someone starting a login, and a five-minute lifetime
 * means the steady state is bounded by the rate of those attempts. It is not
 * free — an unauthenticated caller can make rows appear — but they expire
 * faster than they can accumulate into anything, and the alternative is a
 * scheduled worker to tidy a table that is normally empty.
 */
async function issueChallenge (env, purpose) {
  const now = nowSeconds()
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at < ?').bind(now).run()

  const challenge = base64url(crypto.getRandomValues(new Uint8Array(32)))
  await env.DB
    .prepare('INSERT INTO passkey_challenges (challenge, purpose, expires_at) VALUES (?, ?, ?)')
    .bind(challenge, purpose, now + CHALLENGE_SECONDS)
    .run()
  return challenge
}

/**
 * Spend a challenge, and say whether it was worth anything.
 *
 * The delete happens whether or not the row checks out. A challenge that has
 * been presented once is burnt regardless of the outcome, so a failed attempt
 * cannot be retried against the same challenge while an attacker files down
 * the rest of the request.
 */
async function consumeChallenge (env, challenge, purpose) {
  if (typeof challenge !== 'string' || !challenge) return false

  const row = await env.DB
    .prepare('SELECT purpose, expires_at FROM passkey_challenges WHERE challenge = ?')
    .bind(challenge).first()
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE challenge = ?').bind(challenge).run()

  return Boolean(row) && row.purpose === purpose && row.expires_at >= nowSeconds()
}

/**
 * Read the challenge the browser says it signed, before trusting anything else
 * in the payload.
 *
 * This is only a lookup key. It selects which row to spend; it proves nothing.
 * The proof is that `verifyRegistration`/`verifyAssertion` then check this same
 * value against the signed client data, so a caller who names someone else's
 * challenge has still signed over their own and fails there.
 */
function peekChallenge (clientDataJSON) {
  if (typeof clientDataJSON !== 'string') return ''
  try {
    const parsed = JSON.parse(new TextDecoder().decode(fromBase64url(clientDataJSON)))
    return typeof parsed?.challenge === 'string' ? parsed.challenge : ''
  } catch {
    return ''
  }
}

/** Options for creating a passkey. Admin-gated: this is the bootstrap. */
async function registerChallenge (request, env) {
  const rp = relyingParty(request, env)
  const challenge = await issueChallenge(env, 'register')
  const { results } = await env.DB.prepare('SELECT id FROM passkeys').all()

  return json({
    challenge,
    rp: { id: rp.id, name: rp.name },
    // One operator, so one stable user handle. It is not a secret and not a
    // login name; it exists because WebAuthn requires the field.
    user: { id: base64url(new TextEncoder().encode('admin')), name: 'admin', displayName: `${rp.name} admin` },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    // A discoverable credential is what lets the login screen offer the passkey
    // without being told who is logging in — which in turn is why the public
    // login endpoint can avoid listing credential ids to anyone who asks.
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestation: 'none',
    timeout: CHALLENGE_SECONDS * 1000,
    // Stops the same authenticator quietly registering itself twice.
    excludeCredentials: (results || []).map((row) => ({ type: 'public-key', id: row.id }))
  })
}

async function registerPasskey (request, env) {
  const body = await readJson(request)
  const credential = body?.credential
  const label = typeof body?.label === 'string' ? body.label.trim().slice(0, 64) : ''

  const challenge = peekChallenge(credential?.response?.clientDataJSON)
  if (!await consumeChallenge(env, challenge, 'register')) {
    return json({ error: 'unauthorized', message: 'That challenge is unknown or has expired.' }, 401)
  }

  const rp = relyingParty(request, env)
  let record
  try {
    record = await verifyRegistration(credential, { challenge, origin: rp.origin, rpId: rp.id })
  } catch (err) {
    if (!(err instanceof WebAuthnError)) throw err
    await logEvent(env, { kind: 'admin', outcome: 'refused', detail: `passkey registration refused: ${err.message}` })
    return json({ error: 'unauthorized', message: err.message }, 401)
  }

  await env.DB.prepare(`
    INSERT INTO passkeys (id, public_key, alg, sign_count, label, created_at) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      public_key = excluded.public_key, alg = excluded.alg,
      sign_count = excluded.sign_count, label = excluded.label
  `).bind(record.id, JSON.stringify(record.jwk), record.alg, record.signCount, label || null, nowSeconds()).run()

  await logEvent(env, {
    kind: 'admin',
    outcome: 'passkey-registered',
    detail: `passkey registered${label ? `: ${label}` : ''}`
  })

  return json({ registered: true, id: record.id, label: label || null, format: record.format })
}

async function listPasskeys (request, env) {
  const { results } = await env.DB.prepare(`
    SELECT id, label, alg, sign_count, created_at, last_used_at
      FROM passkeys ORDER BY created_at ASC
  `).all()
  return json({ passkeys: results || [] })
}

/**
 * Remove a passkey. The last one can go too.
 *
 * Refusing to delete the final passkey would be protecting the wrong thing:
 * the admin token still works, so an operator who has just lost the laptop
 * that holds their only credential needs this to succeed, not to be told it is
 * too dangerous.
 */
async function deletePasskey (request, env) {
  const body = await readJson(request)
  const id = typeof body?.id === 'string' ? body.id : ''
  if (!id) return json({ error: 'invalid_request', message: 'id is required.' }, 400)

  const result = await env.DB.prepare('DELETE FROM passkeys WHERE id = ?').bind(id).run()
  const changed = result?.meta?.changes ?? 0
  if (changed) {
    await logEvent(env, { kind: 'admin', outcome: 'passkey-removed', detail: 'passkey removed' })
  }
  return json({ removed: changed > 0 })
}

/**
 * Options for using a passkey. Public, because nobody is logged in yet.
 *
 * It returns no `allowCredentials`. Registration insisted on a discoverable
 * credential precisely so this list can be empty: the browser already knows
 * which passkey belongs to this site, and an unauthenticated caller learns
 * nothing here — not the credential ids, not even whether any passkey exists.
 */
async function loginChallenge (request, env) {
  const rp = relyingParty(request, env)
  return json({
    challenge: await issueChallenge(env, 'login'),
    rpId: rp.id,
    userVerification: 'required',
    timeout: CHALLENGE_SECONDS * 1000
  })
}

async function passkeySession (request, env) {
  // Sessions are signed with the admin token, so without one there is no
  // session to grant no matter how good the assertion is.
  if (!env.ADMIN_TOKEN) return json({ error: 'unauthorized' }, 401)

  const body = await readJson(request)
  const credential = body?.credential

  const challenge = peekChallenge(credential?.response?.clientDataJSON)
  if (!await consumeChallenge(env, challenge, 'login')) {
    return json({ error: 'unauthorized', message: 'That challenge is unknown or has expired.' }, 401)
  }

  const rp = relyingParty(request, env)
  let result
  try {
    result = await verifyAssertion(credential, { challenge, origin: rp.origin, rpId: rp.id }, async (id) => {
      const row = await env.DB
        .prepare('SELECT public_key, alg, sign_count FROM passkeys WHERE id = ?')
        .bind(id).first()
      if (!row) return null
      return { alg: row.alg, signCount: row.sign_count, jwk: JSON.parse(row.public_key) }
    })
  } catch (err) {
    if (!(err instanceof WebAuthnError)) throw err
    await logEvent(env, { kind: 'admin', outcome: 'refused', detail: `passkey login refused: ${err.message}` })
    // One message for every failure. Distinguishing "no such passkey" from
    // "bad signature" would tell an unauthenticated caller which credential ids
    // are real, which is exactly what the empty allowCredentials list avoids.
    return json({ error: 'unauthorized', message: 'That passkey was not accepted.' }, 401)
  }

  await env.DB
    .prepare('UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?')
    .bind(result.signCount, nowSeconds(), result.id).run()

  await logEvent(env, { kind: 'admin', outcome: 'passkey-login', detail: 'signed in with a passkey' })
  return await grantSession(env, 'passkey')
}

/**
 * Register a product, or update one.
 *
 * `coreKey` is optional, and what happens when it is missing is the whole point
 * of this function. A new product gets a fresh key. An *existing* product keeps
 * the one it has.
 *
 * The obvious version — require the key, always write what you are given —
 * turns "rename this product" into "issue a new AES key", which decrypts none
 * of the .lgc files already shipped. Every deployment of that product then
 * fails to load its core the next time it activates, and nothing in the request
 * looked like a destructive operation. Changing the key has to be something you
 * ask for by name.
 */
async function createProduct (request, env) {
  const body = await readJson(request)
  if (!body?.id) {
    return json({ error: 'invalid_request', message: 'id is required.' }, 400)
  }

  const existing = await env.DB
    .prepare('SELECT core_key, name FROM products WHERE id = ?')
    .bind(body.id).first()

  const coreKey = body.coreKey || existing?.core_key || base64(crypto.getRandomValues(new Uint8Array(32)))
  const rotated = Boolean(body.coreKey && existing && body.coreKey !== existing.core_key)

  await env.DB.prepare(`
    INSERT INTO products (id, name, core_key, min_version, created_at) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name, core_key = excluded.core_key, min_version = excluded.min_version
  `).bind(body.id, body.name ?? existing?.name ?? body.id, coreKey, body.minVersion ?? null, nowSeconds()).run()

  return json({
    product: body.id,
    created: !existing,
    updated: Boolean(existing),
    coreKey,
    rotated,
    warning: rotated
      ? 'The core key changed. Every .lgc file packed with the old key is now ' +
        'undecryptable, so repack and release before your customers next activate.'
      : undefined
  })
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

/**
 * Change a licence after it has been minted.
 *
 * Without this the only way to sell a customer a third seat is to edit D1 by
 * hand, which is a bad thing to be doing on a Friday against a live database,
 * and re-minting is worse: it hands them a second key and orphans every
 * instance row that made the first one worth having.
 *
 * The licence key and its hash are not in the writable set, and neither is the
 * watermark. The key cannot change because only its hash was ever kept. The
 * watermark cannot change because it is stamped into artefacts the customer has
 * already produced, and the reason it exists is to still match them next year.
 */
const LICENSE_FIELDS = {
  customer: (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  email: (v) => (v === null ? null : typeof v === 'string' ? v.trim() : undefined),
  plan: (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  notes: (v) => (v === null ? null : typeof v === 'string' ? v : undefined),
  status: (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  seats: (v) => (Number.isInteger(Number(v)) && Number(v) >= 1 ? Number(v) : undefined),
  expires_at: (v) => (v === null ? null : Number.isFinite(Number(v)) ? Math.round(Number(v)) : undefined),
  features: (v) => {
    if (Array.isArray(v)) return v.map(String).map((f) => f.trim()).filter(Boolean).join(',')
    return typeof v === 'string' ? v : undefined
  }
}

async function updateLicense (request, env) {
  const body = await readJson(request)
  if (!body?.id) return json({ error: 'invalid_request', message: 'id is required.' }, 400)

  const existing = await env.DB
    .prepare('SELECT * FROM licenses WHERE id = ?').bind(body.id).first()
  if (!existing) {
    return json({ error: 'invalid_request', message: `No licence "${body.id}".` }, 404)
  }

  const incoming = { ...body, expires_at: body.expiresAt !== undefined ? body.expiresAt : body.expires_at }
  const sets = []
  const values = []
  const changed = []
  for (const [column, coerce] of Object.entries(LICENSE_FIELDS)) {
    if (incoming[column] === undefined) continue
    const value = coerce(incoming[column])
    if (value === undefined) {
      return json({ error: 'invalid_request', message: `"${column}" is not a value this accepts.` }, 400)
    }
    if (value === existing[column]) continue
    sets.push(`${column} = ?`)
    values.push(value)
    changed.push(column)
  }

  if (!sets.length) return json({ id: body.id, changed: [], license: shapeLicense(existing) })

  await env.DB
    .prepare(`UPDATE licenses SET ${sets.join(', ')} WHERE id = ?`)
    .bind(...values, body.id)
    .run()

  await logEvent(env, {
    kind: 'admin',
    outcome: 'updated',
    license_id: body.id,
    product_id: existing.product_id,
    detail: changed.join(', ').slice(0, 300)
  })

  const updated = await env.DB
    .prepare('SELECT * FROM licenses WHERE id = ?').bind(body.id).first()
  const live = await countActiveInstances(env, body.id, '')

  return json({
    id: body.id,
    changed,
    license: shapeLicense(updated),
    live,
    // Lowering the seat count never evicts anyone: an instance that already
    // holds a seat skips the check on re-activation, by design, so restart
    // loops cannot lock a customer out. Say so, rather than let the number
    // imply an eviction that will not happen.
    notice: live > updated.seats
      ? `${live} deployments are live but the licence now covers ${updated.seats}. ` +
        'Nothing was cut off — the ones already running keep their seats until they go ' +
        'quiet or you release them. Only new deployments are refused.'
      : undefined
  })
}

function shapeLicense (row) {
  return {
    ...row,
    features: row.features ? String(row.features).split(',').filter(Boolean) : []
  }
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

/**
 * Every licence, with enough on each row to render a customer list without a
 * second request per customer.
 *
 * `live` is the seat count as the seat check itself computes it — same staleness
 * rule, same ephemeral split — because a dashboard that says "2 of 3" while the
 * server refuses the third activation is worse than no dashboard.
 */
async function listLicenses (request, env) {
  const now = nowSeconds()
  const staleCutoff = now - intEnv(env, 'STALE_DAYS') * 86400
  const ephemeralCutoff = now - intEnv(env, 'EPHEMERAL_STALE_HOURS') * 3600

  const { results } = await env.DB.prepare(`
    SELECT
      l.*,
      COUNT(i.id)                                 AS total,
      SUM(CASE WHEN i.released_at IS NULL
                AND i.last_seen > (CASE WHEN i.ephemeral = 1 THEN ? ELSE ? END)
               THEN 1 ELSE 0 END)                 AS live,
      COUNT(DISTINCT i.asn)                       AS networks,
      COUNT(DISTINCT i.country)                   AS countries,
      MAX(i.last_seen)                            AS last_seen
    FROM licenses l
    LEFT JOIN instances i ON i.license_id = l.id
    GROUP BY l.id
    ORDER BY l.created_at DESC
  `).bind(ephemeralCutoff, staleCutoff).all()

  return json({
    licenses: (results || []).map((row) => ({
      ...row,
      features: row.features ? String(row.features).split(',').filter(Boolean) : [],
      live: row.live || 0,
      overSeats: (row.live || 0) > row.seats
    })),
    config: {
      heartbeatSeconds: intEnv(env, 'HEARTBEAT_HOURS') * 3600,
      staleSeconds: intEnv(env, 'STALE_DAYS') * 86400,
      ephemeralStaleSeconds: intEnv(env, 'EPHEMERAL_STALE_HOURS') * 3600,
      tokenTtlSeconds: intEnv(env, 'TOKEN_TTL_DAYS') * 86400,
      graceSeconds: intEnv(env, 'GRACE_DAYS') * 86400,
      now
    }
  })
}

/**
 * The product list, deliberately without `core_key`.
 *
 * Listing the key alongside the name meant every core key you own travelled to
 * the browser on every dashboard load, and stayed in the page whether or not
 * anyone asked to see one. Nothing about drawing a table of names needs the
 * key. Reading one is now its own request — see `revealCoreKey` — so please do
 * not add the column back here for the convenience of one button.
 */
async function listProducts (request, env) {
  const { results } = await env.DB.prepare(`
    SELECT p.id, p.name, p.min_version, p.created_at,
           COUNT(l.id) AS licenses
      FROM products p
      LEFT JOIN licenses l ON l.product_id = p.id
     GROUP BY p.id
     ORDER BY p.created_at DESC
  `).all()
  return json({ products: results || [] })
}

/**
 * Hand back one product's core key, to a caller who asked for that one key.
 *
 * Three things follow from making this its own endpoint. The key is out of the
 * list response. The window it exists in a browser narrows to the single
 * product an operator clicked on. And reading a key becomes an event in the
 * audit trail, which a field on a bulk list read could never be — you can now
 * answer "when was this key last read, and was that me".
 *
 * POST, not GET, for two reasons. `admin()` only demands the anti-CSRF header
 * on writes, so a GET reveal would rest on SameSite alone; and a product id in
 * a query string puts the subject of the read into request logs and browser
 * history, which is the habit that leaks the key itself the day someone
 * decides the id parameter should be the key instead.
 */
async function revealCoreKey (request, env) {
  const body = await readJson(request)
  const id = typeof body?.id === 'string' ? body.id.trim() : ''
  if (!id) {
    return json({ error: 'invalid_request', message: 'id is required.' }, 400)
  }

  const row = await env.DB
    .prepare('SELECT core_key FROM products WHERE id = ?')
    .bind(id).first()
  if (!row) {
    return json({ error: 'not_found', message: `No product ${id}.` }, 404)
  }

  await logEvent(env, {
    kind: 'admin',
    outcome: 'revealed',
    product_id: id,
    detail: 'core key revealed'
  })

  return json({ product: id, coreKey: row.core_key })
}

/**
 * Free a seat from the operator's side.
 *
 * `/v1/release` needs the licence key, which is the right requirement for a
 * customer's uninstaller and an impossible one for you: the key was shown once
 * and never stored. Without this, a seat held by a machine that was thrown into
 * a skip could only be freed by waiting out STALE_DAYS or editing D1 by hand.
 */
async function adminRelease (request, env) {
  const body = await readJson(request)
  const instanceId = body?.instanceId ||
    (body?.license && body?.fingerprint ? `${body.license}:${body.fingerprint}` : '')
  if (!instanceId) {
    return json({
      error: 'invalid_request',
      message: 'Give instanceId, or license and fingerprint.'
    }, 400)
  }

  const result = await env.DB
    .prepare('UPDATE instances SET released_at = ? WHERE id = ? AND released_at IS NULL')
    .bind(nowSeconds(), instanceId)
    .run()
  const changed = result?.meta?.changes ?? 0

  const row = await env.DB
    .prepare('SELECT license_id, fingerprint FROM instances WHERE id = ?')
    .bind(instanceId).first()

  await logEvent(env, {
    kind: 'admin',
    outcome: changed ? 'released' : 'noop',
    license_id: row?.license_id ?? null,
    fingerprint: row?.fingerprint ?? null,
    detail: changed ? 'released by operator' : 'already released or unknown'
  })

  return json({ instanceId, released: changed > 0 })
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

function base64 (bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
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
