'use strict'

const { computeFingerprint } = require('./fingerprint')
const { createVault } = require('./vault')
const { createTransport } = require('./transport')
const { verify, decodeUnverified } = require('./token')
const {
  LicenseError,
  LicenseInvalidError,
  LicenseMismatchError,
  LicenseRevokedError,
  LicenseExpiredError,
  LicenseServerError,
  SeatLimitError,
  ConfigurationError
} = require('./errors')

const SDK_VERSION = require('../package.json').version

/**
 * The runtime half of the scheme: activate, cache, heartbeat, degrade.
 *
 * Four states, and the transitions between them are the entire policy:
 *
 *   inactive  ──activate()──►  active   the server said yes, or a cached token
 *                                       is still inside its exp
 *        ▲                        │
 *        │                   exp passes, server unreachable
 *        │                        ▼
 *        │                     grace    fully functional, still retrying.
 *        │                        │     Lasts `grc` seconds — days, not minutes.
 *   fatal error                   │
 *        │                   grace runs out
 *        │                        ▼
 *        └──────────────────  degraded  the callback fires and the product
 *                                       decides. This library will not stop
 *                                       anything here.
 *
 * The one path that stops the product is a token that is *provably wrong* —
 * forged signature, revoked key, bound to another machine — because there is no
 * honest deployment in which those happen. Everything else is a failure to
 * confirm, and a failure to confirm is your problem, not your customer's.
 *
 * Read that as a business decision rather than a technical one. A pirate who
 * gets three extra weeks out of a grace window costs you one licence. A
 * fail-closed check that halts forty paying customers during a DNS incident
 * costs you the account, the renewal, and the reference.
 */
function createGuard (options = {}) {
  const {
    product,
    version = '0.0.0',
    publicKey,
    endpoint,
    licenseKey,
    stateDir,
    includeHost = false,
    offlineLicense = null,
    telemetry = 'full',
    heartbeat = true,
    now = () => Date.now(),
    logger = console,
    onStateChange = null,
    onDegrade = null,
    transport: injectedTransport = null,
    fingerprint: injectedFingerprint = null,
    setIntervalImpl = setInterval,
    clearIntervalImpl = clearInterval
  } = options

  if (!product) throw new ConfigurationError('createGuard() requires a `product` id.')
  if (!publicKey) throw new ConfigurationError('createGuard() requires the `publicKey` to trust.')
  if (!endpoint && !offlineLicense) {
    throw new ConfigurationError(
      'createGuard() requires an `endpoint`, or an `offlineLicense` for air-gapped installs.'
    )
  }

  const fp = injectedFingerprint || computeFingerprint({ product, stateDir, includeHost })
  const vault = createVault({ stateDir: fp.stateDir, fingerprintId: fp.id })
  const transport = endpoint
    ? injectedTransport || createTransport({
      endpoint,
      userAgent: `license-guard/${SDK_VERSION} ${product}/${version}`
    })
    : null

  let state = 'inactive'
  let session = null
  let timer = null
  let inFlight = null

  function transition (next, detail = {}) {
    if (next === state) return
    const previous = state
    state = next
    try {
      onStateChange?.({ from: previous, to: next, ...detail })
    } catch (err) {
      logger?.warn?.(`[license-guard] onStateChange threw: ${err.message}`)
    }
    if (next === 'grace') {
      logger?.warn?.(
        `[license-guard] Running on a cached licence for ${product}; the licence server is not ` +
        `reachable. Full functionality continues until ${new Date(session?.graceEndsAt || 0).toISOString()}.`
      )
    }
    if (next === 'degraded') {
      logger?.error?.(
        `[license-guard] The licence for ${product} could not be confirmed and its grace window ` +
        'has run out. The product has NOT been stopped — see onDegrade.'
      )
      try {
        onDegrade?.({ product, fingerprint: fp.id, reason: detail.reason || 'unconfirmed' })
      } catch (err) {
        logger?.warn?.(`[license-guard] onDegrade threw: ${err.message}`)
      }
    }
  }

  function telemetryPayload () {
    if (telemetry === false || telemetry === 'off') return {}
    if (telemetry === 'minimal') {
      return { ephemeral: fp.ephemeral, platform: fp.components.platform }
    }
    return { ephemeral: fp.ephemeral, ...fp.components }
  }

  function requestBody (extra = {}) {
    return {
      product,
      version,
      licenseKey,
      fingerprint: fp.id,
      sdk: SDK_VERSION,
      telemetry: telemetryPayload(),
      ...extra
    }
  }

  /** Turn the server's error vocabulary into this library's error classes. */
  function serverError (status, data) {
    const message = data?.message || `The licence server rejected this request (${status}).`
    switch (data?.error) {
      case 'revoked': return new LicenseRevokedError(message, { status })
      case 'seat_limit': return new SeatLimitError(message, {
        status, seats: data.seats, used: data.used
      })
      case 'unknown_license':
      case 'invalid_license': return new LicenseInvalidError(message, { status })
      case 'wrong_product': return new LicenseMismatchError(message, { status })
      case 'expired': return new LicenseExpiredError(message, { status })
      default:
        // An unrecognised 4xx is not a licence verdict we understand. Treating
        // it as fatal would let a future server bug take down every customer,
        // so it degrades instead.
        return new LicenseServerError(message, { status, error: data?.error })
    }
  }

  function adoptToken ({ token, coreKey, notice, heartbeatSeconds }) {
    const result = verify(token, publicKey, {
      now: now(),
      product,
      fingerprint: fp.id
    })
    session = {
      token,
      coreKey: coreKey || session?.coreKey || null,
      claims: result.claims,
      expiresAt: result.expiresAt,
      graceEndsAt: result.graceEndsAt,
      heartbeatSeconds: heartbeatSeconds || result.claims.hbt || 21600,
      notice: notice || null
    }
    if (notice) logger?.warn?.(`[license-guard] ${notice}`)
    return result
  }

  async function callServer (pathname, extra) {
    const { status, data } = await transport.post(pathname, requestBody(extra))
    if (status >= 400) throw serverError(status, data)
    if (!data?.token) {
      throw new LicenseServerError('The licence server answered without a token.', { status })
    }
    return data
  }

  /** The cached token, if it still verifies. Never throws. */
  function fromCache () {
    const cached = vault.read()
    if (!cached?.token) return null
    try {
      const result = adoptToken(cached)
      return result
    } catch (err) {
      if (err instanceof LicenseExpiredError) {
        // Kept, not discarded: an expired cached token is still proof that this
        // machine was licensed recently, and that is what degraded mode is for.
        session = { ...cached, claims: safeClaims(cached.token), expired: true }
        return { state: 'expired' }
      }
      // Forged or foreign. Not evidence of anything; drop it.
      vault.clear()
      session = null
      return null
    }
  }

  function safeClaims (token) {
    try {
      return decodeUnverified(token)
    } catch {
      return {}
    }
  }

  async function activate () {
    if (inFlight) return inFlight
    inFlight = doActivate().finally(() => { inFlight = null })
    return inFlight
  }

  async function doActivate () {
    if (offlineLicense) {
      // Air-gapped installs. `fp: '*'` in the token is what makes one of these
      // portable; issuing it is a deliberate act with `--any-machine`.
      adoptToken(normalizeOfflineLicense(offlineLicense))
      transition('active', { source: 'offline' })
      return snapshot()
    }

    const cached = fromCache()
    if (cached && cached.state === 'active') {
      transition('active', { source: 'cache' })
      scheduleHeartbeat()
      // The token is good, so nothing blocks — but the server still wants to
      // know this deployment is alive, and it is the check-in that populates
      // your deployment reports. Fire it and move on. backgroundHeartbeat()
      // swallows its own failures; the catch here is belt and braces against
      // an unhandled rejection taking down a customer's process.
      backgroundHeartbeat().catch(() => {})
      return snapshot()
    }

    try {
      const data = await callServer('/v1/activate', {})
      adoptToken(data)
      vault.write({ token: session.token, coreKey: session.coreKey })
      transition('active', { source: 'server' })
      scheduleHeartbeat()
      return snapshot()
    } catch (err) {
      if (err instanceof LicenseError && err.fatal) {
        vault.clear()
        session = null
        transition('inactive', { reason: err.code })
        throw err
      }

      // Non-fatal: the server could not confirm. Fall back to whatever the
      // cache can still prove.
      if (cached?.state === 'grace') {
        transition('grace', { reason: err.code })
        scheduleHeartbeat()
        return snapshot()
      }
      if (cached?.state === 'expired' || session) {
        transition('degraded', { reason: err.code })
        scheduleHeartbeat()
        return snapshot()
      }

      // No cache and no server. There is nothing to run on — the core key has
      // never been on this machine. This is the one situation where a first
      // start genuinely cannot proceed, and saying so plainly beats a
      // decryption error three frames deeper.
      transition('inactive', { reason: err.code })
      throw new LicenseServerError(
        `${product} has not been activated on this machine yet and the licence server at ` +
        `${transport.endpoint} could not be reached (${err.message}). The first activation needs ` +
        'network access; every later start can run from cache.',
        { cause: err }
      )
    }
  }

  async function heartbeatOnce () {
    if (!transport || offlineLicense) return snapshot()
    try {
      const data = await callServer('/v1/heartbeat', { token: session?.token || null })
      adoptToken(data)
      vault.write({ token: session.token, coreKey: session.coreKey })
      transition('active', { source: 'heartbeat' })
    } catch (err) {
      if (err instanceof LicenseError && err.fatal) {
        // A revocation arriving mid-run is the one remote kill switch, and it
        // is deliberately narrow: it fires only when the server explicitly
        // says this licence is no longer valid.
        vault.clear()
        transition('inactive', { reason: err.code })
        throw err
      }
      const nowMs = now()
      if (session && nowMs <= session.graceEndsAt) transition('grace', { reason: err.code })
      else if (session) transition('degraded', { reason: err.code })
    }
    return snapshot()
  }

  async function backgroundHeartbeat () {
    try {
      await heartbeatOnce()
    } catch (err) {
      if (err instanceof LicenseError && err.fatal) {
        logger?.error?.(`[license-guard] ${err.message}`)
      }
    }
  }

  function scheduleHeartbeat () {
    if (!heartbeat || timer || !transport) return
    const seconds = Math.max(60, Math.min(session?.heartbeatSeconds || 21600, 86400))
    timer = setIntervalImpl(() => { backgroundHeartbeat().catch(() => {}) }, seconds * 1000)
    // Never hold the event loop open. A licensing library that stops `node
    // script.js` from exiting is a bug report waiting to happen.
    timer?.unref?.()
  }

  function snapshot () {
    return {
      status: state,
      product,
      fingerprint: fp.id,
      ephemeral: fp.ephemeral,
      claims: session?.claims || null,
      customer: session?.claims?.cus || null,
      plan: session?.claims?.plan || null,
      features: session?.claims?.fea || [],
      watermark: session?.claims?.wm || null,
      seats: session?.claims?.seats ?? null,
      coreKey: session?.coreKey || null,
      expiresAt: session?.expiresAt || null,
      graceEndsAt: session?.graceEndsAt || null,
      notice: session?.notice || null
    }
  }

  return {
    activate,
    heartbeat: heartbeatOnce,
    get status () { return state },
    get fingerprint () { return fp },
    snapshot,

    /** Feature gating. Unknown features are absent, never assumed. */
    has (feature) {
      return Array.isArray(session?.claims?.fea) && session.claims.fea.includes(feature)
    },

    /**
     * For the small number of call sites where you really do want to stop.
     * Deliberately opt-in and deliberately not called anywhere inside this
     * library.
     */
    require (feature) {
      if (!this.has(feature)) {
        throw new LicenseMismatchError(
          `This licence does not include "${feature}".`,
          { feature, plan: session?.claims?.plan || null }
        )
      }
    },

    stop () {
      if (timer) clearIntervalImpl(timer)
      timer = null
    },

    /** Forget this machine's activation. Used by uninstallers and by tests. */
    reset () {
      this.stop()
      vault.clear()
      session = null
      transition('inactive', { reason: 'reset' })
    }
  }
}

function normalizeOfflineLicense (value) {
  if (typeof value === 'string') {
    try {
      return normalizeOfflineLicense(JSON.parse(value))
    } catch {
      throw new ConfigurationError(
        'An `offlineLicense` string must be the JSON contents of a file issued by ' +
        '`license-guard issue --offline`.'
      )
    }
  }
  if (!value?.token) {
    throw new ConfigurationError('An `offlineLicense` needs at least a `token`.')
  }
  return { token: value.token, coreKey: value.coreKey || value.key || null }
}

module.exports = { createGuard, SDK_VERSION }
