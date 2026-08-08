'use strict'

const { LicenseServerError, ConfigurationError } = require('./errors')

/**
 * Talking to the licence server, with a hard rule: this never hangs.
 *
 * A licence check sits in the startup path of somebody else's production
 * service. If the server is slow rather than down — a half-open TCP connection,
 * a DNS resolver that has stopped answering — an un-timed fetch will sit there
 * until the socket gives up, which on Linux can be minutes. A licensing library
 * that adds two minutes to a customer's cold start during your outage has done
 * more damage than the outage.
 *
 * So: an AbortController on every request, a small number of retries with
 * jittered backoff, and a total deadline across all of them. When the deadline
 * passes the caller gets a non-fatal LicenseServerError and falls back to
 * cache, which is exactly what should happen.
 */
function createTransport ({
  endpoint,
  fetchImpl = globalThis.fetch,
  timeoutMs = 5000,
  totalTimeoutMs = 15000,
  retries = 2,
  userAgent = 'license-guard',
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms).unref?.()),
  random = Math.random
} = {}) {
  if (!endpoint) throw new ConfigurationError('A licence server endpoint is required.')
  if (typeof fetchImpl !== 'function') {
    throw new ConfigurationError(
      'No fetch implementation available. Node 18+ has one built in; on older runtimes pass ' +
      '`fetchImpl` explicitly.'
    )
  }
  const base = String(endpoint).replace(/\/+$/, '')

  async function post (pathname, body) {
    const deadline = Date.now() + totalTimeoutMs
    let lastError = null

    for (let attempt = 0; attempt <= retries; attempt++) {
      const remaining = deadline - Date.now()
      if (remaining <= 0) break

      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), Math.min(timeoutMs, remaining))
      timer.unref?.()

      try {
        const response = await fetchImpl(`${base}${pathname}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            accept: 'application/json',
            'user-agent': userAgent
          },
          body: JSON.stringify(body),
          signal: controller.signal
        })

        const text = await response.text()
        let data = null
        try {
          data = text ? JSON.parse(text) : null
        } catch {
          data = null
        }

        // 4xx is an answer, not a failure — the server has decided something
        // about this licence and retrying will not change its mind.
        if (response.status < 500 && response.status !== 429) {
          return { status: response.status, data, raw: text }
        }

        lastError = new LicenseServerError(
          `The licence server returned ${response.status}.`,
          { status: response.status }
        )
        const retryAfter = Number(response.headers?.get?.('retry-after'))
        if (Number.isFinite(retryAfter) && retryAfter > 0) {
          await sleep(Math.min(retryAfter * 1000, Math.max(0, deadline - Date.now())))
          continue
        }
      } catch (err) {
        lastError = new LicenseServerError(
          err.name === 'AbortError'
            ? `The licence server did not respond within ${timeoutMs}ms.`
            : `The licence server could not be reached: ${err.message}`,
          { cause: err.name === 'AbortError' ? 'timeout' : 'network' }
        )
      } finally {
        clearTimeout(timer)
      }

      if (attempt < retries) {
        // Jitter, because every replica of a customer's service restarts at the
        // same moment and un-jittered backoff turns a deploy into a thundering
        // herd against your Worker.
        const backoff = Math.min(250 * 2 ** attempt, 2000)
        await sleep(backoff * (0.5 + random() * 0.5))
      }
    }

    throw lastError || new LicenseServerError('The licence server could not be reached.')
  }

  return { post, endpoint: base }
}

module.exports = { createTransport }
