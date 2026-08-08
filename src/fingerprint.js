'use strict'

const os = require('os')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

/**
 * What counts as "this deployment".
 *
 * The obvious fingerprint — hash the hostname, the MAC address and the
 * platform — is the one every licensing tutorial shows, and it falls apart the
 * moment your customer runs your product the way people actually run software
 * in 2026. In a container the hostname is the container id and changes on every
 * restart; under Kubernetes it is the pod name and changes on every rollout;
 * the MAC belongs to a veth pair created at container start and is random. A
 * fingerprint built from those does not identify a deployment, it identifies a
 * *process launch*, and a customer with three replicas that restart nightly
 * burns through ninety "seats" a month.
 *
 * So identity and telemetry are separated here, and they answer different
 * questions:
 *
 *   the id         is stable across restarts and is what seats are counted by.
 *                  It comes from an instance id that is written to disk once
 *                  and read forever after — or supplied directly by the
 *                  operator, which is the right answer for immutable infra.
 *
 *   the components are everything we can observe — hostname, hashed MAC,
 *                  platform, container hints, Node version. None of it is
 *                  trusted, none of it decides anything, and all of it is
 *                  reported, because "one licence, forty hostnames across six
 *                  networks" is the signal that actually catches sharing.
 *
 * When the disk is read-only and no instance id was supplied, the id falls back
 * to the observable material and `ephemeral` is set. The server is expected to
 * count ephemeral instances loosely; a read-only filesystem is a normal
 * deployment, not an attack.
 */
function resolveStateDir (product, override = process.env.LICENSE_GUARD_STATE_DIR) {
  if (override) return path.join(override, sanitize(product))
  const home = os.homedir() || os.tmpdir()
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
    return path.join(base, 'license-guard', sanitize(product))
  }
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'license-guard', sanitize(product))
  }
  const base = process.env.XDG_STATE_HOME || path.join(home, '.local', 'state')
  return path.join(base, 'license-guard', sanitize(product))
}

/**
 * The persisted half of the identity.
 *
 * Written with mode 0600 and `wx` so two processes starting at once cannot
 * each generate an id and have the loser's win — whoever loses the create race
 * reads the winner's file. Without that, a clustered app would report as many
 * instances as it has workers on its very first boot.
 */
function loadInstanceId (stateDir) {
  const fromEnv = process.env.LICENSE_GUARD_INSTANCE_ID
  if (fromEnv) return { instanceId: fromEnv.trim(), source: 'env', ephemeral: false }

  const file = path.join(stateDir, 'instance-id')
  try {
    const existing = fs.readFileSync(file, 'utf8').trim()
    if (existing) return { instanceId: existing, source: 'disk', ephemeral: false }
  } catch {
    // Not there yet, or unreadable. Both lead to the same next step.
  }

  const generated = crypto.randomUUID()
  try {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, generated + '\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    return { instanceId: generated, source: 'created', ephemeral: false }
  } catch (err) {
    if (err.code === 'EEXIST') {
      try {
        return { instanceId: fs.readFileSync(file, 'utf8').trim(), source: 'disk', ephemeral: false }
      } catch { /* fall through to ephemeral */ }
    }
    return { instanceId: null, source: 'unavailable', ephemeral: true, reason: err.code || 'EIO' }
  }
}

/**
 * The secret used to encrypt the token cache at rest.
 *
 * Kept next to the instance id and never sent anywhere. Its only job is to make
 * a stolen cache file useless on any machine but this one — see vault.js for
 * exactly how much that is worth.
 */
function loadVaultSecret (stateDir) {
  const file = path.join(stateDir, 'vault-key')
  try {
    const existing = fs.readFileSync(file)
    if (existing.length >= 32) return existing
  } catch { /* create it below */ }

  const generated = crypto.randomBytes(32)
  try {
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, generated, { mode: 0o600, flag: 'wx' })
    return generated
  } catch (err) {
    if (err.code === 'EEXIST') {
      try { return fs.readFileSync(file) } catch { /* fall through */ }
    }
    return null
  }
}

/** Lowest-named external interface with a real MAC, hashed before it leaves. */
function primaryMac () {
  const interfaces = os.networkInterfaces()
  const candidates = []
  for (const name of Object.keys(interfaces).sort()) {
    for (const entry of interfaces[name] || []) {
      if (entry.internal) continue
      if (!entry.mac || entry.mac === '00:00:00:00:00:00') continue
      candidates.push(entry.mac)
    }
  }
  return candidates.length ? candidates[0] : null
}

/** Cheap container detection — reported, never enforced. */
function containerHint () {
  if (process.env.KUBERNETES_SERVICE_HOST) return 'kubernetes'
  if (process.env.AWS_LAMBDA_FUNCTION_NAME) return 'lambda'
  if (process.env.FLY_APP_NAME) return 'fly'
  if (process.env.RENDER) return 'render'
  if (process.env.DYNO) return 'heroku'
  try {
    if (fs.existsSync('/.dockerenv')) return 'docker'
  } catch { /* not fatal */ }
  return null
}

/**
 * @param {object} options
 * @param {string} options.product   product id — different products on one host
 *                                   get different ids, so a customer licensing
 *                                   two of your products is two seats, not one
 * @param {string} [options.stateDir] override the default location
 * @param {boolean} [options.includeHost] fold hostname + MAC into the id as
 *                                   well. Off by default: it makes the id
 *                                   stricter and much less stable. Turn it on
 *                                   only for on-premise installs on real
 *                                   hardware.
 */
function computeFingerprint ({ product, stateDir, includeHost = false } = {}) {
  if (!product) throw new TypeError('computeFingerprint() requires a product id.')

  const dir = stateDir ? path.join(stateDir, sanitize(product)) : resolveStateDir(product)
  const { instanceId, source, ephemeral, reason } = loadInstanceId(dir)

  const mac = primaryMac()
  const components = {
    hostname: os.hostname(),
    platform: process.platform,
    arch: process.arch,
    macHash: mac ? sha256hex(`mac:${mac}`).slice(0, 16) : null,
    cpus: os.cpus()?.length ?? null,
    container: containerHint(),
    node: process.versions.node,
    instanceSource: source
  }

  // With an instance id, the id is that and nothing else — which is the whole
  // point: it survives a hostname change, an interface change, a migration to
  // new hardware. Without one there is nothing to be stable about, so we use
  // what we can see and say so.
  const material = instanceId
    ? [product, instanceId, ...(includeHost ? [components.hostname, components.macHash] : [])]
    : [product, components.hostname, components.macHash, components.platform, components.arch]

  return {
    id: sha256hex(material.map((part) => `${String(part).length}:${part}`).join('|')).slice(0, 32),
    ephemeral: Boolean(ephemeral),
    ephemeralReason: reason || null,
    stateDir: dir,
    components
  }
}

function sha256hex (value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function sanitize (value) {
  return String(value).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 64) || 'product'
}

module.exports = {
  computeFingerprint,
  resolveStateDir,
  loadVaultSecret,
  primaryMac,
  containerHint
}
