'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { seal, open } = require('./aes')
const { loadVaultSecret } = require('./fingerprint')

/**
 * Where the cached token and the core key live between runs.
 *
 * Something has to be cached or the product cannot survive a restart during a
 * network outage, and the thing worth caching includes the core decryption key
 * — which is awkward, because that key is the one secret the whole scheme
 * exists to withhold.
 *
 * So be precise about what the encryption here buys, because it is easy to
 * oversell:
 *
 *   it does stop   copying `cache.bin` off a licensed machine and using it on
 *                  an unlicensed one. The key is derived from a random secret
 *                  in the state directory *and* the machine's fingerprint, so
 *                  the file is inert anywhere else — and inert even here if the
 *                  fingerprint changes.
 *
 *   it does stop   the cache being grep-able. A key sitting in a JSON file on
 *                  disk is one `grep -r` away from a screenshot in a chat.
 *
 *   it does not stop  someone with root on the licensed machine and an hour to
 *                  spare. Both halves of the derivation are readable there, by
 *                  construction — the process must be able to decrypt its own
 *                  cache without asking anyone. This is a lock on the door of a
 *                  house whose owner is the attacker.
 *
 * That last line is the honest summary of this entire library, and it is in
 * SECURITY.md too. Tier 2 buys weeks against a determined attacker, not
 * permanence.
 */
const MAGIC = Buffer.from('LGV1', 'ascii')
const INFO = Buffer.from('license-guard cache v1', 'utf8')

function createVault ({ stateDir, fingerprintId, fileName = 'cache.bin' } = {}) {
  const file = path.join(stateDir, fileName)
  let secret = null
  let resolved = false

  /** Deferred: a product that never goes offline never needs to create it. */
  function key () {
    if (!resolved) {
      secret = loadVaultSecret(stateDir)
      resolved = true
    }
    if (!secret) return null
    return Buffer.from(
      crypto.hkdfSync('sha256', secret, Buffer.from(fingerprintId, 'utf8'), INFO, 32)
    )
  }

  const aad = () => Buffer.concat([MAGIC, Buffer.from(fingerprintId, 'utf8')])

  return {
    file,

    /** Returns null for every failure. A bad cache is a cache miss, never a crash. */
    read () {
      const k = key()
      if (!k) return null
      let buffer
      try {
        buffer = fs.readFileSync(file)
      } catch {
        return null
      }
      if (buffer.length < 4 + 12 + 16 || !buffer.subarray(0, 4).equals(MAGIC)) return null
      try {
        const plaintext = open(
          {
            iv: buffer.subarray(4, 16),
            tag: buffer.subarray(16, 32),
            body: buffer.subarray(32)
          },
          k,
          aad(),
          'cache'
        )
        return JSON.parse(plaintext.toString('utf8'))
      } catch {
        // Wrong machine, rotated vault key, or a half-written file. All of them
        // mean the same thing to the caller: activate again.
        return null
      }
    },

    /** Best effort. A read-only filesystem must not stop the product starting. */
    write (value) {
      const k = key()
      if (!k) return false
      try {
        fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 })
        const { iv, tag, body } = seal(Buffer.from(JSON.stringify(value), 'utf8'), k, aad())
        // Written to a sibling and renamed, so a crash mid-write leaves the
        // previous good cache in place rather than a truncated one.
        const temporary = `${file}.${process.pid}.tmp`
        fs.writeFileSync(temporary, Buffer.concat([MAGIC, iv, tag, body]), { mode: 0o600 })
        fs.renameSync(temporary, file)
        return true
      } catch {
        return false
      }
    },

    clear () {
      try {
        fs.unlinkSync(file)
        return true
      } catch {
        return false
      }
    }
  }
}

module.exports = { createVault }
