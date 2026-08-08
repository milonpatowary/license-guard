'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { computeFingerprint, resolveStateDir } = require('../src/fingerprint')

function tempDir () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'lg-fp-'))
}

const withoutEnv = (names, fn) => {
  const saved = {}
  for (const name of names) {
    saved[name] = process.env[name]
    delete process.env[name]
  }
  try {
    return fn()
  } finally {
    for (const name of names) {
      if (saved[name] === undefined) delete process.env[name]
      else process.env[name] = saved[name]
    }
  }
}

test('the id is stable across calls, which is the whole point', () => {
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const stateDir = tempDir()
    const first = computeFingerprint({ product: 'acme', stateDir })
    const second = computeFingerprint({ product: 'acme', stateDir })
    assert.equal(first.id, second.id)
    assert.equal(first.ephemeral, false)
    assert.equal(second.components.instanceSource, 'disk')
  })
})

test('the instance id survives a hostname change', () => {
  // A pod rename, a `hostnamectl`, a move to new hardware. None of them should
  // cost the customer their seat, and the default id does not read the hostname.
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const stateDir = tempDir()
    const before = computeFingerprint({ product: 'acme', stateDir })
    const realHostname = os.hostname
    os.hostname = () => 'a-completely-different-host'
    try {
      assert.equal(computeFingerprint({ product: 'acme', stateDir }).id, before.id)
    } finally {
      os.hostname = realHostname
    }
  })
})

test('--include-host deliberately makes the id fragile', () => {
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const stateDir = tempDir()
    const before = computeFingerprint({ product: 'acme', stateDir, includeHost: true })
    const realHostname = os.hostname
    os.hostname = () => 'moved-to-new-hardware'
    try {
      assert.notEqual(computeFingerprint({ product: 'acme', stateDir, includeHost: true }).id, before.id)
    } finally {
      os.hostname = realHostname
    }
  })
})

test('two products on one machine are two deployments', () => {
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const stateDir = tempDir()
    assert.notEqual(
      computeFingerprint({ product: 'acme', stateDir }).id,
      computeFingerprint({ product: 'other', stateDir }).id
    )
  })
})

test('an explicit instance id wins, and is how immutable infrastructure behaves', () => {
  const stateDir = tempDir()
  process.env.LICENSE_GUARD_INSTANCE_ID = 'prod-eu-west-1'
  try {
    const a = computeFingerprint({ product: 'acme', stateDir })
    // A different state directory — a fresh container — still lands on the
    // same id, which is exactly what a rolling deploy needs.
    const b = computeFingerprint({ product: 'acme', stateDir: tempDir() })
    assert.equal(a.id, b.id)
    assert.equal(a.components.instanceSource, 'env')
    assert.equal(fs.existsSync(path.join(a.stateDir, 'instance-id')), false, 'nothing written')
  } finally {
    delete process.env.LICENSE_GUARD_INSTANCE_ID
  }
})

test('an unwritable state directory falls back and admits it', () => {
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    // A read-only container filesystem, modelled by rooting the state directory
    // under a regular file so every write fails with ENOTDIR. `chmod 0500`
    // would be the obvious way to do this and does nothing at all when the
    // tests run as root, which is how they run in CI.
    const file = path.join(tempDir(), 'not-a-directory')
    fs.writeFileSync(file, '')

    const fp = computeFingerprint({ product: 'acme', stateDir: path.join(file, 'state') })
    assert.equal(fp.ephemeral, true, 'the server needs to know to count this one loosely')
    assert.equal(fp.components.instanceSource, 'unavailable')
    assert.match(fp.id, /^[0-9a-f]{32}$/, 'there is still an id — it is just not durable')
  })
})

test('a concurrent first start does not mint two identities', () => {
  // Cluster mode: four workers boot at once, each finds no instance-id and each
  // wants to create one. The `wx` flag means three of them lose the race and
  // read the winner's file — without it a customer reports four seats on their
  // very first boot.
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const stateDir = tempDir()
    const ids = new Set(
      Array.from({ length: 8 }, () => computeFingerprint({ product: 'acme', stateDir }).id)
    )
    assert.equal(ids.size, 1)
  })
})

test('the MAC address is hashed, never reported raw', () => {
  withoutEnv(['LICENSE_GUARD_INSTANCE_ID'], () => {
    const fp = computeFingerprint({ product: 'acme', stateDir: tempDir() })
    const macs = Object.values(os.networkInterfaces())
      .flat()
      .filter((i) => i && !i.internal)
      .map((i) => i.mac)
    for (const mac of macs) {
      assert.equal(JSON.stringify(fp.components).includes(mac), false)
    }
    if (fp.components.macHash) assert.match(fp.components.macHash, /^[0-9a-f]{16}$/)
  })
})

test('the default state directory is per-platform and per-product', () => {
  const dir = resolveStateDir('acme core!', undefined)
  assert.match(path.basename(dir), /^acme_core_$/, 'the product name is sanitised into a path segment')
  assert.ok(path.isAbsolute(dir))
})
