'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')

const { verify, decodeUnverified } = require('../src/token')
const { unpackCore } = require('../src/pack')

const CLI = path.join(__dirname, '..', 'bin', 'license-guard.js')
const tempDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'lg-cli-'))

/** The CLI is run as a process, because that is how anyone will ever run it. */
function run (args, { expectFailure = false } = {}) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' })
    if (expectFailure) assert.fail(`expected "${args.join(' ')}" to fail, but it succeeded`)
    return stdout
  } catch (err) {
    if (!expectFailure) {
      assert.fail(`"${args.join(' ')}" failed: ${err.stderr || err.message}`)
    }
    return String(err.stderr || '')
  }
}

test('keygen writes a pair that the rest of the toolchain accepts', () => {
  const out = path.join(tempDir(), 'keys.json')
  run(['keygen', '--json', '--out', out])
  const keys = JSON.parse(fs.readFileSync(out, 'utf8'))

  assert.match(keys.publicKey, /^lgpk1_[A-Za-z0-9_-]{43}$/)
  assert.match(keys.secretKey, /^lgsk1_[A-Za-z0-9_-]{43}$/)
  assert.ok(keys.workerSecret.length > 40)
  assert.equal(fs.statSync(out).mode & 0o077, 0, 'a file with a signing key in it is not world-readable')
})

test('keygen without --json prints the three forms and says what each is for', () => {
  const output = run(['keygen'])
  assert.match(output, /lgpk1_/)
  assert.match(output, /lgsk1_/)
  assert.match(output, /wrangler secret put SIGNING_KEY/)
  assert.match(output, /release-blocking incident/)
})

test('pack produces a core file that unpacks with the key it printed', () => {
  const dir = tempDir()
  const source = path.join(dir, 'core.js')
  const target = path.join(dir, 'core.lgc')
  const keyOut = path.join(dir, 'core.key')
  fs.writeFileSync(source, 'module.exports = () => "protected"\n')

  const output = run([
    'pack', '--in', source, '--out', target,
    '--product', 'acme-core', '--version', '3.2.1',
    '--watermark', 'batch-7', '--key-out', keyOut
  ])

  assert.match(output, /product\s+acme-core/)
  assert.match(output, /add it to \.npmignore/)

  const key = fs.readFileSync(keyOut, 'utf8').trim()
  const { source: recovered, meta } = unpackCore(fs.readFileSync(target), key)
  assert.match(recovered, /protected/)
  assert.equal(meta.version, '3.2.1')
  assert.equal(meta.watermark, 'batch-7')
})

test('pack with an explicit key reuses it, so one product key spans builds', () => {
  const dir = tempDir()
  fs.writeFileSync(path.join(dir, 'a.js'), 'module.exports = 1\n')
  fs.writeFileSync(path.join(dir, 'b.js'), 'module.exports = 2\n')
  const keyOut = path.join(dir, 'k')

  run(['pack', '--in', path.join(dir, 'a.js'), '--out', path.join(dir, 'a.lgc'),
    '--product', 'p', '--key-out', keyOut])
  const key = fs.readFileSync(keyOut, 'utf8').trim()

  run(['pack', '--in', path.join(dir, 'b.js'), '--out', path.join(dir, 'b.lgc'),
    '--product', 'p', '--key', key])

  assert.equal(unpackCore(fs.readFileSync(path.join(dir, 'b.lgc')), key).source.trim(), 'module.exports = 2')
})

test('issue signs a token bound to a fingerprint', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'k.json')])
  const keys = JSON.parse(fs.readFileSync(path.join(dir, 'k.json'), 'utf8'))

  const token = run([
    'issue', '--secret', keys.secretKey, '--product', 'acme-core', '--license', 'lic_9',
    '--customer', 'Acme Ltd', '--fingerprint', 'fp-xyz', '--days', '30',
    '--seats', '4', '--features', 'reports,sso', '--plan', 'enterprise'
  ]).trim()

  const result = verify(token, keys.publicKey, { product: 'acme-core', fingerprint: 'fp-xyz' })
  assert.equal(result.claims.cus, 'Acme Ltd')
  assert.equal(result.claims.seats, 4)
  assert.deepEqual(result.claims.fea, ['reports', 'sso'])
  assert.equal(result.claims.plan, 'enterprise')
})

test('issue refuses to mint a portable licence unless you ask for one by name', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'k.json')])
  const keys = JSON.parse(fs.readFileSync(path.join(dir, 'k.json'), 'utf8'))

  const stderr = run(
    ['issue', '--secret', keys.secretKey, '--product', 'p', '--license', 'l'],
    { expectFailure: true }
  )
  assert.match(stderr, /--any-machine/)
  assert.match(stderr, /wrong answer for everyone else/)
})

test('an offline bundle carries the token and the core key together', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'k.json')])
  const keys = JSON.parse(fs.readFileSync(path.join(dir, 'k.json'), 'utf8'))
  const out = path.join(dir, 'license.json')

  run([
    'issue', '--secret', keys.secretKey, '--product', 'p', '--license', 'l',
    '--any-machine', '--core-key', Buffer.alloc(32, 1).toString('base64'), '--out', out
  ])

  const bundle = JSON.parse(fs.readFileSync(out, 'utf8'))
  assert.equal(decodeUnverified(bundle.token).fp, null, 'portable on purpose')
  assert.equal(bundle.coreKey, Buffer.alloc(32, 1).toString('base64'))
  assert.equal(fs.statSync(out).mode & 0o077, 0)
})

test('inspect reads a core file, a token, and a bundle', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'k.json')])
  const keys = JSON.parse(fs.readFileSync(path.join(dir, 'k.json'), 'utf8'))

  fs.writeFileSync(path.join(dir, 'c.js'), 'module.exports = 1\n')
  run(['pack', '--in', path.join(dir, 'c.js'), '--out', path.join(dir, 'c.lgc'),
    '--product', 'acme-core', '--version', '9.9.9'])
  assert.match(run(['inspect', path.join(dir, 'c.lgc')]), /"version": "9\.9\.9"/)

  const token = run(['issue', '--secret', keys.secretKey, '--product', 'acme-core',
    '--license', 'l', '--any-machine']).trim()
  assert.match(run(['inspect', token]), /"prd": "acme-core"/)
  assert.match(run(['inspect', token]), /Not verified/)
  assert.match(run(['inspect', token, '--public-key', keys.publicKey]), /Signature valid/)
})

test('inspect reports a token signed by the wrong key as rejected, and exits non-zero', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'a.json')])
  run(['keygen', '--json', '--out', path.join(dir, 'b.json')])
  const a = JSON.parse(fs.readFileSync(path.join(dir, 'a.json'), 'utf8'))
  const b = JSON.parse(fs.readFileSync(path.join(dir, 'b.json'), 'utf8'))

  const token = run(['issue', '--secret', a.secretKey, '--product', 'p', '--license', 'l',
    '--any-machine']).trim()

  let exitCode = 0
  try {
    execFileSync(process.execPath, [CLI, 'inspect', token, '--public-key', b.publicKey],
      { encoding: 'utf8' })
  } catch (err) {
    exitCode = err.status
  }
  assert.equal(exitCode, 1)
})

test('fingerprint prints a stable id and explains the ephemeral case', () => {
  const stateDir = tempDir()
  const env = { ...process.env }
  delete env.LICENSE_GUARD_INSTANCE_ID

  const read = () => execFileSync(
    process.execPath,
    [CLI, 'fingerprint', '--product', 'acme-core', '--state-dir', stateDir, '--json'],
    { encoding: 'utf8', env }
  )

  const first = JSON.parse(read())
  assert.match(first.id, /^[0-9a-f]{32}$/)
  assert.equal(JSON.parse(read()).id, first.id, 'stable across invocations')

  const human = execFileSync(
    process.execPath,
    [CLI, 'fingerprint', '--product', 'acme-core', '--state-dir', stateDir],
    { encoding: 'utf8', env }
  )
  assert.match(human, /Give this id to your supplier/)
})

test('missing options and unknown commands fail with a message, not a stack', () => {
  assert.match(run(['pack'], { expectFailure: true }), /Missing required options: --in, --out, --product/)
  assert.match(run(['nonsense'], { expectFailure: true }), /Unknown command "nonsense"/)
  assert.match(run(['--help']), /self-hosted licensing/)
  assert.match(run(['pack', '--help']), /--watermark/)
})

test('derive rebuilds the public key and Worker secret from a piped secret', () => {
  const dir = tempDir()
  run(['keygen', '--json', '--out', path.join(dir, 'k.json')])
  const keys = JSON.parse(fs.readFileSync(path.join(dir, 'k.json'), 'utf8'))

  // Piped, not passed as an argument: anything in argv is visible to every
  // process on the machine via `ps`, and this is the one value that must not be.
  const piped = (args) => execFileSync(process.execPath, [CLI, ...args], {
    input: keys.secretKey + '\n',
    encoding: 'utf8'
  })

  assert.equal(piped(['derive', '--public-only']).trim(), keys.publicKey)
  assert.equal(piped(['derive', '--worker-only']).trim(), keys.workerSecret)

  const human = piped(['derive'])
  assert.match(human, /wrangler secret put SIGNING_KEY/)
  assert.equal(human.includes(keys.secretKey), false, 'never echoes the secret back')
})

test('derive with nothing piped in explains how to pipe it', () => {
  const stderr = run(['derive', '--secret', ''], { expectFailure: true })
  assert.match(stderr, /security find-generic-password/)
  assert.match(stderr, /appearing in `ps`/)
})
