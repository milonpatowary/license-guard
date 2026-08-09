#!/usr/bin/env node
'use strict'

const fs = require('fs')
const path = require('path')
const { parseArgs } = require('util')

const { generateKeyPair, publicKeyFor, workerSecretFor } = require('../src/keys')
const { packCore, readCoreMeta } = require('../src/pack')
const { sign, decodeUnverified, verify } = require('../src/token')
const { computeFingerprint } = require('../src/fingerprint')
const { randomKey } = require('../src/aes')

const USAGE = `
license-guard — self-hosted licensing for private Node.js code

  keygen                       Create the Ed25519 signing keypair. Once, ever.
  derive                       Re-derive the public key and Worker secret.
  pack                         Encrypt a module into a .lgc core file.
  issue                        Sign a licence token offline.
  inspect <file|token>         Show what a .lgc file or a token contains.
  fingerprint --product <id>   Print this machine's deployment id.

Run "license-guard <command> --help" for the options of each.

Everything here is offline. The Worker in server/ is the only part that needs to
be deployed, and it is the only part that ever sees a customer.
`.trim()

const COMMANDS = {
  keygen: {
    describe: 'Create a signing keypair.',
    options: {
      out: { type: 'string', short: 'o' },
      json: { type: 'boolean', default: false }
    },
    run (values) {
      const keys = generateKeyPair()
      if (values.json) {
        write(values.out, JSON.stringify(keys, null, 2))
        return
      }
      print(`
Public key — embed this in the code you ship. Safe to commit.

  ${keys.publicKey}

Secret key — signs licence tokens. Keep it on one machine, in a password
manager, and nowhere near a repository.

  ${keys.secretKey}

Worker secret — the same secret key in the format Cloudflare's WebCrypto reads.
Install it with:

  wrangler secret put SIGNING_KEY

  ${keys.workerSecret}

If the secret key ever leaks, anyone can mint licences for every version you
have already shipped. Rotating it means a new public key, which means a new
release — so treat the leak as a release-blocking incident, not a chore.
`.trim())
      if (values.out) write(values.out, JSON.stringify(keys, null, 2))
    }
  },

  pack: {
    describe: 'Encrypt a module into a .lgc core file.',
    options: {
      in: { type: 'string', short: 'i' },
      out: { type: 'string', short: 'o' },
      product: { type: 'string' },
      version: { type: 'string', default: '0.0.0' },
      key: { type: 'string' },
      watermark: { type: 'string' },
      'key-out': { type: 'string' }
    },
    run (values) {
      required(values, ['in', 'out', 'product'])
      const source = fs.readFileSync(values.in, 'utf8')
      const key = values.key ? Buffer.from(values.key, 'base64') : randomKey()

      const { file, meta, key: keyB64 } = packCore({
        source,
        key,
        meta: {
          product: values.product,
          version: values.version,
          watermark: values.watermark || null
        }
      })

      fs.writeFileSync(values.out, file)
      if (values['key-out']) write(values['key-out'], keyB64)

      print(`
Packed ${values.in} → ${values.out}

  product   ${meta.product}
  version   ${meta.version}
  build     ${meta.buildId}
  size      ${meta.bytes} bytes plaintext, ${file.length} bytes packed

Core key (base64) — this is what the licence server hands out on activation.
Store it against the product row in D1; it is not a per-customer secret.

  ${keyB64}

Ship the .lgc file inside your private package. Do not ship the plaintext, and
add it to .npmignore — the single most common way this scheme fails is the
original .js sitting next to the .lgc in the published tarball.
`.trim())
    }
  },

  issue: {
    describe: 'Sign a licence token offline.',
    options: {
      secret: { type: 'string' },
      product: { type: 'string' },
      license: { type: 'string' },
      customer: { type: 'string', default: '' },
      fingerprint: { type: 'string' },
      'any-machine': { type: 'boolean', default: false },
      days: { type: 'string', default: '30' },
      'grace-days': { type: 'string', default: '7' },
      'heartbeat-hours': { type: 'string', default: '6' },
      seats: { type: 'string', default: '1' },
      plan: { type: 'string', default: 'standard' },
      features: { type: 'string', default: '' },
      watermark: { type: 'string' },
      issuer: { type: 'string', default: 'license-guard' },
      'core-key': { type: 'string' },
      out: { type: 'string', short: 'o' }
    },
    run (values) {
      required(values, ['secret', 'product', 'license'])
      if (!values.fingerprint && !values['any-machine']) {
        fail(
          'Give --fingerprint <id> to bind this licence to one deployment, or --any-machine to ' +
          'issue a portable one.\n\n' +
          'A portable licence is a file that works on every machine it is copied to. That is the ' +
          'right answer for an air-gapped customer and the wrong answer for everyone else, which ' +
          'is why it will not happen by accident.'
        )
      }

      const nowSeconds = Math.floor(Date.now() / 1000)
      const claims = {
        jti: require('crypto').randomUUID(),
        iss: values.issuer,
        prd: values.product,
        lic: values.license,
        cus: values.customer || values.license,
        fp: values['any-machine'] ? null : values.fingerprint,
        wm: values.watermark || require('crypto').randomBytes(4).toString('hex'),
        plan: values.plan,
        fea: values.features ? values.features.split(',').map((f) => f.trim()).filter(Boolean) : [],
        seats: Number(values.seats),
        iat: nowSeconds,
        exp: nowSeconds + Math.round(Number(values.days) * 86400),
        grc: Math.round(Number(values['grace-days']) * 86400),
        hbt: Math.round(Number(values['heartbeat-hours']) * 3600)
      }

      const token = sign(claims, values.secret)
      const bundle = { token, coreKey: values['core-key'] || null, claims }

      if (values.out) {
        write(values.out, JSON.stringify(bundle, null, 2))
        print(`Wrote ${values.out}`)
      } else {
        print(token)
      }

      if (values['any-machine']) {
        // stderr, so `license-guard issue … > token.txt` writes a token and
        // not a token plus a paragraph.
        warn(`
This licence is not bound to a machine and will work anywhere it is copied.
It expires ${new Date(claims.exp * 1000).toISOString()} — keep that short.
`.trim())
      }
    }
  },

  inspect: {
    describe: 'Show what a .lgc file or a token contains.',
    options: {
      'public-key': { type: 'string' }
    },
    run (values, positionals) {
      const target = positionals[0]
      if (!target) fail('inspect needs a file path or a token.')

      if (target.startsWith('lgt1.')) return inspectToken(target, values['public-key'])
      if (!fs.existsSync(target)) fail(`No such file: ${target}`)

      const bytes = fs.readFileSync(target)
      if (bytes.subarray(0, 4).toString('ascii') === 'LGC1') {
        print(JSON.stringify(readCoreMeta(bytes), null, 2))
        return
      }
      // A licence bundle written by `issue --out`.
      try {
        const bundle = JSON.parse(bytes.toString('utf8'))
        if (bundle.token) return inspectToken(bundle.token, values['public-key'])
      } catch { /* fall through */ }
      fail(`${target} is neither a .lgc core file nor a licence bundle.`)
    }
  },

  fingerprint: {
    describe: "Print this machine's deployment id.",
    options: {
      product: { type: 'string' },
      'state-dir': { type: 'string' },
      'include-host': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false }
    },
    run (values) {
      required(values, ['product'])
      const fp = computeFingerprint({
        product: values.product,
        stateDir: values['state-dir'],
        includeHost: values['include-host']
      })
      if (values.json) return print(JSON.stringify(fp, null, 2))
      print(`
  id          ${fp.id}
  state dir   ${fp.stateDir}
  ephemeral   ${fp.ephemeral}${fp.ephemeralReason ? ` (${fp.ephemeralReason})` : ''}
  hostname    ${fp.components.hostname}
  platform    ${fp.components.platform}/${fp.components.arch}
  container   ${fp.components.container || 'none detected'}
  id source   ${fp.components.instanceSource}

${fp.ephemeral
  ? 'This id is derived from observable machine details because no instance id could be\n' +
    'written to disk. It will change if the hostname or network interface changes. On\n' +
    'immutable infrastructure, set LICENSE_GUARD_INSTANCE_ID to something stable per\n' +
    'deployment instead.'
  : 'Give this id to your supplier to have a licence bound to this deployment.'}
`.trim())
    }
  },

  derive: {
    describe: 'Re-derive the public key and Worker secret from a stored secret key.',
    options: {
      secret: { type: 'string' },
      'public-only': { type: 'boolean', default: false },
      'worker-only': { type: 'boolean', default: false }
    },
    run (values) {
      // Read from stdin by default. A secret passed as --secret is visible in
      // `ps` to every process on the machine for as long as this runs, and
      // lands in shell history besides. Piping it in avoids both, and makes
      // this compose with whatever holds the key:
      //
      //   security find-generic-password -s license-guard.SIGNING_KEY -w \
      //     | license-guard derive --worker-only \
      //     | wrangler secret put SIGNING_KEY
      const secret = values.secret || readStdin()
      if (!secret) {
        fail(
          'No secret key. Pipe it in:\n\n' +
          '  security find-generic-password -a "$USER" -s license-guard.SIGNING_KEY -w | ' +
          'license-guard derive\n\n' +
          'Or pass --secret lgsk1_… if you do not mind it appearing in `ps` and in your ' +
          'shell history.'
        )
      }

      const publicKey = publicKeyFor(secret)
      const workerSecret = workerSecretFor(secret)

      // Bare output when a single value was asked for, so it pipes cleanly.
      if (values['public-only']) return print(publicKey)
      if (values['worker-only']) return print(workerSecret)

      print(`
Public key — embed this in the code you ship. Safe to commit.

  ${publicKey}

Worker secret — the same key in the format Cloudflare's WebCrypto reads:

  wrangler secret put SIGNING_KEY

  ${workerSecret}

Both are derived from the secret key you supplied, so there is only ever one
value to keep safe. If either of these does not match what you deployed, you
have supplied a different secret key than the one in use.
`.trim())
    }
  }
}

/** Whatever was piped in, trimmed. Empty string when stdin is a terminal. */
function readStdin () {
  try {
    if (process.stdin.isTTY) return ''
    return fs.readFileSync(0, 'utf8').trim()
  } catch {
    return ''
  }
}

function inspectToken (token, publicKey) {
  const claims = decodeUnverified(token)
  print(JSON.stringify(claims, null, 2))
  if (!publicKey) {
    print('\nNot verified — pass --public-key lgpk1_… to check the signature.')
    return
  }
  try {
    const result = verify(token, publicKey, { clockSkewSeconds: 0 })
    print(`\nSignature valid. State: ${result.state}. Expires ${new Date(result.expiresAt).toISOString()}.`)
  } catch (err) {
    print(`\nRejected: ${err.code} — ${err.message}`)
    process.exitCode = 1
  }
}

function required (values, names) {
  const missing = names.filter((name) => !values[name])
  if (missing.length) fail(`Missing required option${missing.length > 1 ? 's' : ''}: --${missing.join(', --')}`)
}

function write (file, contents) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true })
  // Secrets go to disk readable only by the person who ran the command.
  fs.writeFileSync(file, contents.endsWith('\n') ? contents : contents + '\n', { mode: 0o600 })
}

function print (text) {
  process.stdout.write(text + '\n')
}

function warn (text) {
  process.stderr.write(text + '\n')
}

function fail (message) {
  process.stderr.write(`license-guard: ${message}\n`)
  process.exit(1)
}

function main (argv) {
  const [name, ...rest] = argv
  if (!name || name === '--help' || name === '-h' || name === 'help') return print(USAGE)
  if (name === '--version' || name === '-v') return print(require('../package.json').version)

  const command = COMMANDS[name]
  if (!command) fail(`Unknown command "${name}".\n\n${USAGE}`)

  if (rest.includes('--help') || rest.includes('-h')) {
    return print(`license-guard ${name} — ${command.describe}\n\nOptions:\n` +
      Object.keys(command.options).map((option) => `  --${option}`).join('\n'))
  }

  let parsed
  try {
    parsed = parseArgs({ args: rest, options: command.options, allowPositionals: true })
  } catch (err) {
    fail(err.message)
  }

  try {
    command.run(parsed.values, parsed.positionals)
  } catch (err) {
    fail(err.message)
  }
}

if (require.main === module) main(process.argv.slice(2))

module.exports = { main, COMMANDS }
