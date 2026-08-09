#!/usr/bin/env node
'use strict'

/**
 * The operator's side of the licence server.
 *
 * `license-guard` is the offline tool: keys, packing, signing. Everything here
 * talks to a deployed Worker over HTTPS, which means everything here needs the
 * admin token — so the first job of this file is to make handling that token
 * boring. It is read from the environment or the macOS Keychain and passed in a
 * header. It never appears in `argv`, where `ps` would show it to every process
 * on the machine for as long as the command runs.
 */

const { execFileSync } = require('child_process')
const { parseArgs } = require('util')

const { publicKeyFor, workerSecretFor } = require('../src/keys')
const { verify, decodeUnverified } = require('../src/token')
const { computeFingerprint } = require('../src/fingerprint')

// Clear, then home. Written as escapes on purpose: a literal ESC byte in a
// source file survives until the first editor or copy-paste that strips control
// characters, and then the screen stops clearing for no visible reason.
const CLEAR_SCREEN = '\u001b[2J\u001b[H'

const USAGE = `
lg-admin — run the licence server you deployed

  deploy                       Install secrets from the Keychain and deploy.
  selftest                     Prove a deployment end to end, then tidy up.

  product --id <id>            Register a product and its core key.
  license --product <id>       Mint a licence. Prints the key once.
  revoke --license <id>        Kill a licence immediately.

  activate --product <id>      Activate this machine, and verify the token.
  release --product <id>       Give this machine's seat back.

  machines                     Every installed deployment, in detail.
  watch                        machines, refreshed.
  report                       Seats, networks, and who is sharing.

Where the server is, and who you are:

  --endpoint https://…         or LICENSE_GUARD_ENDPOINT
  admin token                  $ADMIN_TOKEN, else the macOS Keychain
                               (service license-guard.ADMIN_TOKEN), else a prompt

Add --json to any read command to get the raw response instead.
`.trim()

/* ------------------------------------------------------------------ *
 * Commands
 * ------------------------------------------------------------------ */

const COMMANDS = {
  deploy: {
    describe: 'Install secrets from the Keychain and deploy the Worker.',
    options: {
      config: { type: 'string', default: 'server/wrangler.toml' },
      secrets: { type: 'boolean', default: false },
      'public-key': { type: 'string' },
      endpoint: { type: 'string' }
    },
    async run (values) {
      const config = values.config

      if (values.secrets) {
        print(head('Installing secrets'))
        // The signing key is stored once, in its lgsk1_ form, and the form
        // WebCrypto needs is derived here. Two stored copies of one key is two
        // things to get out of step, and the day they disagree is the day every
        // client rejects every token.
        const secretKey = keychain('license-guard.SIGNING_KEY')
        if (!secretKey) {
          fail(
            'No signing key in the Keychain. Store it once:\n\n' +
            '  security add-generic-password -U -a "$USER" -s license-guard.SIGNING_KEY -w\n\n' +
            '(-w with no value prompts, so it stays out of your shell history.)'
          )
        }
        putSecret('SIGNING_KEY', workerSecretFor(secretKey), config)
        for (const name of ['ADMIN_TOKEN', 'IP_SALT']) {
          const value = keychain(`license-guard.${name}`)
          if (value) putSecret(name, value, config)
          else warn(`  ${name} is not in the Keychain — leaving whatever is deployed.`)
        }
        print(`\n  public key for this signing key:\n\n    ${publicKeyFor(secretKey)}\n`)
      }

      print(head('Deploying'))
      wrangler(['deploy', '--config', config], { stdio: 'inherit' })

      const endpoint = values.endpoint || process.env.LICENSE_GUARD_ENDPOINT
      if (!endpoint) {
        print('\nDeployed. Pass --endpoint to have this check health afterwards.')
        return
      }

      print(head('Checking health'))
      // A deploy is not finished when wrangler says it is. The failure that
      // matters — a signing key that will not import — only shows up when
      // something asks the Worker to sign, and health is the one endpoint that
      // does that without needing a licence.
      const health = await waitForHealth(endpoint)
      if (!health.ok) {
        fail(`The Worker is up but cannot sign:\n\n  ${health.detail || 'no detail given'}`)
      }
      print('  signing: ok')

      if (values['public-key']) {
        print(head('Checking the key pair'))
        print(pairingAdvice(values['public-key']))
      }
    }
  },

  product: {
    describe: 'Register a product and the core key its builds are packed with.',
    options: {
      id: { type: 'string' },
      name: { type: 'string' },
      'core-key': { type: 'string' },
      'min-version': { type: 'string' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      required(values, ['id'])

      // The key is deliberately not generated here. Doing so meant that
      // `product --id x --name "New name"` sent a brand new AES key and
      // silently replaced the one every shipped .lgc was packed with. The
      // server keeps the existing key when none is supplied; a fresh product
      // gets a fresh one.
      const data = await api('POST', '/v1/admin/products', values, {
        id: values.id,
        name: values.name || undefined,
        coreKey: values['core-key'] || undefined,
        minVersion: values['min-version'] || null
      })
      if (values.json) return print(JSON.stringify(data, null, 2))

      print(`
${data.created ? 'Registered' : 'Updated'} "${values.id}".

Core key${data.created ? ' (generated)' : data.rotated ? ' (REPLACED)' : ' (unchanged)'}:

  ${data.coreKey}

This is the AES key your .lgc files are packed with, and the server hands it to
every licensed deployment of this product. It is not a per-customer secret.
${data.created
  ? '\nPack your core with it:\n\n' +
    `  license-guard pack --in src/core.js --out dist/core.lgc --product ${values.id} \\\n` +
    `    --key '${data.coreKey}'`
  : data.rotated
    ? `\n${data.warning}`
    : '\nUnchanged, because you did not pass --core-key. That is deliberate: builds\n' +
      'already in customers\' hands were packed with this key and would stop\n' +
      'decrypting if it moved.'}

Next: mint a licence for a customer.

  lg-admin license --product ${values.id} --customer "Their Company" --seats 3
`.trim())
    }
  },

  license: {
    describe: 'Mint a licence for a customer.',
    options: {
      product: { type: 'string' },
      customer: { type: 'string' },
      email: { type: 'string' },
      seats: { type: 'string', default: '1' },
      plan: { type: 'string', default: 'standard' },
      features: { type: 'string', default: '' },
      'expires-in-days': { type: 'string' },
      notes: { type: 'string' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      required(values, ['product', 'customer'])
      const seats = Number(values.seats)
      if (!Number.isInteger(seats) || seats < 1) fail('--seats must be a whole number, 1 or more.')

      const features = values.features
        ? values.features.split(',').map((f) => f.trim()).filter(Boolean)
        : []
      const expiresAt = values['expires-in-days']
        ? Math.floor(Date.now() / 1000) + Math.round(Number(values['expires-in-days']) * 86400)
        : null

      const data = await api('POST', '/v1/admin/licenses', values, {
        product: values.product,
        customer: values.customer,
        email: values.email || null,
        seats,
        plan: values.plan,
        features,
        expiresAt,
        notes: values.notes || null
      })
      if (values.json) return print(JSON.stringify(data, null, 2))

      print(`
Licence for ${values.customer}

  key         ${data.licenseKey}
  id          ${data.id}
  product     ${values.product}
  seats       ${seats}
  plan        ${values.plan}
  features    ${features.length ? features.join(', ') : '(none)'}
  expires     ${expiresAt ? new Date(expiresAt * 1000).toISOString().slice(0, 10) : 'never'}

Send them the key. The server stored only its SHA-256, so this is the only time
it exists in readable form anywhere — there is no endpoint that can show it
again, and there cannot be one, because that is the same endpoint an attacker
with your admin token would use.

They set it as LICENSE_GUARD_KEY, or pass it to createGuard({ licenseKey }).
Each distinct deployment claims one of the ${seats} seat${seats === 1 ? '' : 's'} on first activation and
keeps it until it goes quiet or calls release.

Track it with:

  lg-admin machines --license ${data.id}
`.trim())
    }
  },

  revoke: {
    describe: 'Revoke a licence.',
    options: {
      license: { type: 'string' },
      status: { type: 'string', default: 'revoked' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      required(values, ['license'])
      const data = await api('POST', '/v1/admin/revoke', values, {
        id: values.license,
        status: values.status
      })
      if (values.json) return print(JSON.stringify(data, null, 2))
      print(`
${values.license} is now "${values.status}".

Every future activation and heartbeat is refused, fatally — the client stops
rather than degrading. Tokens already issued keep working until they expire,
which is TOKEN_TTL_DAYS at worst (7 by default). Shorten that variable, not
GRACE_DAYS, if you need revocation to bite faster than a week.
`.trim())
    }
  },

  activate: {
    describe: 'Activate this machine, and verify the token that comes back.',
    options: {
      product: { type: 'string' },
      'license-key': { type: 'string' },
      'public-key': { type: 'string' },
      version: { type: 'string', default: '0.0.0' },
      fingerprint: { type: 'string' },
      'state-dir': { type: 'string' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      required(values, ['product'])
      const licenseKey = values['license-key'] || process.env.LICENSE_GUARD_KEY
      if (!licenseKey) fail('Give --license-key, or set LICENSE_GUARD_KEY.')

      const fp = values.fingerprint
        ? { id: values.fingerprint, ephemeral: false, components: {} }
        : computeFingerprint({ product: values.product, stateDir: values['state-dir'] })

      const body = {
        product: values.product,
        version: values.version,
        licenseKey,
        fingerprint: fp.id,
        sdk: require('../package.json').version,
        telemetry: fp.components.hostname
          ? {
              hostname: fp.components.hostname,
              platform: fp.components.platform,
              arch: fp.components.arch,
              container: fp.components.container,
              macHash: fp.components.macHash,
              ephemeral: fp.ephemeral
            }
          : undefined
      }

      const data = await api('POST', '/v1/activate', values, body, { admin: false })
      if (values.json) return print(JSON.stringify({ fingerprint: fp.id, ...data }, null, 2))

      const claims = decodeUnverified(data.token)
      print(`
Activated.

  fingerprint   ${fp.id}${fp.ephemeral ? '  (ephemeral — no durable id could be written)' : ''}
  licence       ${claims.lic}
  customer      ${claims.cus}
  plan          ${claims.plan}
  features      ${claims.fea?.length ? claims.fea.join(', ') : '(none)'}
  seats         ${claims.seats}
  watermark     ${claims.wm}
  token expires ${new Date(claims.exp * 1000).toISOString()} (${relative(claims.exp)})
  grace         ${Math.round((claims.grc || 0) / 86400)} days past that
  check in      every ${Math.round((claims.hbt || 0) / 3600)} hours
  core key      ${data.coreKey ? 'returned' : 'not returned'}${data.notice ? `\n  notice        ${data.notice}` : ''}
`.trimEnd())

      print(verdict(data.token, values['public-key'], values.product, fp.id))
    }
  },

  release: {
    describe: "Give this machine's seat back.",
    options: {
      product: { type: 'string' },
      'license-key': { type: 'string' },
      fingerprint: { type: 'string' },
      'state-dir': { type: 'string' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      required(values, ['product'])
      const licenseKey = values['license-key'] || process.env.LICENSE_GUARD_KEY
      if (!licenseKey) fail('Give --license-key, or set LICENSE_GUARD_KEY.')
      const id = values.fingerprint ||
        computeFingerprint({ product: values.product, stateDir: values['state-dir'] }).id

      const data = await api('POST', '/v1/release', values, {
        product: values.product, licenseKey, fingerprint: id
      }, { admin: false })
      if (values.json) return print(JSON.stringify(data, null, 2))
      print(`Released ${id}. The seat is free immediately.`)
    }
  },

  machines: {
    describe: 'Every installed deployment, in detail.',
    options: {
      license: { type: 'string' },
      limit: { type: 'string', default: '200' },
      events: { type: 'boolean', default: false },
      'heartbeat-hours': { type: 'string', default: '6' },
      'stale-days': { type: 'string', default: '45' },
      'ephemeral-stale-hours': { type: 'string', default: '36' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      const query = values.license
        ? `?license=${encodeURIComponent(values.license)}&limit=${values.limit}`
        : `?limit=${values.limit}`
      const [fleet, summary] = await Promise.all([
        api('GET', `/v1/admin/deployments${query}`, values),
        api('GET', '/v1/admin/report?days=3650', values)
      ])
      if (values.json) return print(JSON.stringify(fleet, null, 2))
      print(renderMachines(fleet, summary, values))
    }
  },

  watch: {
    describe: 'machines, refreshed on an interval.',
    options: {
      license: { type: 'string' },
      interval: { type: 'string', default: '30' },
      limit: { type: 'string', default: '200' },
      'heartbeat-hours': { type: 'string', default: '6' },
      'stale-days': { type: 'string', default: '45' },
      'ephemeral-stale-hours': { type: 'string', default: '36' },
      endpoint: { type: 'string' }
    },
    async run (values) {
      const seconds = Math.max(5, Number(values.interval) || 30)
      const query = values.license
        ? `?license=${encodeURIComponent(values.license)}&limit=${values.limit}`
        : `?limit=${values.limit}`

      for (;;) {
        const [fleet, summary] = await Promise.all([
          api('GET', `/v1/admin/deployments${query}`, values),
          api('GET', '/v1/admin/report?days=3650', values)
        ])
        // Clear and home, then redraw. Scrollback stays intact if the terminal
        // keeps it, and a watch that appends instead would bury the top of the
        // fleet within a minute.
        process.stdout.write(CLEAR_SCREEN)
        print(renderMachines(fleet, summary, values))
        print(`\nRefreshing every ${seconds}s. Ctrl-C to stop.`)
        await sleep(seconds * 1000)
      }
    }
  },

  report: {
    describe: 'Seats, networks, and who is sharing.',
    options: {
      days: { type: 'string', default: '30' },
      endpoint: { type: 'string' },
      json: { type: 'boolean', default: false }
    },
    async run (values) {
      const data = await api('GET', `/v1/admin/report?days=${values.days}`, values)
      if (values.json) return print(JSON.stringify(data, null, 2))

      const rows = data.licenses || []
      if (!rows.length) return print('No licences yet.')

      print(head(`Sharing report — last ${data.windowDays} days`))
      print('')
      print(table(
        ['customer', 'licence', 'seats', 'live', 'networks', 'countries', ''],
        rows.map((r) => [
          truncate(r.customer, 24),
          r.id,
          String(r.seats),
          `${r.instances}`,
          String(r.networks),
          String(r.countries),
          r.overSeats ? 'OVER SEATS' : r.sharingSuspected ? 'sharing?' : ''
        ])
      ))

      const flagged = rows.filter((r) => r.sharingSuspected || r.overSeats)
      print('')
      print(flagged.length
        ? `
${flagged.length} licence${flagged.length === 1 ? '' : 's'} flagged.

Sort on networks, not on instances. Two deployments inside one datacentre is a
customer who grew. Three instances on three networks in three countries, sold
to one company, is a key doing the rounds — and it is the only sharing this can
see. Someone who strips the guard and runs one quiet copy is invisible here and
always will be.

  lg-admin machines --license <id> --events
`.trim()
        : 'Nothing flagged. Every licence is inside its seat count and on as few networks as you would expect.')
    }
  },

  selftest: {
    describe: 'Prove a deployment end to end against a throwaway licence.',
    options: {
      'public-key': { type: 'string' },
      endpoint: { type: 'string' },
      cleanup: { type: 'boolean', default: false },
      config: { type: 'string', default: 'server/wrangler.toml' },
      database: { type: 'string', default: 'license-guard' }
    },
    async run (values) {
      required(values, ['public-key'])
      const suffix = require('crypto').randomBytes(3).toString('hex')
      const product = `_selftest_${suffix}`
      const results = []
      const check = (name, ok, detail) => {
        results.push({ name, ok, detail })
        // Detail only on failure. A passing line that also explains itself
        // makes a green run look like it has something to say, and the eye
        // stops reading a list where every row is annotated.
        print(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `  — ${detail}`}`)
      }

      print(head('Self-test'))
      print(`  product ${product}, removed at the end with --cleanup\n`)

      const health = await api('GET', '/v1/health', values, null, { admin: false })
      check('health reports the signing key is usable', health.ok === true, health.detail)
      if (!health.ok) fail('Stopping: nothing else can pass while the key will not import.')

      await api('POST', '/v1/admin/products', values, {
        id: product, name: 'Self test', coreKey: require('../src/aes').randomKey().toString('base64')
      })
      const licence = await api('POST', '/v1/admin/licenses', values, {
        product, customer: `Self test ${suffix}`, seats: 1, features: ['selftest']
      })
      check('a licence can be minted', Boolean(licence.licenseKey))

      const body = (fingerprint) => ({
        product, version: '0.0.0', licenseKey: licence.licenseKey, fingerprint
      })

      const first = await api('POST', '/v1/activate', values, body('selftest-a'), { admin: false })
      let verified = null
      try {
        verified = verify(first.token, values['public-key'], { product, fingerprint: 'selftest-a' })
      } catch (err) {
        verified = { error: err.message }
      }
      // The one check nothing else covers: that the key the Worker signs with
      // and the key compiled into your shipped clients are actually a pair.
      // Health proves the key imports; only this proves it is the right key.
      check('the token verifies against the public key you ship', !verified.error, verified.error)
      check('the core key comes back', Boolean(first.coreKey))

      const beat = await api('POST', '/v1/heartbeat', values, body('selftest-a'), { admin: false })
      check('a known deployment renews', Boolean(beat.token))

      const unseen = await api('POST', '/v1/heartbeat', values, body('selftest-a2'), {
        admin: false, allowError: true
      })
      check(
        'a heartbeat from an unseen deployment is refused for seats, not for a mangled body',
        unseen.error === 'seat_limit',
        unseen.error === 'invalid_request'
          ? 'invalid_request means the deployed Worker predates the body-reuse fix — redeploy'
          : unseen.error
      )

      const second = await api('POST', '/v1/activate', values, body('selftest-b'), {
        admin: false, allowError: true
      })
      check('the seat limit holds', second.error === 'seat_limit', second.error)

      await api('POST', '/v1/release', values, body('selftest-a'), { admin: false })
      const reclaimed = await api('POST', '/v1/activate', values, body('selftest-b'), {
        admin: false, allowError: true
      })
      check('a released seat can be claimed by someone else', Boolean(reclaimed.token), reclaimed.error)

      await api('POST', '/v1/admin/revoke', values, { id: licence.id, status: 'revoked' })
      const revoked = await api('POST', '/v1/heartbeat', values, body('selftest-b'), {
        admin: false, allowError: true
      })
      check('revocation bites at once', revoked.error === 'revoked', revoked.error)

      const failed = results.filter((r) => !r.ok)
      print('')
      if (values.cleanup) {
        print(head('Cleaning up'))
        // Scoped to this run's product id, and run through wrangler so it uses
        // the credentials you already have rather than needing new ones.
        const sql = [
          `DELETE FROM events WHERE product_id = '${product}'`,
          `DELETE FROM instances WHERE license_id = '${licence.id}'`,
          `DELETE FROM licenses WHERE id = '${licence.id}'`,
          `DELETE FROM products WHERE id = '${product}'`
        ].join('; ')
        wrangler(['d1', 'execute', values.database, '--remote', '--yes', '--command', sql,
          '--config', values.config], { stdio: 'inherit' })
      } else {
        print(`Left behind: product ${product}, licence ${licence.id} (revoked). Re-run with
--cleanup to delete them, or remove them yourself:

  npx wrangler@4 d1 execute ${values.database} --remote --config ${values.config} \\
    --command "DELETE FROM events WHERE product_id = '${product}'; \\
      DELETE FROM instances WHERE license_id = '${licence.id}'; \\
      DELETE FROM licenses WHERE id = '${licence.id}'; \\
      DELETE FROM products WHERE id = '${product}'"`)
      }

      print('')
      if (failed.length) {
        process.exitCode = 1
        fail(`${failed.length} of ${results.length} checks failed:\n  ` +
          failed.map((f) => f.name).join('\n  '))
      }
      print(`All ${results.length} checks passed. This deployment issues tokens your shipped
clients will accept, counts seats correctly, and revokes on demand.`)
    }
  }
}

/* ------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------ */

/**
 * The fleet, one block per licence.
 *
 * The columns worth space are the ones that answer a question you actually
 * have: is this deployment alive, where is it, and is it the only one. Raw
 * epoch seconds answer none of those, so every time is rendered twice — as a
 * date you can quote in an email, and as an age you can judge at a glance.
 */
function renderMachines (fleet, summary, values) {
  const instances = fleet.instances || []
  const events = fleet.events || []
  if (!instances.length) {
    return 'No deployments yet. Nothing has activated against this server.'
  }

  const now = Math.floor(Date.now() / 1000)
  const heartbeat = Number(values['heartbeat-hours']) * 3600
  const staleAfter = (row) => row.ephemeral
    ? Number(values['ephemeral-stale-hours']) * 3600
    : Number(values['stale-days']) * 86400

  const byLicence = new Map()
  for (const row of instances) {
    if (!byLicence.has(row.license_id)) byLicence.set(row.license_id, [])
    byLicence.get(row.license_id).push(row)
  }
  const meta = new Map((summary.licenses || []).map((l) => [l.id, l]))

  const out = [head(`Installed deployments — ${instances.length} across ${byLicence.size} licence${byLicence.size === 1 ? '' : 's'}`)]

  for (const [licenseId, rows] of byLicence) {
    const info = meta.get(licenseId)
    rows.sort((a, b) => b.last_seen - a.last_seen)

    const live = rows.filter((r) => !r.released_at && now - r.last_seen <= staleAfter(r))
    const seats = info?.seats ?? '?'
    const overSeats = typeof seats === 'number' && live.length > seats

    out.push('')
    out.push(`${info?.customer || '(unknown customer)'}   ${licenseId}`)
    out.push(`  ${live.length} of ${seats} seat${seats === 1 ? '' : 's'} in use` +
      (overSeats ? '   OVER SEATS' : '') +
      (info?.sharingSuspected ? '   sharing suspected' : ''))

    for (const row of rows) {
      const age = now - row.last_seen
      const state = row.released_at
        ? 'released'
        : age > staleAfter(row)
          ? 'stale — seat freed'
          : age > heartbeat * 2
            ? 'quiet — missed a check-in'
            : 'healthy'
      const mark = state === 'healthy' ? '*' : state === 'released' ? '-' : '!'

      out.push('')
      out.push(`  ${mark} ${row.fingerprint}`)
      out.push(`      host        ${row.hostname || '(not reported)'}` +
        `${row.platform ? `   ${row.platform}/${row.arch}` : ''}` +
        `${row.container ? `   in ${row.container}` : ''}`)
      out.push(`      running     ${row.app_version || '(unknown)'}` +
        `${row.node_version ? `   on node ${row.node_version}` : ''}` +
        `${row.ephemeral ? '   ephemeral id' : ''}`)
      out.push(`      first seen  ${stamp(row.first_seen)}   ${relative(row.first_seen)}`)
      out.push(`      last seen   ${stamp(row.last_seen)}   ${relative(row.last_seen)}   ${state}`)
      out.push(`      activations ${row.activations}`)
      out.push(`      network     ${network(row)}`)
      if (row.released_at) out.push(`      released    ${stamp(row.released_at)}`)

      if (values.events) {
        const mine = events.filter((e) => e.fingerprint === row.fingerprint).slice(0, 6)
        if (mine.length) {
          out.push('      recent')
          for (const e of mine) {
            out.push(`        ${stamp(e.at)}  ${e.kind} ${e.outcome}` +
              `${e.detail ? `  ${e.detail}` : ''}`)
          }
        }
      }
    }
  }

  // A refusal leaves no instance row, by design — nothing was admitted. So the
  // fleet listing above cannot show it, and the most interesting thing a
  // customer does (trying to run a fourth copy on three seats) would be
  // invisible in the one view you actually open.
  const seen = new Set(instances.map((row) => row.fingerprint))
  const refused = events.filter((e) => e.outcome === 'denied' && !seen.has(e.fingerprint))
  if (refused.length) {
    out.push('')
    out.push(head(`Refused — ${refused.length} in the window`))
    out.push('')
    out.push(table(
      ['when', 'kind', 'reason', 'fingerprint', 'from'],
      refused.slice(0, 15).map((e) => [
        stamp(e.at),
        e.kind,
        e.detail || '',
        e.fingerprint || '(none sent)',
        [e.asn && `AS${e.asn}`, e.country].filter(Boolean).join(' ') || ''
      ])
    ))
    out.push('')
    out.push('  seat_limit here is a customer wanting more seats. unknown_license from an')
    out.push('  address you recognise is usually a typo; from one you do not, it is someone')
    out.push('  guessing. invalid_request is almost always your own integration.')
  }

  const errors = events.filter((e) => e.outcome === 'error')
  if (errors.length) {
    out.push('')
    out.push(head('Server-side failures'))
    for (const e of errors.slice(0, 10)) {
      out.push(`  ${stamp(e.at)}  ${e.kind}  ${e.detail}`)
    }
    out.push('')
    out.push('These are the server failing, not a customer being refused. A signing_failed')
    out.push('here means SIGNING_KEY is wrong and no deployment can activate.')
  }

  out.push('')
  out.push('  * healthy   ! needs a look   - released')
  out.push('')
  out.push(`Quiet after ${values['heartbeat-hours'] * 2}h without a check-in; the seat is freed after ` +
    `${values['stale-days']} days\n(${values['ephemeral-stale-hours']}h for an ephemeral id). ` +
    'Those thresholds come from the Worker\'s\nvars — pass the flags if you changed them there.')

  return out.join('\n')
}

function network (row) {
  const parts = []
  if (row.asn) parts.push(`AS${row.asn}${row.as_org ? ` ${row.as_org}` : ''}`)
  if (row.country) parts.push(row.country)
  if (row.colo) parts.push(`via ${row.colo}`)
  if (row.ip_hash) parts.push(`ip ${String(row.ip_hash).slice(0, 8)}`)
  return parts.length ? parts.join('  ') : '(not recorded)'
}

function stamp (seconds) {
  if (!seconds) return '(never)'
  return new Date(seconds * 1000).toISOString().replace('T', ' ').slice(0, 16) + 'Z'
}

function relative (seconds) {
  const delta = Math.floor(Date.now() / 1000) - seconds
  const future = delta < 0
  const n = Math.abs(delta)
  const scale = [
    [90, 1, 'second'],
    [5400, 60, 'minute'],
    [172800, 3600, 'hour'],
    [Infinity, 86400, 'day']
  ].find(([limit]) => n < limit)
  const [, divisor, unit] = scale
  const value = Math.round(n / divisor)
  const text = `${value} ${unit}${value === 1 ? '' : 's'}`
  return future ? `in ${text}` : `${text} ago`
}

function table (headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] ?? '').length)))
  const line = (cells) => '  ' + cells
    .map((cell, i) => String(cell ?? '').padEnd(widths[i])).join('  ').trimEnd()
  return [line(headers), line(widths.map((w) => '-'.repeat(w))), ...rows.map(line)].join('\n')
}

function truncate (value, max) {
  const text = String(value ?? '')
  return text.length > max ? text.slice(0, max - 1) + '…' : text
}

function head (text) {
  return `\n${text}\n${'-'.repeat(text.length)}`
}

function verdict (token, publicKey, product, fingerprint) {
  if (!publicKey) {
    return `
Not verified. Pass --public-key lgpk1_… — the same key compiled into the build
you ship — and this will check the signature. Until you have done that once
against a real deployment, you have not proved the server signs with the key
your customers trust; you have only proved it signs with something.`.trimEnd()
  }
  try {
    const result = verify(token, publicKey, { product, fingerprint })
    return `\nSignature valid, and bound to this product and this machine. State: ${result.state}.`
  } catch (err) {
    process.exitCode = 1
    return `\nREJECTED: ${err.code} — ${err.message}\n\n${pairingAdvice(publicKey)}`
  }
}

function pairingAdvice (publicKey) {
  return `
Check the pair. Derive the public key from the secret you deployed:

  security find-generic-password -a "$USER" -s license-guard.SIGNING_KEY -w \\
    | license-guard derive --public-only

If that does not print ${truncate(publicKey, 20)}, the Worker is signing with a
different key than the one your clients trust, and every deployment will reject
every token. Fix it with lg-admin deploy --secrets.`.trimEnd()
}

/* ------------------------------------------------------------------ *
 * Plumbing
 * ------------------------------------------------------------------ */

async function api (method, pathname, values, body, { admin = true, allowError = false } = {}) {
  const endpoint = (values.endpoint || process.env.LICENSE_GUARD_ENDPOINT || '').replace(/\/$/, '')
  if (!endpoint) {
    fail('No licence server. Pass --endpoint https://… or set LICENSE_GUARD_ENDPOINT.')
  }

  const headers = { 'content-type': 'application/json' }
  if (admin) headers.authorization = `Bearer ${adminToken()}`

  let response
  try {
    response = await fetch(endpoint + pathname, {
      method,
      headers,
      body: body === null || body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000)
    })
  } catch (err) {
    fail(`Could not reach ${endpoint}: ${err.message}`)
  }

  const text = await response.text()
  let data
  try {
    data = JSON.parse(text)
  } catch {
    fail(`${method} ${pathname} returned ${response.status} and something that is not JSON:\n\n${truncate(text, 400)}`)
  }

  if (!response.ok && !allowError) {
    if (response.status === 401) {
      fail('The admin token was refused. It is read from $ADMIN_TOKEN, then the Keychain\n' +
        '(service license-guard.ADMIN_TOKEN). Rotate it with:\n\n' +
        '  npx wrangler@4 secret put ADMIN_TOKEN --config server/wrangler.toml')
    }
    fail(`${method} ${pathname} — ${response.status} ${data.error || ''}\n\n  ${data.message || text}`)
  }
  return data
}

/**
 * The admin token, from the least dangerous place that has it.
 *
 * Never from `argv`: a command line is readable by every process on the machine
 * through `ps` for as long as it runs, and it lands in shell history besides.
 */
let cachedToken = null
function adminToken () {
  if (cachedToken) return cachedToken
  cachedToken = process.env.ADMIN_TOKEN || keychain('license-guard.ADMIN_TOKEN')
  if (!cachedToken) {
    fail(
      'No admin token.\n\n' +
      '  export ADMIN_TOKEN=$(security find-generic-password -a "$USER" \\\n' +
      '    -s license-guard.ADMIN_TOKEN -w)\n\n' +
      'or store it in the Keychain once and this will find it by itself:\n\n' +
      '  security add-generic-password -U -a "$USER" -s license-guard.ADMIN_TOKEN -w'
    )
  }
  return cachedToken
}

/** A secret out of the macOS Keychain, or '' anywhere else. */
function keychain (service) {
  if (process.platform !== 'darwin') return ''
  try {
    return execFileSync(
      'security',
      ['find-generic-password', '-a', process.env.USER || '', '-s', service, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim()
  } catch {
    return ''
  }
}

/** `wrangler secret put`, with the value on stdin so it never reaches `ps`. */
function putSecret (name, value, config) {
  print(`  ${name}`)
  wrangler(['secret', 'put', name, '--config', config], {
    input: value,
    stdio: ['pipe', 'ignore', 'inherit']
  })
}

function wrangler (args, options) {
  try {
    return execFileSync('npx', ['--yes', 'wrangler@4', ...args], options)
  } catch (err) {
    fail(`wrangler ${args[0]} failed: ${err.message}`)
  }
}

async function waitForHealth (endpoint, attempts = 10) {
  let last = {}
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(`${endpoint.replace(/\/$/, '')}/v1/health`, {
        signal: AbortSignal.timeout(10000)
      })
      last = await response.json()
      // A 503 is a settled answer, not a cold start: the key is wrong and
      // waiting will not change it.
      if (last.ok || response.status === 503) return last
    } catch {
      // A new deployment can refuse connections for a second or two.
    }
    await sleep(1500)
  }
  return last
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function required (values, names) {
  const missing = names.filter((name) => !values[name])
  if (missing.length) {
    fail(`Missing required option${missing.length > 1 ? 's' : ''}: --${missing.join(', --')}`)
  }
}

function print (text) {
  process.stdout.write(text + '\n')
}

function warn (text) {
  process.stderr.write(text + '\n')
}

function fail (message) {
  process.stderr.write(`lg-admin: ${message}\n`)
  process.exit(1)
}

function main (argv) {
  const [name, ...rest] = argv
  if (!name || name === '--help' || name === '-h' || name === 'help') return print(USAGE)
  if (name === '--version' || name === '-v') return print(require('../package.json').version)

  const command = COMMANDS[name]
  if (!command) fail(`Unknown command "${name}".\n\n${USAGE}`)

  if (rest.includes('--help') || rest.includes('-h')) {
    return print(`lg-admin ${name} — ${command.describe}\n\nOptions:\n` +
      Object.keys(command.options).map((option) => `  --${option}`).join('\n'))
  }

  let parsed
  try {
    parsed = parseArgs({ args: rest, options: command.options, allowPositionals: true })
  } catch (err) {
    fail(err.message)
  }

  Promise.resolve()
    .then(() => command.run(parsed.values, parsed.positionals))
    .catch((err) => fail(err?.message || String(err)))
}

if (require.main === module) main(process.argv.slice(2))

module.exports = { main, COMMANDS, renderMachines, relative, table }
