# license-guard

Self-hosted licensing and deployment tracing for private Node.js code.

Your core logic ships **encrypted**. The key comes from **your** licence server
in exchange for a licence key you issued to a named customer. Every activation
and check-in is logged, so you can see where your product is running, on how
many machines, and — the useful part — when one key starts turning up on
networks belonging to different companies.

No SaaS. No per-install fee. The server is one Cloudflare Worker and one D1
database, which is free at any scale you are likely to reach.

```
your build                    your Worker                    your customer
─────────────────────────────────────────────────────────────────────────────
core.js                                                      npm i @you/product
   │                                                                │
   │ license-guard pack                                             │ require()
   ▼                                                                ▼
core.lgc  ──────────────  ships inside the package  ──────────►  activate()
   │                                                                │
   └── AES key ──────────►  D1: products, licenses  ◄───────────────┤
                                    │                    licence key│
                                    ├─ checks seats, status         │
                                    ├─ LOGS the deployment          │
                                    └─ returns ────────────────────►┤
                                        signed token + core key     │
                                                                    ▼
                                                            decrypt & run
```

**Before you deploy this, read [SECURITY.md](SECURITY.md).** It is blunt about
what this buys — days of an attacker's time, not permanence — and about the
failure mode that will actually cost you money, which is not piracy.

## Install

```sh
npm install @devmilon/license-guard
```

Node 18 or later. No runtime dependencies. The command it installs is
`license-guard` — the scope is on the package, not the binary.

> The unscoped name is unavailable: npm's typosquat protection rejects
> `license-guard` as too close to the existing `licenseguard`, which is an
> unrelated package. Worth knowing if you go looking for it on npm and find
> something else.

## See it work

```sh
git clone https://github.com/milonpatowary/license-guard
cd license-guard && npm run demo
```

One second, no network, no account. It generates keys, encrypts a module, runs
the real Worker against a real SQLite database, activates two deployments,
refuses a third, shows that restarts are free, shows that a copy without a
licence key is inert, and prints the sharing report. Read
`examples/protected-product/run.js` as the tutorial — every step maps to a real
one.

## Set it up

### 1. Keys, once

```sh
npx @devmilon/license-guard keygen
```

Three things come out. The **public key** (`lgpk1_…`) goes in the code you ship
and is safe to commit. The **secret key** (`lgsk1_…`) signs licences and belongs
in a password manager. The **Worker secret** is the same secret in the format
Cloudflare's WebCrypto reads.

### 2. Deploy the licence server

```sh
npx wrangler@4 d1 create license-guard          # paste the id into server/wrangler.toml
npx wrangler@4 d1 execute license-guard --remote --file=server/schema.sql
npx wrangler@4 secret put SIGNING_KEY --config server/wrangler.toml
npx wrangler@4 secret put ADMIN_TOKEN --config server/wrangler.toml
npx wrangler@4 secret put IP_SALT     --config server/wrangler.toml
npx wrangler@4 deploy --config server/wrangler.toml
```

See [server/README.md](server/README.md) for the endpoints and the admin API.

### 3. Encrypt your core at build time

```sh
npx @devmilon/license-guard pack \
  --in src/core.js --out dist/core.lgc \
  --product acme-core --version $npm_package_version \
  --key-out .core-key
```

Register the printed key with the product, once:

```sh
curl -X POST https://licence.example.com/v1/admin/products \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"id":"acme-core","coreKey":"'"$(cat .core-key)"'"}'
```

Then make sure the plaintext does not ship:

```json
{
  "files": ["dist", "index.js"],
  "scripts": { "prepublishOnly": "npm run build && npm pack --dry-run" }
}
```

The most common way this scheme fails is `src/core.js` sitting next to
`dist/core.lgc` in the published tarball. Look at `npm pack --dry-run` output
before every release.

### 4. Load it at runtime

Your package's public entry point becomes a few lines:

```js
const { protect } = require('@devmilon/license-guard')

module.exports = async function init () {
  const { core, license } = await protect({
    product: 'acme-core',
    version: require('./package.json').version,
    publicKey: 'lgpk1_…',                          // safe to commit
    endpoint: 'https://licence.example.com',
    licenseKey: process.env.ACME_LICENSE_KEY,
    coreFile: require.resolve('./dist/core.lgc'),
    context: { license: null }                     // see below
  })

  return { ...core, license }
}
```

`license` is the snapshot: status, customer, plan, features, watermark, expiry.
`core` is your real module.

Note the shape. Activation happens **once, at load**, and the result *is* the
module. There is no per-call check and no `if (!licensed) return` scattered
through your hot path — a check in twenty places is a check an attacker deletes
in twenty places, or in one. When the code is encrypted, the only leverage is
the key, and the key is obtained once.

### 5. Issue a licence per customer

```sh
curl -X POST https://licence.example.com/v1/admin/licenses \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"product":"acme-core","customer":"Northwind Bank","seats":3,
       "features":["reports","sso"],"plan":"enterprise"}'
```

The response contains the licence key **once**. Only its hash is stored, so
there is no way to show it again — a dump of your database yields no working
keys.

## How it behaves when things go wrong

This is the part worth understanding before you ship it.

| Situation | What happens |
|---|---|
| Server unreachable, cached token valid | Runs. No delay, no warning. |
| Server unreachable, token expired, inside grace | Runs, logs a warning, keeps retrying. |
| Server unreachable, past grace | **Runs**, calls `onDegrade`. This library never stops your product. |
| Server unreachable, never activated here | Fails, and says the first activation needs network. |
| Licence revoked | Fatal — on the next check-in. |
| Seat limit reached | Fatal, for the machine that tipped it over. Existing deployments keep working. |
| Token signed by the wrong key | Fatal. Someone is impersonating your server. |
| Core file tampered with | Fatal. |
| Unrecognised error from the server | Degrades. A future server bug must not become an outage across your installed base. |

Defaults: 7-day token, 14-day grace, 6-hour heartbeat. Twenty-one days of your
own outage before a customer notices anything. That is deliberate — see
SECURITY.md.

## Feature gating and watermarking

```js
if (guard.has('sso')) enableSso()
guard.require('reports')          // throws if absent

// Inside the encrypted core, where the check is worth something:
function exportReport (rows) {
  return { rows, issuedTo: license.customer, mark: license.watermark }
}
```

The watermark is per-licence and stable. Stamp it into anything the product
generates. When one of those artefacts turns up somewhere it should not be, it
names the licence that made it.

## Deployment tracing

Every activation and heartbeat records the fingerprint, hostname, platform,
container hint, app version, hashed IP, ASN, AS organisation and country.

```sh
curl -H "authorization: Bearer $ADMIN_TOKEN" \
  https://licence.example.com/v1/admin/report
```

```json
{ "licenses": [
  { "customer": "Someone Who Shares", "instances": 3, "networks": 3,
    "countries": 3, "sharingSuspected": true },
  { "customer": "Northwind Bank", "instances": 2, "networks": 1,
    "countries": 1, "sharingSuspected": false }
] }
```

Sort by `networks`. Two boxes in one datacentre is a customer who grew. Three
instances across three companies in three countries is a key doing the rounds,
and it is worth a phone call.

## Containers, Kubernetes, and the fingerprint

The tutorial fingerprint — hash the hostname and the MAC — is wrong for how
software is actually deployed. In a container the hostname is the container id
and changes on restart; under Kubernetes it is the pod name and changes on every
rollout; the MAC belongs to a veth pair and is random. A customer with three
replicas restarting nightly would burn ninety seats a month.

So the default identity is an instance id written to the state directory once
and read forever after. It survives hostname changes, interface changes and
migrations. Hostname, MAC hash and container hints are still **reported** —
they are what makes the sharing report work — but they decide nothing.

On immutable infrastructure, set it explicitly:

```yaml
env:
  - name: LICENSE_GUARD_INSTANCE_ID
    value: "prod-eu-west-1"      # or valueFrom a StatefulSet-stable field
```

If the filesystem is read-only and no id was supplied, the fingerprint falls
back to observable machine details and is flagged `ephemeral`. The server counts
ephemeral instances on a 36-hour window instead of 45 days, so container churn
does not accumulate seats.

## Air-gapped customers

Some customers will never let your product make an outbound connection. Issue
them a portable licence:

```sh
npx @devmilon/license-guard issue \
  --secret lgsk1_… --product acme-core --license lic_northwind \
  --customer "Northwind Bank" --any-machine --days 365 \
  --core-key "$(cat .core-key)" --out northwind.json
```

```js
await protect({
  product: 'acme-core',
  publicKey: 'lgpk1_…',
  offlineLicense: require('./northwind.json'),
  coreFile: require.resolve('./dist/core.lgc')
})
```

That file works on every machine it is copied to, which is why `--any-machine`
is required and will never happen by accident. Keep the expiry short and renew
it as part of the support contract.

## CLI

```
license-guard keygen                       create the signing keypair
license-guard pack --in --out --product    encrypt a module
license-guard issue --secret --product …   sign a token offline
license-guard inspect <file|token>         show what something contains
license-guard fingerprint --product <id>   this machine's deployment id
```

Everything is offline. The Worker is the only part that gets deployed, and the
only part a customer ever talks to.

## API

```js
const {
  protect,              // activate + decrypt + load, in one call
  createGuard,          // the licence state machine on its own
  loadEncryptedModule,  // the loader on its own
  packCore, unpackCore, readCoreMeta,
  computeFingerprint,
  sign, verify, decodeUnverified,
  generateKeyPair, publicKeyFor
} = require('@devmilon/license-guard')
```

Full types in [`index.d.ts`](index.d.ts).

## Tests

```sh
npm test
```

147 tests, no network, no Docker. The licence server is tested by running the
real Worker handler against a real SQLite database through `node:sqlite` — D1
*is* SQLite, so the queries under test are the queries that ship. That is how
the signing-key caching bug in `server/worker.js` was found: a module-level memo
meant a rotated `SIGNING_KEY` was silently ignored by warm isolates, which would
have surfaced as random signature failures on the one day it mattered.

## Support this work

If this saved you a licensing subscription, or a week of building one:

| Asset | Network | Address |
|---|---|---|
| TRX | TRON | `TLVs5cx85cwUCCGV8KujZkh5gDCpxomTd6` |
| USDT **or** USDC | BNB Smart Chain (BEP-20) | `0x737d85ECF68EAEF3dA5Ac912412D98e721F80ab9` |

Send only the named asset on the named network — see [DONATE.md](DONATE.md) for
the warnings that go with that, and for GitHub Sponsors and Ko-fi. Stars and bug
reports are worth as much.

## Licence

MIT — see [LICENSE](LICENSE). The tool is open; what you protect with it is
yours.
