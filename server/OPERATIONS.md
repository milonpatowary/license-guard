# Running it

The day-to-day of a deployed licence server: getting a customer licensed, and
knowing afterwards where your code is running.

Everything here is `lg-admin`, which ships with this package. It has no
dependencies and talks to your Worker over HTTPS.

```sh
npx -p @devmilon/license-guard lg-admin --help   # from anywhere
node bin/lg-admin.js --help                      # from a clone of this repo
```

`-p` is not optional. This package ships two binaries, and without it npx runs
the one whose name matches the package — so `npx @devmilon/license-guard
lg-admin` gets you `license-guard: Unknown command "lg-admin"`. Once the package
is a dependency of something, plain `npx lg-admin` works, because the bin is
linked into `node_modules/.bin`.

Use the second form inside a clone of this repo. There, npx finds the local
package, decides it is already installed, and tries to exec a binary that was
never linked.

## The dashboard

The Worker serves one at `/admin`. Same Worker, same database, no second thing
to deploy:

```
https://licence.yourdomain.com/admin
```

It covers the whole loop — register a product, mint a licence, watch the
machines that come back, release a seat, revoke — so the CLI below is for
scripting and CI rather than for the parts you do by hand.

**How it holds your admin token: it doesn't.** You paste the token once and the
Worker trades it for an `HttpOnly` cookie, which JavaScript in the page cannot
read. That matters because a bearer token kept in `localStorage` is readable by
anything that gets script into the page, and a leaked admin token cannot be
expired — where a session can, and does, after twelve hours. The cookie is
`Secure`, `SameSite=Strict`, and signed with the admin token as the key, so
`wrangler secret put ADMIN_TOKEN` logs everyone out with no session table to
clear. Writes also require a header no cross-site form can set.

The page loads no scripts, styles, fonts or images from anywhere — its
Content-Security-Policy is `default-src 'none'` with a per-response nonce for
its own inline script and style. It renders every value through `textContent`,
because hostnames and container names arrive from customer machines and are
therefore whatever a customer's machine chose to send.

### Passkeys, so you stop pasting the token

Open **Passkeys**, name the device, and register it. After that the login screen
offers Face ID or Touch ID and the token stays in the Keychain where you left
it.

This is worth doing for a reason beyond convenience. The admin token is a shared
secret, and the path it takes to reach the login box — Keychain, clipboard, text
field — leaves a copy at every step. A passkey's private key never leaves the
device: what reaches the Worker is a signature over a challenge the Worker
chose, and what the database stores is a public key. Someone who walks off with
a dump of `passkeys` gets nothing they can log in with. A phished passkey is
also not a thing that happens, because the browser will only sign for the origin
the credential was registered against.

Registering needs the admin token, and that is not an oversight — a passkey
cannot bootstrap itself. **Keep the token.** It is the way back in when the
device holding your passkey is lost, stolen or wiped, and it is the only way to
register a replacement. If you register passkeys on two devices, you can lose
one without ceremony; that is the cheapest insurance available here.

A passkey login and a token login are the same session afterwards: same cookie,
same twelve hours, same `wrangler secret put ADMIN_TOKEN` revoking all of them
at once. Registrations, sign-ins and removals are written to `events`, so
`lg-admin machines` and the Overview both show who came in and how.

Two caveats worth knowing before you rely on it. Passkeys are bound to the
hostname they were registered under, so moving the dashboard to a new domain
means registering again — the old credentials will simply not be offered. And
the passkey is stored wherever your platform puts it: on a Mac with iCloud
Keychain that means it syncs to your other Apple devices, which is usually what
you want and is worth knowing either way.

## Set it up once

Two environment variables save you typing them on every command:

```sh
export LICENSE_GUARD_ENDPOINT=https://licence.yourdomain.com
export ADMIN_TOKEN=$(security find-generic-password -a "$USER" \
  -s license-guard.ADMIN_TOKEN -w)
```

The token is also read straight from the Keychain if you skip the export, so on
a Mac the second line is optional. It is never accepted as a command-line
argument — anything in `argv` is readable by every process on the machine
through `ps` for as long as the command runs.

Put both in your shell profile and forget about them.

## Deploy

```sh
lg-admin deploy --secrets --endpoint https://licence.yourdomain.com
```

`--secrets` reads `license-guard.SIGNING_KEY` from the Keychain, derives the
base64 PKCS8 form WebCrypto needs, and installs it — along with `ADMIN_TOKEN`
and `IP_SALT` if they are stored too. Each value goes to `wrangler` on stdin,
never in `argv`. Drop `--secrets` for a code-only deploy, which is most of them.

It then polls `/v1/health` until the Worker answers, and fails loudly if the
Worker is up but cannot sign. That check exists because the alternative is
finding out on a customer's first activation, as an opaque 500, visible only in
`wrangler tail`. That is not hypothetical — it is what happened here.

### Prove it works

```sh
lg-admin selftest --public-key lgpk1_… --cleanup
```

Nine checks against a throwaway product and licence: health, minting,
activation, **that the token verifies against the public key you ship**,
renewal, the seat limit, seat reclaim after a release, and revocation. Then it
deletes its own rows.

The fourth one is the only check that proves your `SIGNING_KEY` and the
`lgpk1_…` compiled into your shipped clients are actually a pair. Health proves
the key imports and signs; it cannot tell you it is the *right* key. Deploy
with the wrong one and every customer rejects every token, with no error on
your side at all.

Run it after every deploy that touched a secret. It exits non-zero on failure,
so it drops into CI unchanged.

## License a customer

### 1. Register the product, once

```sh
lg-admin product --id acme-core --name "Acme Core"
```

Prints a generated AES core key. Pack your encrypted core with that exact key —
the server hands it to every licensed deployment, and a mismatch means the
`.lgc` will not decrypt anywhere:

```sh
license-guard pack --in src/core.js --out dist/core.lgc \
  --product acme-core --key '<the core key>'
```

Re-run `product` with `--core-key` to keep the key an existing build already
uses. It upserts, so it is also how you change the name or the core key later.

### 2. Mint the licence

```sh
lg-admin license --product acme-core \
  --customer "Northwind Bank" --email ops@northwind.example \
  --seats 3 --plan enterprise --features reports,sso \
  --expires-in-days 365
```

```
  key         ACMECO-5F012-A0C33-C7D9E-498C0-EC18E
  id          lic_090f5f84cd37bd64
```

**The key is shown once.** Only its SHA-256 is stored, there is no endpoint
that can show it again, and there cannot be one — that is the same endpoint
someone with your admin token would use. Losing it costs one re-mint; a
"show me the key" endpoint would cost you the property that a database dump
yields no working keys.

`--seats` counts *distinct deployments*, not users, not CPUs. `--features` is
what `guard.has('reports')` reads. `--expires-in-days` is the subscription
end; a token is never issued past it, which is the only place renewal is
actually enforced.

### 3. What the customer does

```sh
export LICENSE_GUARD_KEY=ACMECO-5F012-A0C33-C7D9E-498C0-EC18E
```

```js
const { protect } = require('@devmilon/license-guard')

const { core, license } = await protect({
  product: 'acme-core',
  publicKey: 'lgpk1_…',                          // safe to commit
  endpoint: 'https://licence.yourdomain.com',
  coreFile: require.resolve('./dist/core.lgc')
})
```

First run claims a seat and writes a durable instance id under the state
directory. That id — not the hostname, not the MAC — is the fingerprint. It has
to be durable, because a hostname is a container id and a MAC is a random veth
address, and a fingerprint built from those charges a seat every restart.

### 4. Check it from your own machine

```sh
lg-admin activate --product acme-core \
  --license-key ACMECO-… --public-key lgpk1_… --version 2.1.0
```

Activates using this machine's real fingerprint and verifies the token that
comes back — signature, product binding, machine binding. Give the seat back
with `lg-admin release --product acme-core --license-key ACMECO-…`, or it will
sit there for 45 days.

## Watch the fleet

```sh
lg-admin machines                       # everything
lg-admin machines --license lic_… -e    # one customer, with their event log
lg-admin watch --interval 30            # redrawn on a timer
```

```
Northwind Bank   lic_090f5f84cd37bd64
  3 of 3 seats in use

  * prod-web-1
      host        prod-web-1   linux/x64   in kubernetes
      running     2.1.0
      first seen  2026-08-09 05:35Z   5 minutes ago
      last seen   2026-08-09 05:40Z   1 second ago   healthy
      activations 1
      network     AS395747  US  via DFW  ip 47a147b9

  ! prod-web-2
      last seen   2026-06-23 22:28Z   46 days ago   stale — seat freed
```

Every time is shown twice, as a date you can quote in an email and an age you
can judge at a glance, because the question is never "what is the epoch second"
— it is "is this thing alive".

| | |
|---|---|
| `healthy` | Checked in within two heartbeat intervals. |
| `quiet` | Missed a check-in. One is nothing; a fleet of them is your outage. |
| `stale` | Past the staleness window. The seat is already free. |
| `released` | Called `/v1/release`, usually an uninstaller. |

Below the fleet, two sections that the fleet listing cannot show:

**Refused.** A refusal creates no instance row, by design — nothing was
admitted. So the most interesting thing a customer does, trying to run a fourth
copy on three seats, would otherwise be invisible in the one view you open.
`seat_limit` is a customer who wants to buy more. `unknown_license` from an
address you recognise is a typo; from one you do not, it is someone guessing.
`invalid_request` is almost always your own integration.

**Server-side failures.** `outcome = 'error'` rows: the server failing, not a
customer being refused. A `signing_failed` here means `SIGNING_KEY` is wrong and
*nothing* can activate. It is the first thing to look at when a customer says
the product stopped working and you cannot see why.

### Who is sharing

```sh
lg-admin report --days 30
```

Sort on **networks**, not on instances. Two deployments in one datacentre is a
customer who grew. Three instances on three networks in three countries, on a
licence sold to one company, is a key doing the rounds.

This is the only sharing detection that reliably works. Someone who takes the
code, strips the guard and runs one quiet copy is invisible here and always will
be — see [SECURITY.md](../SECURITY.md). Do not build a business process that
assumes otherwise.

## When something goes wrong

**A customer is over seats.** `lg-admin machines --license lic_…` and look at
`network` and `first seen`. Three rows on one ASN appearing the same afternoon
is a deployment being rolled; three rows on three ASNs over three months is not.

**Kill a licence now.**

```sh
lg-admin revoke --license lic_090f5f84cd37bd64
```

Every activation and heartbeat is refused fatally from that moment — the client
stops rather than degrading. Tokens already issued keep working until they
expire, up to `TOKEN_TTL_DAYS` (7 by default). If a week is too long, shorten
that variable — not `GRACE_DAYS`, which protects customers against *your*
outage and is not a revocation control.

**Every customer is rejecting tokens.** The signing key and the public key you
shipped are not a pair. Confirm:

```sh
security find-generic-password -a "$USER" -s license-guard.SIGNING_KEY -w \
  | license-guard derive --public-only
```

If that does not print the `lgpk1_…` in your released build, redeploy the right
secret with `lg-admin deploy --secrets`. It cannot be fixed by shipping a new
public key any faster than you can ship a release.

**Health says 503.** The `detail` names the mistake. The common one is pasting
the `lgsk1_…` secret key where the base64 PKCS8 belongs; `keygen` prints both,
one line apart.

**Rotating the signing key** takes effect immediately, including on warm
isolates. But the public key is compiled into everything you have shipped, so
rotation means a release. Plan it as a breaking change.
