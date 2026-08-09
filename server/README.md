# The licence server

One Cloudflare Worker, one D1 database, no monthly bill.

Workers' free tier is 100,000 requests a day. A thousand customer deployments
checking in every six hours is four thousand requests a day, so the ceiling is
not a constraint — which is the point. The commercial alternative charges a few
dollars per active install per month for the privilege of telling you about your
own customers.

## Deploy

```sh
npx wrangler@4 d1 create license-guard
# paste the printed database_id into wrangler.toml

npx wrangler@4 d1 execute license-guard --remote --file=server/schema.sql

node bin/license-guard.js keygen                                      # keep the secret key safe
npx wrangler@4 secret put SIGNING_KEY --config server/wrangler.toml   # the "Worker secret" line
npx wrangler@4 secret put ADMIN_TOKEN --config server/wrangler.toml   # any long random string
npx wrangler@4 secret put IP_SALT     --config server/wrangler.toml   # any long random string

npx wrangler@4 deploy --config server/wrangler.toml
```

`node bin/license-guard.js`, not `npx @devmilon/license-guard`. Every command
here is run from a clone of this repository, and inside it npx finds a local
package of that name, decides it is already installed, and tries to exec a
binary that was never linked because nothing was installed — which surfaces as
a bare `sh: license-guard: command not found`. Running the file directly
sidesteps that and needs no install, since this package has no dependencies.
(From anywhere *outside* the repo, `npx @devmilon/license-guard keygen` is
correct.)

Generate the keypair on the machine that will keep it. `keygen` prints a secret
key, and the whole scheme rests on that value never having been anywhere it
could be logged, pasted or scrolled past — which includes a terminal you are
screen-sharing and any chat window.

## Keeping the secrets

There are three, and they are not equally important.

**`lgsk1_…`, the signing key.** The only one that is irreplaceable. Losing it
means you can never again issue an offline licence or redeploy the same signing
key, so every client already shipped with the matching public key is stranded
and you are forced into a release. Leaking it means anyone can mint licences
for every version you have ever shipped. Back it up somewhere that survives the
laptop.

Keep only this one. The public key and the Worker secret are both *derived*
from it, so storing them separately is two more things to get out of step:

```sh
license-guard derive --public-only < secret.txt      # lgpk1_…
license-guard derive --worker-only < secret.txt      # base64 PKCS8
```

**`ADMIN_TOKEN`.** Used constantly, and freely rotatable — `wrangler secret put`
a new one and the old is dead. Losing it costs you one command.

**`IP_SALT`.** Never needed again, and must never change. Every `ip_hash` in
`instances` and `events` was computed with it, so a new salt silently stops new
rows correlating with old ones and there is no way to recompute the history.
Back it up with the same care as the signing key, then never touch it.

### macOS Keychain

```sh
# -w with no value prompts, so nothing lands in shell history.
# -U updates in place; without it, a second add fails as a duplicate.
security add-generic-password -U -a "$USER" -s license-guard.SIGNING_KEY -w
security add-generic-password -U -a "$USER" -s license-guard.ADMIN_TOKEN -w
security add-generic-password -U -a "$USER" -s license-guard.IP_SALT     -w
```

Namespace the service (`license-guard.`) rather than using bare `SIGNING_KEY`.
The second product you license will want its own, and by then you will not
remember which is which.

Reading them back, without any of it reaching the terminal or `ps`:

```sh
# Install the Worker's signing key, derived on the fly.
security find-generic-password -a "$USER" -s license-guard.SIGNING_KEY -w \
  | license-guard derive --worker-only \
  | wrangler secret put SIGNING_KEY --config server/wrangler.toml

# Load the admin token for a shell session.
export ADMIN_TOKEN=$(security find-generic-password -a "$USER" -s license-guard.ADMIN_TOKEN -w)
```

Pipe secrets; do not pass them as arguments. Anything in `argv` is readable by
every process on the machine through `ps` for as long as the command runs,
which is why `derive` reads from stdin by default.

Keychain alone is not a backup — it is one disk. The signing key and the IP
salt both need a copy somewhere else.

## Smoke test after deploying

```sh
lg-admin selftest --public-key lgpk1_… --endpoint https://licence.example.com --cleanup
```

Nine checks against a throwaway product and licence, including the one that
matters most — that a token this server signs verifies against the public key
compiled into the clients you ship — then it deletes its own rows and exits
non-zero if anything failed. [OPERATIONS.md](OPERATIONS.md) covers it, and the
rest of running this thing, properly.

By hand, if you would rather see the requests:

```sh
BASE=https://license-guard.<your-subdomain>.workers.dev

curl -s $BASE/v1/health              # {"ok":true,"signing":"ok",...}
                                     # 503 + detail => SIGNING_KEY is wrong; fix it first

curl -s -X POST $BASE/v1/admin/products \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"id":"smoke","name":"Smoke","coreKey":"'"$(openssl rand -base64 32)"'"}'

KEY=$(curl -s -X POST $BASE/v1/admin/licenses \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"product":"smoke","customer":"Smoke Test","seats":1}' | jq -r .licenseKey)

# Should return a token and a coreKey.
curl -s -X POST $BASE/v1/activate -H 'content-type: application/json' \
  -d '{"product":"smoke","version":"0.0.0","licenseKey":"'"$KEY"'","fingerprint":"fp-smoke"}'

# Should be refused with seat_limit, because the licence has one seat.
curl -s -X POST $BASE/v1/activate -H 'content-type: application/json' \
  -d '{"product":"smoke","version":"0.0.0","licenseKey":"'"$KEY"'","fingerprint":"fp-other"}'

curl -s -H "authorization: Bearer $ADMIN_TOKEN" "$BASE/v1/admin/report" | jq
```

The second activate returning `seat_limit` is the one that matters: it proves
the seat count, the instance upsert and the event log all agree against real
D1. Verify the returned token against your public key with
`node bin/license-guard.js inspect <token> --public-key lgpk1_…` before
trusting any of it.

Then point a route at it (`licence.yourdomain.com`) so the hostname your
customers see is yours and can outlive Cloudflare.

## Endpoints

### Customer-facing

| | |
|---|---|
| `POST /v1/activate` | First contact from a deployment. Claims a seat, returns a token and the core key. |
| `POST /v1/heartbeat` | Renewal. Extends the token, updates `last_seen`. Falls through to activate if the instance is unknown. |
| `POST /v1/release` | Give a seat back. Call it from your uninstaller. |
| `GET /v1/health` | Liveness, and a real signature with the configured key. 503 with a `detail` when that key will not import. |

Request body:

```json
{
  "product": "acme-core",
  "version": "2.1.0",
  "licenseKey": "ACMECO-1A2B3-…",
  "fingerprint": "9f2c…",
  "sdk": "0.1.0",
  "telemetry": { "hostname": "prod-1", "platform": "linux", "arch": "x64",
                 "container": "kubernetes", "macHash": "…", "ephemeral": false }
}
```

Response:

```json
{
  "token": "lgt1.…",
  "coreKey": "base64 AES-256 key",
  "heartbeatSeconds": 21600,
  "notice": "This licence expires in 9 days."
}
```

The token is signed *before* the instance row is written. The other order is
the obvious one and it is wrong: if signing throws, the seat has already been
claimed for a deployment that receives a 500 and no token, and the client
retries, and each retry costs another activation. A signing failure now writes
an `events` row with `outcome = 'error'` and the reason in `detail`, because
the one failure that most needs to be written down is the one that happens on
the first activation after a deploy, when nobody is running `wrangler tail`.

Errors are `{ "error": "<code>", "message": "…" }` with codes `unknown_license`,
`revoked`, `wrong_product`, `expired`, `seat_limit`, `invalid_request`. The
client maps each to an error class; only the first four are fatal. Anything the
client does not recognise degrades rather than stopping a customer, which is
what makes a future server bug survivable.

### Admin

All require `Authorization: Bearer $ADMIN_TOKEN`.

| | |
|---|---|
| `POST /v1/admin/products` | Register a product. Upserts, and keeps the existing core key unless you send a new one. |
| `GET /v1/admin/products` | Products, with a licence count each. No core keys — see below. |
| `POST /v1/admin/products/key` | `{"id":"…"}` → that one product's core key. Logged as an event. |
| `POST /v1/admin/licenses` | Mint a licence. Returns the key **once**. |
| `GET /v1/admin/licenses` | Every licence, with live seats counted the way the seat check counts them. |
| `PATCH /v1/admin/licenses` | Change seats, plan, features, expiry, email or notes. Not the key or the watermark. |
| `POST /v1/admin/revoke` | Set a licence to `revoked` (or any status). |
| `POST /v1/admin/release` | Free a seat without the licence key, which you do not have. |
| `GET /v1/admin/report?days=30` | The sharing report. |
| `GET /v1/admin/deployments?license=…` | Instances and events for one licence. |
| `POST /v1/admin/passkeys/challenge` | Registration options for a new passkey. |
| `POST /v1/admin/passkeys` | Verify and store a passkey. |
| `GET /v1/admin/passkeys` | Registered passkeys. Public keys and metadata. |
| `DELETE /v1/admin/passkeys` | `{"id":"…"}` → forget a passkey. |

Admin routes take either `Authorization: Bearer $ADMIN_TOKEN` — what the CLI
sends — or the dashboard's session cookie, in which case a write also needs the
`x-lg-dashboard: 1` header. See [OPERATIONS.md](OPERATIONS.md#the-dashboard).

Core keys are the one thing the list routes never return. `GET
/v1/admin/products` would otherwise send every key you own to the browser on
every dashboard load, and leave them sitting in the page whether or not anyone
asked to see one; `POST /v1/admin/products/key` fetches a single key, for the
product named in the body, and records the read in `events`. The reveal is a
`POST` so that a cookie-authenticated call needs the `x-lg-dashboard` header
too, and so that no product id lands in a request log or browser history.

### The dashboard

`GET /admin` serves it, and `POST`/`GET`/`DELETE /v1/admin/session` open, check
and close a session. The page is public and holds nothing: no token, no data,
and a `default-src 'none'` policy with a per-response nonce for its own inline
script and style.

Sign in with a passkey or with the admin token; both end in the same session.
`POST /v1/admin/passkey/challenge` and `POST /v1/admin/passkey/session` are the
login pair and are necessarily public — nobody is authenticated yet when they
are called. The challenge names no credential ids, because registration insists
on a discoverable credential so that it does not have to; an unauthenticated
caller cannot learn from this server whether a passkey exists at all.
Challenges live in `passkey_challenges` and are deleted on use, which is what
makes an assertion good exactly once.

Registering is admin-gated, so the token is what bootstraps the first passkey
and what recovers the account when every registered device is gone. WebAuthn
verification is in [`webauthn.js`](webauthn.js) — CBOR, COSE and ASN.1 by hand,
because the Worker bundles no dependencies. ES256 and RS256 are accepted;
attestation is requested as `none` and not verified, which is the right trade
when the person registering already holds the admin token.

```sh
curl -X POST https://licence.example.com/v1/admin/licenses \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"product":"acme-core","customer":"Northwind Bank","email":"ops@northwind.example",
       "seats":3,"plan":"enterprise","features":["reports","sso"],
       "expiresAt":1798761600}'
```

The licence key is returned once and never stored — only its SHA-256. There is
no "show me the key again" endpoint and there cannot be one. That costs you a
support path and buys you a database whose compromise yields no working keys.

## Configuration

Set in `[vars]`; every one has a sane default in `worker.js`.

| | | |
|---|---|---|
| `TOKEN_TTL_DAYS` | 7 | How long a token is valid without a check-in. Shorten this — not grace — if you need fast revocation. |
| `GRACE_DAYS` | 14 | How long past expiry a deployment keeps working while it cannot reach you. |
| `HEARTBEAT_HOURS` | 6 | How often a running deployment checks in. |
| `STALE_DAYS` | 45 | A seat is freed after this long without a check-in. |
| `EPHEMERAL_STALE_HOURS` | 36 | The same, for instances that could not persist an identity. Short, so container churn does not accumulate seats. |
| `ISSUER` | `license-guard` | The `iss` claim. |

## Tables

`products` and `licenses` are what you administer. `instances` is current state
— who is running this right now — and is what seats are counted from. `events`
is append-only history and is what answers "where has this licence been".

Keeping the last two separate matters: collapse them and you lose the history
the moment a customer's fleet rolls over, which is exactly when you want it.

## Reading the sharing report

```json
{ "customer": "Someone Who Shares", "instances": 3, "networks": 3,
  "countries": 3, "seats": 3, "overSeats": false, "sharingSuspected": true }
```

Sort by `networks`. Two boxes in one datacentre is a customer who grew. Three
instances across three ASNs in three countries, on a licence sold to one
company, is a key doing the rounds.

This is the only detection that reliably works. Someone who takes the code,
strips the guard and runs one copy quietly is invisible here and always will be
— see [SECURITY.md](../SECURITY.md).

## Rotating the signing key

`wrangler secret put SIGNING_KEY` takes effect immediately, including on warm
isolates — the key is memoised against the secret it came from, not simply held.
That was a real bug during development: the obvious `if (cachedKey) return
cachedKey` meant rotation silently did nothing until the isolates recycled, and
clients that had already picked up the new public key would have started
rejecting tokens at random.

Rotation still means a **new release**, because the public key is compiled into
the shipped package. Plan it like a breaking change, not a chore.

## Rate limiting

There is none in the Worker. Use a Cloudflare rate-limiting rule on
`/v1/activate` — it runs before your Worker, costs no requests, and is the right
layer for it.

## Testing changes

```sh
npm test
```

`test/server.test.js` runs this exact handler against a real SQLite database
through `node:sqlite`. D1 *is* SQLite, so the statements under test are the
statements that ship — including the `ON CONFLICT … DO UPDATE` clause that a
hand-written fake would have accepted without comment.

The `Request` in that suite is still a fake, and it is worth knowing where its
edges are, because one of them hid a bug for the whole of 0.1.0. Its `json()`
used to be re-readable. A real body is a stream, read once and gone, and
`heartbeat` was handing its Request to `activate`, which read it again, got
null, and refused a legitimate re-activation. The fake is single-read now. If
you add to it, make it stricter than the runtime rather than kinder.

For anything touching the runtime rather than the SQL — WebCrypto, request
bodies, `request.cf` — run the real thing:

```sh
npx wrangler@4 dev --local --config server/wrangler.toml
```

That is workerd, the same binary Cloudflare runs, with a local D1. It needs no
account and no credentials. Put the secrets in a `.dev.vars` beside
`wrangler.toml` (it is gitignored); note that file is read at startup only, so
changing a secret means a restart, not a reload.

The schema and the four statements that carry the most weight have also been
run against a real D1 database in production, not just against `node:sqlite`:

- the whole of `schema.sql`, applied clean
- the `instances` upsert, twice, confirming `activations` increments and
  `first_seen` survives while `last_seen` advances
- the seat count, confirming the `CASE` gives an ephemeral instance a 36-hour
  window and a real host 45 days
- the sharing report's `COUNT(DISTINCT …)` over its `LEFT JOIN`
- the `(? IS NULL OR license_id = ?)` filter, on both branches

Still not covered: D1's request-level transaction semantics and its
result-size limits at scale. Deploy to a staging Worker before a release.
