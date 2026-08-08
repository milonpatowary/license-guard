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

npx @devmilon/license-guard keygen                                   # keep the secret key safe
npx wrangler@4 secret put SIGNING_KEY --config server/wrangler.toml   # the "Worker secret" line
npx wrangler@4 secret put ADMIN_TOKEN --config server/wrangler.toml   # any long random string
npx wrangler@4 secret put IP_SALT     --config server/wrangler.toml   # any long random string

npx wrangler@4 deploy --config server/wrangler.toml
```

Generate the keypair on the machine that will keep it. `keygen` prints a secret
key, and the whole scheme rests on that value never having been anywhere it
could be logged, pasted or scrolled past — which includes a terminal you are
screen-sharing and any chat window.

## Smoke test after deploying

```sh
BASE=https://license-guard.<your-subdomain>.workers.dev

curl -s $BASE/v1/health                                     # {"ok":true,...}

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
`npx @devmilon/license-guard inspect <token> --public-key lgpk1_…` before
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
| `GET /v1/health` | Liveness. |

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

Errors are `{ "error": "<code>", "message": "…" }` with codes `unknown_license`,
`revoked`, `wrong_product`, `expired`, `seat_limit`, `invalid_request`. The
client maps each to an error class; only the first four are fatal. Anything the
client does not recognise degrades rather than stopping a customer, which is
what makes a future server bug survivable.

### Admin

All require `Authorization: Bearer $ADMIN_TOKEN`.

| | |
|---|---|
| `POST /v1/admin/products` | Register a product and its core key. Upserts. |
| `POST /v1/admin/licenses` | Mint a licence. Returns the key **once**. |
| `POST /v1/admin/revoke` | Set a licence to `revoked` (or any status). |
| `GET /v1/admin/report?days=30` | The sharing report. |
| `GET /v1/admin/deployments?license=…` | Instances and events for one licence. |

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
