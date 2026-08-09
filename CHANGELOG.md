# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.2.0] — 2026-08-09

### Added

- `PATCH /v1/admin/licenses`, `lg-admin license-update`, and an edit form on the
  customer page: seats, plan, features, expiry, email, notes and status can all
  change after a licence is minted. Selling a customer a third seat previously
  meant editing D1 by hand. The key and the watermark stay read-only — only the
  key's hash was ever stored, and the watermark is stamped into artefacts the
  customer has already produced, which is the entire reason it exists. Lowering
  the seat count evicts nobody, because an instance that already holds a seat
  skips the check on re-activation; the response says so rather than letting the
  number imply an eviction that will not happen.
- Dashboard: a theme switcher (Auto, Light, Dark) remembered per device; search
  across customer, licence, product, email, plan and features, matching every
  word in any order; a product filter and five sort orders; a Sharing page for
  the report; and a Live checkbox that refreshes the moving views every 30
  seconds — never a form you are filling in.
- Dashboard layout for small screens. Below 760px the tables become cards that
  label their own cells from `data-label`, so there is one renderer rather than
  two layouts free to drift apart, and nothing scrolls sideways at 390px.
- Passkey sign-in for the dashboard (WebAuthn). Register a device once from the
  new **Passkeys** tab and the login screen offers Face ID or Touch ID instead
  of a token to paste. The admin token is a shared secret that has to travel
  from a Keychain through a clipboard into a text field to be used, and leaves a
  copy at every stop; a passkey's private key never leaves the device, what
  reaches the server is a signature over a challenge the server chose, and what
  the database holds is a public key that is worth nothing to whoever steals it.
  Phishing stops being possible too, because the browser will not sign for an
  origin the credential was not registered against.

  The token login stays, and is not vestigial: it authorises registering the
  first passkey — a passkey cannot bootstrap itself — and it is the way back in
  when every registered device is lost. Both routes end in the identical
  twelve-hour session cookie, and rotating `ADMIN_TOKEN` still invalidates every
  session at once.

  Verification is hand-written in `server/webauthn.js` — enough CBOR to read an
  attestation object, enough COSE to turn a credential key into a JWK, and the
  ASN.1 unwrapping ECDSA needs — because the Worker bundles no dependencies.
  ES256 and RS256 are accepted. Challenges are single-use rows in
  `passkey_challenges`, deleted when spent, so a captured assertion cannot be
  replayed; the public login challenge lists no credential ids, so it discloses
  nothing about which passkeys exist, or whether any do. Registrations,
  sign-ins and removals are written to `events`.

  Two new tables, `passkeys` and `passkey_challenges` — re-run
  `wrangler d1 execute license-guard --remote --file=server/schema.sql` before
  deploying.

- An admin dashboard at `GET /admin`, served by the same Worker: customers with
  live seat counts, every machine that has activated with its status and
  network, refusals and server-side failures, and forms for products and
  licences. One HTML page, no build step, no CDN, `default-src 'none'` with a
  per-response nonce for its own inline script and style, and every value
  rendered through `textContent` because hostnames arrive from customer
  machines.
- Session auth for the dashboard: `POST /v1/admin/session` trades the admin
  token for an `HttpOnly; Secure; SameSite=Strict` cookie, so the token is
  never left where a script can read it and a session can be expired where a
  leaked token cannot. It is signed with the admin token as the HMAC key, so
  rotating the token invalidates every outstanding session with no session
  table to clear. Cookie-authenticated writes additionally require an
  `x-lg-dashboard` header, which no cross-site form can set.
- `GET /v1/admin/licenses`, `GET /v1/admin/products`, and
  `POST /v1/admin/release` — the last because freeing a seat previously needed
  the licence key, which the operator has never had.
- `POST /v1/admin/products/key`, which returns one product's core key and logs
  that it did. The product list does not carry `core_key` at all: listing it
  there sent every key you own to the browser on every dashboard load and left
  them in the page unread, where the page's own CSP was the only thing standing
  between an injected script and all of them. The dashboard's reveal button now
  fetches the one key it is about to show, and `events` records the read.
- `lg-admin`, a second binary: the operator's side of a deployed server.
  `deploy` installs secrets from the macOS Keychain and refuses to call a
  deploy finished until the Worker proves it can sign. `selftest` runs nine
  checks against a throwaway licence and cleans up after itself — including the
  only check that proves the deployed `SIGNING_KEY` and the `lgpk1_…` compiled
  into shipped clients are a pair, which health cannot tell you. `product`,
  `license` and `revoke` administer; `machines`, `watch` and `report` show
  where your code is running, with refusals and server-side failures broken out
  because neither leaves an instance row to list. The admin token is read from
  the environment or the Keychain and never accepted as an argument, where `ps`
  would show it to every process on the machine.
- [server/OPERATIONS.md](server/OPERATIONS.md): licensing a customer, reading
  the fleet, and what to do when every client starts rejecting tokens.
- `license-guard derive` re-derives the public key and the Worker secret from a
  stored `lgsk1_…`, so exactly one value has to be kept safe rather than three
  copies of the same key drifting apart. Reads the secret from stdin by
  default, because anything passed in `argv` is visible to every process on the
  machine via `ps`.
- `workerSecretFor()` on the public API, which is what `derive` uses.
- `GET /v1/health` now signs a constant with the configured key and answers 503
  with a plain-language `detail` when it cannot, so a misconfigured
  `SIGNING_KEY` is one unauthenticated curl away instead of an opaque 500 on a
  customer's first activation.

### Fixed

- The packaging test read `npm pack --dry-run --json` as an array. npm 12
  returns an object keyed by package name, so `[0]` was undefined — and because
  the release workflow installs `npm@latest` to speak OIDC, the first place
  that surfaced was the publish job, on this release. It reads both shapes now,
  and also asserts that `bin/lg-admin.js`, `server/dashboard.js` and
  `server/webauthn.js` are in the tarball, and that nothing from `private/` or
  any `.dev.vars` ever is.
- `POST /v1/admin/products` required a `coreKey` and wrote whatever it was
  given, which quietly turned "rename this product" into "issue a new AES key".
  Every `.lgc` already in a customer's hands was packed with the old one and
  would have stopped decrypting at their next activation, with nothing in the
  request that looked destructive. `coreKey` is optional now: a new product gets
  a generated key, an existing one keeps the key it has, and replacing it is
  something you ask for by name and are warned about. `lg-admin product` no
  longer generates one client-side, which is where the sharp edge was.
- A heartbeat that carried no `telemetry` block erased the hostname, platform,
  architecture, container and Node version already recorded for that instance.
  The upsert assigned those columns unconditionally, so a client that reported
  itself on activation and stayed quiet afterwards was blank six hours later,
  and the fleet listing showed "(not reported)" for a deployment that had
  reported perfectly well. They are `COALESCE`d now: an absent field means "not
  sent", never "cleared".
- A heartbeat from an instance the server has never seen — one whose seat was
  reclaimed for staleness while it was offline, or any instance at all after a
  database restore — was refused with `invalid_request` instead of
  re-activating. `heartbeat` passed its `Request` to `activate`, which read the
  body a second time; a Request body is a stream and can only be read once, so
  that read returned null. The recovery path had never worked. The test fake
  allowed a body to be read twice, so the suite saw it working; the fake is
  single-read now, like the runtime, which turns the bug into a failure.
- A signing failure claimed a seat. `activate` and `heartbeat` wrote the
  instance row before issuing the token, so when `SIGNING_KEY` was wrong the
  seat was taken and `activations` incremented for a deployment that got a 500
  and no token — and every client retry did it again, while the events table
  recorded nothing, the log line being on the far side of the throw. The token
  is signed first now, and a signing failure writes an `error` event carrying
  the reason before the 500 goes out.
- `SIGNING_KEY` set to the `lgsk1_…` secret key rather than its base64 PKCS8
  form failed as `InvalidCharacterError: atob() called with invalid
  base64-encoded data` from inside the runtime. Found on a live deployment.
  Each way of getting that value wrong is now named, including that specific
  mix-up, which is the likely one because `keygen` prints both.
- `derive` read nothing from a non-blocking pipe. `fs.readFileSync(0)` throws
  EAGAIN when the writer is another Node process, so `echo … | derive` worked
  while `node … | derive` reported no secret had been supplied. It reads the
  stream now.
- server/README.md now covers keeping the three secrets, including that
  `IP_SALT` must never change — every stored `ip_hash` was computed with it, and
  a new salt silently stops new rows correlating with the old ones.

## [0.1.0] — 2026-08-08

First release.

### Added

- `protect()` — activate, decrypt and load an encrypted core module in one call.
- `createGuard()` — the licence state machine: activation, token cache,
  heartbeat, grace and degrade. Fail-open by design; only a provably invalid
  licence is fatal.
- `packCore()` / `loadEncryptedModule()` — AES-256-GCM core container with a
  clear-text, tamper-evident header, loaded through `vm.compileFunction` so
  stack traces from inside the core name a file rather than `<anonymous>`.
- Ed25519 licence tokens (`lgt1.…`) with no negotiable algorithm field, bound to
  product and deployment, carrying plan, features, seat count and a
  per-customer watermark.
- `computeFingerprint()` — deployment identity built on a persisted instance id
  rather than hostname and MAC, so containers and rolling deploys do not consume
  a seat per restart. Observable machine details are reported, never enforced.
- Encrypted-at-rest token cache, keyed to the machine, so a copied installation
  directory is inert elsewhere.
- `license-guard` CLI: `keygen`, `pack`, `issue`, `inspect`, `fingerprint`.
- A Cloudflare Worker + D1 licence server: activation, heartbeat, release, seat
  enforcement, deployment logging, and a sharing report that flags one licence
  key appearing across unrelated networks.
- Air-gapped support via portable licences (`issue --any-machine`).
- A runnable end-to-end demo (`npm run demo`) that needs no network or account.

### Notes

- Published as `@devmilon/license-guard`. The unscoped `license-guard` is
  refused by npm's typosquat protection for being too close to the unrelated
  `licenseguard`; a scoped name sidesteps that check entirely. The installed
  command is still `license-guard`.
- The signing key is memoised against the secret it came from, so
  `wrangler secret put SIGNING_KEY` takes effect on warm isolates. The obvious
  cache-once implementation silently ignored rotation; the end-to-end test
  caught it.
- Read [SECURITY.md](SECURITY.md) before deploying. This raises the cost of
  unlicensed use from zero to several days of skilled work. It does not raise it
  to infinity, and nothing that runs on someone else's computer can.

[Unreleased]: https://github.com/milonpatowary/license-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/milonpatowary/license-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/milonpatowary/license-guard/releases/tag/v0.1.0
