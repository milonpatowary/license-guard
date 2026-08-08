# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- The signing key is memoised against the secret it came from, so
  `wrangler secret put SIGNING_KEY` takes effect on warm isolates. The obvious
  cache-once implementation silently ignored rotation; the end-to-end test
  caught it.
- Read [SECURITY.md](SECURITY.md) before deploying. This raises the cost of
  unlicensed use from zero to several days of skilled work. It does not raise it
  to infinity, and nothing that runs on someone else's computer can.

[Unreleased]: https://github.com/milonpatowary/license-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/milonpatowary/license-guard/releases/tag/v0.1.0
