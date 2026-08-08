# Contributing

Bug reports with a reproduction are the most useful thing you can send. Second
most useful: a note about what this got wrong in production.

## Running the tests

```sh
npm install
npm test
```

No network, no Docker, no account. On Node 22+ that includes the licence server,
which runs the real Worker handler against a real SQLite database through
`node:sqlite`; on 18 and 20 those files skip and the client suite still runs.

```sh
npm run demo     # the whole system end to end, about a second
npm run lint
```

## The rules this codebase is built on

**Nothing in this library may stop a customer's product.** Failing to reach the
licence server is our problem, not theirs. The only fatal conditions are a
licence that is provably wrong — forged signature, revoked key, wrong machine,
tampered core. If you are adding a code path that throws, check
[`src/errors.js`](src/errors.js) and be sure you have chosen the right side of
that line.

**Cryptographic decisions are load-bearing and are tested as such.** There is a
test for a forged signature, for a flipped ciphertext byte, for a relabelled
header, for a token replayed under a different format version, and for a cache
copied to another machine. Anything touching `token.js`, `pack.js`, `aes.js` or
`vault.js` needs its own adversarial test, not just a happy path.

**Time is a parameter.** Everything interesting here happens across days, so
`now` is injectable and the tests drive it. Do not use `Date.now()` directly in
`src/`.

**Comments explain why, not what.** Several comments in this repository exist
because the obvious implementation was wrong — the fingerprint that reads the
hostname, the transaction-style probe, the signing key cached once. Those
comments are the reason the bug will not come back; please write them the same
way if you fix something subtle.

## Changes to the Worker

`server/worker.js` is deployed by users, so its SQL and its error vocabulary are
part of the public interface. If you add an error code, add it to
`serverError()` in `src/guard.js` too — an unrecognised code deliberately
degrades rather than failing, so a mismatch will look like it works.

Run `npx wrangler deploy --dry-run --config server/wrangler.toml` before opening
a pull request; CI does the same, and it is the only thing that catches an
import workerd does not have.

## Style

`standard`, enforced in CI. `npm run lint -- --fix` for the mechanical parts.

## Donation addresses

`DONATE.md` is covered by CODEOWNERS. Any pull request touching an address will
be scrutinised; that is not personal, it is a known attack on open-source
repositories. If you fork this, please point the addresses at yourself or remove
them.
