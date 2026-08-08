# What this actually protects against

Read this before you deploy it, and read it again before you promise anyone
that your code is safe.

## The short version

`license-guard` raises the cost of using your code without paying from **zero**
to **several days of skilled work**. It does not raise it to infinity, and no
tool that runs on someone else's computer ever will.

If your threat model is a competitor with an engineer and a week, this will not
stop them. If your threat model is the ordinary way private code leaks — a
contractor keeps a copy, a customer's repository is cloned, a laptop is sold, a
tarball ends up on a file-sharing site — then it works, because none of those
people are attackers. They are opportunists, and an opportunist stops at the
first locked door.

## What it stops

**A stolen repository is not a working product.** The core logic ships
encrypted. The key is not in the package, not in the environment, and not
derivable from anything the thief holds. It comes from your server, once, in
exchange for a licence key you issued to a named customer.

**A stolen licence key does not scale.** Keys are bound to deployments, and
deployments are counted. One key on forty machines is refused on machine three,
and — more usefully — it is *recorded* on machines one and two, with the network
and country each came from.

**A copied installation does not travel.** The cached token and core key on a
licensed machine are encrypted with material derived from that machine. Copy the
directory to another host and it is inert.

**A modified build does not run.** The core is authenticated, not just
encrypted. Editing the ciphertext, or relabelling the header to claim it is a
different product or version, fails the authentication tag rather than
producing subtly wrong code.

**A fake licence server does not work.** The public key is compiled into your
package, and only tokens signed by your key are accepted. Pointing the client at
a look-alike server — via DNS, `/etc/hosts`, or a proxy with a trusted CA —
produces signature failures, not licences.

**Your output is attributable.** Every licence carries a watermark, and every
token carries it to the running product. Stamp it into generated documents,
exports and logs, and a leaked artefact identifies the licence that made it.

## What it does not stop

**Someone with root on a licensed machine.** By the time your code runs, the
core has been decrypted into that process's memory, and the process belongs to
them. `node --inspect`, a heap snapshot, and a string search recovers the source.
This is not a flaw in the implementation; it is what "running code on a computer
you do not control" means. Every DRM system ever shipped has this property.

**Someone who deletes the licence check.** If they have recovered the plaintext
core, the next step is to publish a version with the guard stripped out. Nothing
in this repository prevents that. What survives is the watermark in the artefacts
they already produced, and your legal position.

**A quiet single-machine pirate.** Someone who runs one unauthorised copy, on
one machine, on a network you have never seen, with the guard removed, is
invisible to you and will remain so. Any claim to the contrary from a licensing
vendor is marketing.

**A determined competitor.** Assume a week of a good engineer's time defeats
this completely. Price that in when you decide how much of your product to move
into the encrypted core.

## The one thing that will actually cost you money

Not piracy. **A licensing check that stops a paying customer's production.**

Every default here leans away from that, deliberately:

- Activation happens once at load, not on every call.
- A signed token is cached and valid for seven days.
- A network failure keeps the product running on cache.
- An expired token enters a fourteen-day grace window in which everything works.
- Past grace it *degrades* — it calls your callback and carries on. This library
  never stops your product.
- The only fatal conditions are a licence that is provably wrong: a forged
  signature, a revoked key, a token for another machine, or a tampered core.

The arithmetic is unsentimental. A pirate who gets three extra weeks out of the
grace window costs you one licence. A fail-closed check that halts forty paying
customers during a DNS incident costs you the account, the renewal, the
reference, and a week of your life. Do not tighten these defaults because
strictness feels safer. It is not safer; it just moves the risk onto the people
who paid you.

If you genuinely need same-hour revocation — a chargeback, a terminated
contract — shorten `TOKEN_TTL_DAYS` rather than shortening grace. That
propagates the revocation faster without changing what happens when *you* are
the one who is down.

## Operational things that will bite you

**Ship the plaintext by accident and none of this matters.** The single most
common failure is the original `.js` sitting next to the `.lgc` in the published
tarball. Use `files` in `package.json` rather than `.npmignore`, and check
`npm pack --dry-run` before every release.

**The signing key is a release-blocking secret.** If it leaks, anyone can mint
licences for every version you have already shipped, and the only fix is a new
public key, which means a new release and a migration for every customer.
Keep it in a password manager and in `wrangler secret`, nowhere else.

**Rotate the core key on major releases, not never.** The core key is per-build,
not per-customer. Anyone who has legitimately activated once has held it. A new
build with a new key means yesterday's recovered key opens yesterday's product.

**Do not fingerprint on hostnames in containers.** The default deliberately does
not. Read the comment at the top of `src/fingerprint.js` before turning
`includeHost` on.

**Telemetry is customer data.** IP addresses are hashed with a salt before
storage; hostnames are not. Say so in your privacy notice, and let
enterprise customers set `telemetry: 'minimal'`. Licensing still works without
any of it.

## The layer that does more work than this one

Against a company — the entity most likely to over-deploy your product — the
effective controls are legal, not technical. A proprietary licence file, a
per-customer agreement with an audit clause, copyright headers on every file,
and a named human on their side who signed something. Companies do not steal
software because it is hard; they stop because their legal department says no.

Treat `license-guard` as the thing that makes casual copying inconvenient and
gives you the evidence to have the conversation. The conversation is what
recovers the revenue.

## Reporting a vulnerability

If you find a flaw in the cryptographic construction — the token format, the
core container, the cache derivation — please open a GitHub issue with the
details. There are no user credentials in this project and no hosted service to
compromise, so there is nothing gained by embargoing a report.
