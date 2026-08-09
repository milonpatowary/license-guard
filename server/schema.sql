-- license-guard licence server schema (Cloudflare D1 / SQLite)
--
--   wrangler d1 execute license-guard --remote --file=server/schema.sql
--
-- Six tables. The split between `instances` and `events` is the important one:
-- `instances` is current state — who is running this right now — and is what
-- seat limits are counted from. `events` is history, append-only, and is what
-- answers "where has this licence been". Collapsing them into one table loses
-- the history the moment a customer's fleet rolls over, which is exactly when
-- you want it.
--
-- The last two hold the dashboard's passkeys and are unrelated to licensing.

CREATE TABLE IF NOT EXISTS products (
  id          TEXT PRIMARY KEY,
  name        TEXT,
  -- The AES key for the current build's .lgc file, base64. Not a per-customer
  -- secret: every licensed instance of a given build receives the same one.
  -- Rotating it means repacking and shipping a new build.
  core_key    TEXT NOT NULL,
  min_version TEXT,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
  id          TEXT PRIMARY KEY,
  -- Only the hash. A dump of this table must not hand the reader working
  -- licence keys, and support staff browsing D1 in the dashboard should not be
  -- able to read a customer's key either.
  key_hash    TEXT NOT NULL UNIQUE,
  product_id  TEXT NOT NULL,
  customer    TEXT NOT NULL,
  email       TEXT,
  plan        TEXT NOT NULL DEFAULT 'standard',
  features    TEXT NOT NULL DEFAULT '',
  seats       INTEGER NOT NULL DEFAULT 1,
  -- Per-licence, stable for the life of the licence, and echoed into every
  -- token. The product stamps it into exports, logs and generated files, so a
  -- document that turns up where it should not can be traced to one customer.
  watermark   TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',
  expires_at  INTEGER,
  notes       TEXT,
  created_at  INTEGER NOT NULL,
  FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE INDEX IF NOT EXISTS licenses_by_product ON licenses (product_id, status);

CREATE TABLE IF NOT EXISTS instances (
  id           TEXT PRIMARY KEY,
  license_id   TEXT NOT NULL,
  fingerprint  TEXT NOT NULL,
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  released_at  INTEGER,
  ephemeral    INTEGER NOT NULL DEFAULT 0,
  activations  INTEGER NOT NULL DEFAULT 0,
  hostname     TEXT,
  platform     TEXT,
  arch         TEXT,
  container    TEXT,
  mac_hash     TEXT,
  node_version TEXT,
  app_version  TEXT,
  ip_hash      TEXT,
  asn          INTEGER,
  as_org       TEXT,
  country      TEXT,
  colo         TEXT,
  FOREIGN KEY (license_id) REFERENCES licenses(id)
);

CREATE INDEX IF NOT EXISTS instances_by_license ON instances (license_id, released_at, last_seen);

CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  outcome     TEXT NOT NULL,
  product_id  TEXT,
  license_id  TEXT,
  fingerprint TEXT,
  detail      TEXT,
  hostname    TEXT,
  app_version TEXT,
  ip_hash     TEXT,
  asn         INTEGER,
  as_org      TEXT,
  country     TEXT
);

CREATE INDEX IF NOT EXISTS events_by_license ON events (license_id, at);
CREATE INDEX IF NOT EXISTS events_by_time ON events (at);

-- A registered passkey for the dashboard. Public keys only: there is nothing
-- in this table that lets its reader log in, which is the entire reason to
-- prefer it to a shared token. Rows are per-device, so revoking a lost laptop
-- is a DELETE and costs nobody else their access.
CREATE TABLE IF NOT EXISTS passkeys (
  -- The credential id the authenticator generated, base64url.
  id           TEXT PRIMARY KEY,
  -- The credential public key as a JWK, exactly as WebCrypto will import it.
  public_key   TEXT NOT NULL,
  -- COSE algorithm: -7 for ES256, -257 for RS256.
  alg          INTEGER NOT NULL,
  -- The authenticator's own counter. Only useful when it moves; see the clone
  -- check in webauthn.js for why zero has to stay acceptable.
  sign_count   INTEGER NOT NULL DEFAULT 0,
  label        TEXT,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);

-- Challenges, held only between the two halves of a ceremony.
--
-- This is a table rather than a signed cookie for one reason: a row can be
-- deleted. Consuming the challenge on use is what stops a captured assertion
-- from being replayed, and a stateless signed challenge cannot offer that
-- without a store to mark it spent — at which point it is this table with
-- extra steps.
CREATE TABLE IF NOT EXISTS passkey_challenges (
  challenge  TEXT PRIMARY KEY,
  purpose    TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS passkey_challenges_by_expiry ON passkey_challenges (expires_at);
