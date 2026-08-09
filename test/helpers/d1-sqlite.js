'use strict'

const fs = require('fs')
const path = require('path')

/**
 * D1, backed by the SQLite that ships with Node.
 *
 * D1 *is* SQLite — the storage engine, the SQL dialect and the type affinities
 * are the same — so running the Worker's real statements against `node:sqlite`
 * tests the thing that actually breaks. The alternative, a hand-written fake
 * that pattern-matches queries, tests only that I can spell my own queries
 * consistently, and it would have cheerfully accepted the `ON CONFLICT ... DO
 * UPDATE` clause that a real database has an opinion about.
 *
 * What it does not cover: D1's network round trip, its request-level
 * transaction semantics, and its result-size limits. Those are integration
 * concerns; nothing here pretends otherwise.
 */
function createD1 (databasePath = ':memory:') {
  // node:sqlite is behind an experimental flag warning and only exists from
  // Node 22. The test files that need it skip when it is missing.
  const { DatabaseSync } = require('node:sqlite')
  const db = new DatabaseSync(databasePath)
  db.exec('PRAGMA foreign_keys = ON')

  function statement (sql, params = []) {
    return {
      bind (...values) {
        return statement(sql, values.map(normalize))
      },
      async first (column) {
        const row = db.prepare(sql).get(...params)
        if (row === undefined) return null
        return column ? row[column] : row
      },
      async all () {
        return { results: db.prepare(sql).all(...params), success: true, meta: {} }
      },
      async run () {
        const result = db.prepare(sql).run(...params)
        return {
          success: true,
          meta: {
            changes: Number(result.changes),
            last_row_id: Number(result.lastInsertRowid)
          }
        }
      }
    }
  }

  return {
    prepare (sql) { return statement(sql) },
    async batch (statements) {
      const out = []
      for (const s of statements) out.push(await s.run())
      return out
    },
    async exec (sql) { db.exec(sql); return { count: 0, duration: 0 } },
    _raw: db,
    close () { db.close() }
  }
}

/**
 * node:sqlite refuses `undefined` and has no boolean type. D1 accepts both and
 * coerces, so anything written against D1 would pass there and throw here —
 * which would be a false failure, not a found bug.
 */
function normalize (value) {
  if (value === undefined) return null
  if (typeof value === 'boolean') return value ? 1 : 0
  return value
}

function applySchema (d1) {
  const sql = fs.readFileSync(path.join(__dirname, '..', '..', 'server', 'schema.sql'), 'utf8')
  d1._raw.exec(sql)
  return d1
}

/**
 * Enough of a Request for the Worker: url, method, headers, json(), cf.
 *
 * `json()` throws on a second call, because a real Request body is a stream
 * that can only be read once. A fake that returns the same object every time
 * is more forgiving than the runtime, and that gap hid a real bug: the
 * heartbeat handler passed its Request to `activate`, which read the body a
 * second time, got null, and refused a legitimate re-activation with
 * `invalid_request`. Under workerd that path never worked. Here it always did.
 */
function makeRequest (method, url, { body = null, headers = {}, cf = {} } = {}) {
  const map = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  let used = false
  return {
    method,
    url: url.startsWith('http') ? url : `https://licence.test${url}`,
    headers: { get: (name) => map.get(String(name).toLowerCase()) ?? null },
    cf,
    get bodyUsed () { return used },
    async json () {
      if (used) throw new TypeError('Body has already been read')
      used = true
      if (body === null) throw new SyntaxError('no body')
      return typeof body === 'string' ? JSON.parse(body) : body
    }
  }
}

module.exports = { createD1, applySchema, makeRequest }
