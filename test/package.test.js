'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const pkg = require('../package.json')
const api = require('../src/index')

const root = path.join(__dirname, '..')

/**
 * The checks that only fail after publishing.
 *
 * A previous package of mine shipped with `package.json` missing from its
 * `exports` map, which nothing catches until a consumer installs the tarball
 * and a tool tries to read it. These are cheap; the failures they prevent are
 * not.
 */

test('every name the types promise actually exists at runtime', () => {
  const declared = fs.readFileSync(path.join(root, 'index.d.ts'), 'utf8')
  const names = [...declared.matchAll(/^\s{2}export (?:function|const|class) (\w+)/gm)]
    .map((match) => match[1])

  assert.ok(names.length > 20, 'the regex found the declarations')
  for (const name of names) {
    assert.ok(api[name] !== undefined, `index.d.ts declares "${name}" but src/index.js does not export it`)
  }
})

test('the exports map does not lock out package.json', () => {
  // Subpath exports are deny-by-default. Omitting this entry breaks `require
  // ('license-guard/package.json')`, which bundlers and version-check tools do
  // constantly, with ERR_PACKAGE_PATH_NOT_EXPORTED.
  assert.equal(pkg.exports['./package.json'], './package.json')
})

test('the published tarball has everything it needs and nothing it should not', () => {
  const listing = JSON.parse(
    execFileSync('npm', ['pack', '--dry-run', '--json'], { cwd: root, encoding: 'utf8' })
  )
  const files = listing[0].files.map((f) => f.path)

  for (const required of [
    'src/index.js', 'src/guard.js', 'src/loader.js', 'src/pack.js', 'src/token.js',
    'bin/license-guard.js', 'index.d.ts', 'README.md', 'LICENSE',
    'server/worker.js', 'server/schema.sql', 'server/wrangler.toml', 'server/package.json',
    'SECURITY.md', 'DONATE.md'
  ]) {
    assert.ok(files.includes(required), `${required} is missing from the tarball`)
  }

  for (const unwanted of files) {
    assert.ok(!unwanted.startsWith('test/'), `${unwanted} should not ship`)
    assert.ok(!unwanted.startsWith('.github/'), `${unwanted} should not ship`)
  }
})

test('the CLI is executable and self-describes', () => {
  const bin = path.join(root, pkg.bin['license-guard'])
  assert.equal(fs.readFileSync(bin, 'utf8').startsWith('#!/usr/bin/env node'), true)
  if (process.platform !== 'win32') {
    assert.ok(fs.statSync(bin).mode & 0o111, 'the bin needs its executable bit')
  }
})

test('the package declares no runtime dependencies', () => {
  // A licensing library is the last place anyone wants a supply-chain surface.
  // Everything here is node:crypto, node:vm and node:fs.
  assert.deepEqual(pkg.dependencies, {})
})

test('the worker is loadable as an ES module from its published path', async () => {
  const worker = await import('../server/worker.js')
  assert.equal(typeof worker.handle, 'function')
  assert.equal(typeof worker.default.fetch, 'function')
})

test('the schema and the worker agree about the columns', async () => {
  // Cheap drift check: every column the worker writes to `instances` must exist
  // in schema.sql, or the first activation in production fails.
  const schema = fs.readFileSync(path.join(root, 'server', 'schema.sql'), 'utf8')
  const worker = fs.readFileSync(path.join(root, 'server', 'worker.js'), 'utf8')

  const insert = worker.match(/INSERT INTO instances \(([\s\S]*?)\) VALUES/)
  assert.ok(insert, 'found the instances insert')
  const columns = insert[1].split(',').map((c) => c.trim()).filter(Boolean)

  const table = schema.match(/CREATE TABLE IF NOT EXISTS instances \(([\s\S]*?)\n\);/)[1]
  for (const column of columns) {
    assert.match(table, new RegExp(`\\b${column}\\b`), `instances.${column} is not in schema.sql`)
  }
})
