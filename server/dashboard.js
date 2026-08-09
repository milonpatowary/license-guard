/**
 * The admin dashboard: one HTML page, served by the same Worker as the API.
 *
 * No build step, no framework, no CDN. A licence server that needs a bundler to
 * show you a table of customers is a licence server with a second thing to keep
 * deployed, and the whole argument for this design is that there is only one.
 *
 * Two constraints shape the code below, and both are load-bearing:
 *
 * 1. No backticks anywhere in the page's own JavaScript. The page is a template
 *    literal in this file, so a stray backtick silently ends the string and the
 *    build fails somewhere unrelated. (That is not hypothetical — it happened
 *    to a SQL comment in worker.js.) String concatenation throughout.
 *
 * 2. No innerHTML, ever. Half the strings rendered here came from a customer's
 *    machine — hostname and container are whatever the client sent — so they
 *    are attacker-controlled in the only sense that matters. Everything goes
 *    through textContent, which cannot execute anything.
 */

export function dashboardPage (nonce) {
  return '<!doctype html>\n<html lang="en">\n' + HEAD.replace('__NONCE__', nonce) +
    BODY.replace('__NONCE__', nonce)
}

const HEAD = `<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>license-guard</title>
<style nonce="__NONCE__">
/* Three theme states, and the third one is the reason this looks repetitive.
   "System" sets no attribute at all, so prefers-color-scheme decides; light and
   dark stamp data-theme on <html> and must beat the media query in both
   directions. That means the dark palette is written twice — once guarded by
   :not([data-theme="light"]) so an explicit light choice survives a dark OS,
   and once under [data-theme="dark"] so an explicit dark choice survives a
   light one. Collapsing either copy breaks exactly one of the six
   combinations, and it will be the one nobody tests. */
:root {
  --bg: #fbfbfa; --panel: #fff; --line: #e3e1dd; --ink: #1a1a19; --dim: #6b6862;
  --accent: #1f5c9e; --ok: #1c7c4a; --warn: #a55b00; --bad: #b4231d;
  --mono: ui-monospace, SFMono-Regular, Menlo, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #16161a; --panel: #1e1e23; --line: #33333c; --ink: #eceaea; --dim: #9b9792;
    --accent: #79b0e8; --ok: #63c58c; --warn: #e0a34a; --bad: #ef7a72;
    color-scheme: dark;
  }
}
:root[data-theme="dark"] {
  --bg: #16161a; --panel: #1e1e23; --line: #33333c; --ink: #eceaea; --dim: #9b9792;
  --accent: #79b0e8; --ok: #63c58c; --warn: #e0a34a; --bad: #ef7a72;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.55 system-ui, sans-serif;
}
a { color: var(--accent); }
header {
  display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
  padding: 14px 20px; border-bottom: 1px solid var(--line); background: var(--panel);
  position: sticky; top: 0; z-index: 5;
}
header h1 { font-size: 15px; margin: 0; font-weight: 650; letter-spacing: -0.01em; }
header .host { color: var(--dim); font-family: var(--mono); font-size: 12px; }
header .spacer { flex: 1; }
nav { display: flex; gap: 4px; }
nav button, .btn {
  font: inherit; font-size: 14px; padding: 6px 12px; border-radius: 7px; cursor: pointer;
  border: 1px solid transparent; background: transparent; color: var(--ink);
}
nav button:hover, .btn:hover { background: var(--bg); }
nav button[aria-current="page"] { background: var(--accent); color: #fff; }
.btn { border-color: var(--line); background: var(--panel); }
.btn.primary { background: var(--accent); color: #fff; border-color: transparent; }
.btn.danger { color: var(--bad); border-color: var(--line); }
.btn:disabled { opacity: 0.5; cursor: default; }
main { padding: 22px 20px 64px; max-width: 1080px; margin: 0 auto; }
h2 { font-size: 19px; margin: 0 0 4px; letter-spacing: -0.01em; }
h3 { font-size: 14px; margin: 26px 0 10px; color: var(--dim); font-weight: 650;
     text-transform: uppercase; letter-spacing: 0.06em; }
p.lede { color: var(--dim); margin: 0 0 22px; }
.cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 650; letter-spacing: -0.02em; }
.card .k { color: var(--dim); font-size: 13px; }
.card.flag .n { color: var(--warn); }
table { width: 100%; border-collapse: collapse; background: var(--panel);
        border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line); font-size: 14px; }
th { color: var(--dim); font-weight: 600; font-size: 12px; text-transform: uppercase;
     letter-spacing: 0.05em; }
tr:last-child td { border-bottom: none; }
tbody tr.click { cursor: pointer; }
tbody tr.click:hover { background: var(--bg); }
.mono { font-family: var(--mono); font-size: 12.5px; }
.dim { color: var(--dim); }
.tag { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px;
       border: 1px solid var(--line); }
.tag.ok { color: var(--ok); border-color: currentColor; }
.tag.warn { color: var(--warn); border-color: currentColor; }
.tag.bad { color: var(--bad); border-color: currentColor; }
.panel, .machine { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
                   padding: 14px 16px; margin-bottom: 10px; }
.grow { flex: 1; }
.gap { margin-top: 10px; }
.machine .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.machine .fp { font-family: var(--mono); font-size: 12.5px; word-break: break-all; }
.panel dl, .machine dl { display: grid; grid-template-columns: 116px 1fr; gap: 3px 14px;
              margin: 10px 0 0; font-size: 13.5px; }
.panel dt, .machine dt { color: var(--dim); }
.panel dd, .machine dd { margin: 0; }
form { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
       padding: 18px; max-width: 520px; }
label { display: block; margin-bottom: 13px; font-size: 13.5px; color: var(--dim); }
label span { display: block; margin-bottom: 4px; }
input, select {
  font: inherit; width: 100%; padding: 8px 10px; border-radius: 7px;
  border: 1px solid var(--line); background: var(--bg); color: var(--ink);
}
input:focus, select:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
.row { display: flex; gap: 12px; }
.row > label { flex: 1; }
.msg { padding: 11px 14px; border-radius: 9px; margin-bottom: 16px; font-size: 14px;
       border: 1px solid var(--line); background: var(--panel); }
.msg.bad { color: var(--bad); border-color: currentColor; }
.msg.ok { color: var(--ok); border-color: currentColor; }
.keybox { background: var(--panel); border: 2px solid var(--ok); border-radius: 10px;
          padding: 16px; margin-bottom: 18px; }
.keybox .key { font-family: var(--mono); font-size: 17px; word-break: break-all;
               margin: 10px 0; user-select: all; }
.bar { height: 6px; border-radius: 999px; background: var(--line); overflow: hidden; max-width: 200px; }
.bar i { display: block; height: 100%; background: var(--ok); }
.bar.over i { background: var(--bad); }
.login { max-width: 380px; margin: 14vh auto; }
.btn.wide { display: block; width: 100%; padding: 11px; font-size: 14px; }
.or { display: flex; align-items: center; gap: 10px; color: var(--dim);
      font-size: 12.5px; margin: 18px 0; }
.or::before, .or::after { content: ''; flex: 1; height: 1px; background: var(--line); }
.empty { color: var(--dim); padding: 28px; text-align: center; background: var(--panel);
         border: 1px dashed var(--line); border-radius: 10px; }
.evt { font-family: var(--mono); font-size: 12.5px; padding: 5px 0;
       border-bottom: 1px solid var(--line); display: flex; gap: 12px; flex-wrap: wrap; }
.evt:last-child { border-bottom: none; }
.evt .w { color: var(--dim); white-space: nowrap; }
footer { color: var(--dim); font-size: 12.5px; padding: 0 20px 40px; max-width: 1080px; margin: 0 auto; }

/* toolbar: search, filter, sort, live */
.toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.toolbar input, .toolbar select { width: auto; flex: 0 1 auto; }
.toolbar input.search { flex: 1 1 220px; min-width: 0; }
.toolbar .live { display: flex; align-items: center; gap: 6px; color: var(--dim);
                 font-size: 13px; white-space: nowrap; }
.toolbar .live input { width: auto; flex: none; accent-color: var(--accent); }
.theme { display: inline-flex; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
.theme button { font: inherit; font-size: 12.5px; padding: 5px 9px; border: none; cursor: pointer;
                background: transparent; color: var(--dim); }
.theme button[aria-pressed="true"] { background: var(--accent); color: #fff; }
.stale { opacity: 0.55; }

/* Small screens. The licences table has six columns and cannot shrink into a
   phone, so below this width every row becomes a card and each cell labels
   itself from the data-label attribute the renderer sets. Nothing branches in
   JavaScript, which means the two layouts cannot drift apart. */
@media (max-width: 760px) {
  header { padding: 10px 14px; gap: 8px 10px; }
  /* The spacer exists to push the nav right on a wide screen. On a phone it
     forces a line break after the title and strands the buttons on rows of
     their own. */
  header .spacer { display: none; }
  header h1 { flex: 1 1 auto; }
  header .host { order: 3; flex-basis: 100%; }
  /* Wrap, do not scroll. A scrolling nav clipped "Products" mid-word with no
     visible affordance, which reads as a rendering bug rather than an
     invitation to swipe. */
  nav { order: 4; width: 100%; flex-wrap: wrap; }
  nav button { white-space: nowrap; }
  main { padding: 16px 14px 56px; }
  footer { padding: 0 14px 32px; }
  h2 { font-size: 18px; }
  .cards { grid-template-columns: repeat(auto-fit, minmax(126px, 1fr)); gap: 8px; }
  .card { padding: 11px 12px; }
  .card .n { font-size: 21px; }
  form { padding: 14px; }
  .row { flex-direction: column; gap: 0; }

  table, thead, tbody, tr, td { display: block; width: 100%; }
  thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  table { border: none; background: none; }
  tbody tr { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
             margin-bottom: 10px; padding: 4px 0; }
  /* Grid, not flex, and every child pinned to column two. With flex, a cell
     holding two elements — the customer name and its licence id, or the seat
     count and its bar — lays them out side by side against the label, and the
     name wraps to two lines while the id sits in the space it needed. */
  td { border-bottom: none; display: grid; grid-template-columns: 84px 1fr;
       gap: 2px 12px; align-items: baseline; padding: 5px 14px; }
  td::before {
    content: attr(data-label); color: var(--dim); font-size: 11.5px; text-transform: uppercase;
    letter-spacing: 0.05em; grid-column: 1; grid-row: 1;
  }
  td > * { grid-column: 2; min-width: 0; }
  /* Grid items stretch by default, which is right for the seat bar and wrong
     for a pill — a status tag as wide as the card stops reading as a tag. */
  td > .tag { justify-self: start; }
  td:empty { display: none; }
  .bar { max-width: none; }

  .panel dl, .machine dl { grid-template-columns: 1fr; gap: 0; }
  .panel dt, .machine dt { margin-top: 8px; font-size: 12px; text-transform: uppercase;
                           letter-spacing: 0.05em; }
  .machine .top { gap: 8px; }
  .machine .fp { flex-basis: 100%; order: 3; }
  .evt { flex-direction: column; gap: 2px; }
  .toolbar { gap: 6px; }
  .toolbar select, .toolbar input { flex: 1 1 130px; }
}
</style>
</head>
`

const BODY = `<body>
<div id="root"></div>
<script nonce="__NONCE__">
'use strict'

// ---- tiny DOM helpers. textContent only; see the note at the top of the file.
function el (tag, attrs, kids) {
  var node = document.createElement(tag)
  if (attrs) {
    for (var k in attrs) {
      if (k === 'class') node.className = attrs[k]
      else if (k === 'text') node.textContent = attrs[k]
      else if (k.slice(0, 2) === 'on') node.addEventListener(k.slice(2), attrs[k])
      // Styles go through the CSSOM, never through a style attribute. A CSP
      // nonce does not cover style attributes — only elements — so
      // setAttribute('style', ...) is refused under this page's policy and the
      // rule is dropped without anything throwing. The seat bars rendered at
      // zero width for exactly that reason until a browser said so.
      else if (k === 'styles') { for (var p in attrs[k]) node.style[p] = attrs[k][p] }
      else if (attrs[k] !== null && attrs[k] !== undefined) node.setAttribute(k, attrs[k])
    }
  }
  ;(kids || []).forEach(function (kid) {
    if (kid === null || kid === undefined || kid === false) return
    node.appendChild(typeof kid === 'string' ? document.createTextNode(kid) : kid)
  })
  return node
}
function clear (node) { while (node.firstChild) node.removeChild(node.firstChild) }

// ---- state
var state = {
  licenses: [], products: [], config: {}, msg: null, mintedKey: null, busy: false,
  query: '', product: '', sort: 'flagged', editing: false, timer: null, refreshedAt: 0
}
var root = document.getElementById('root')

// ---- preferences
//
// localStorage, not a cookie: none of this is worth sending to the server on
// every request, and the theme has to apply before the first paint of a page
// the server rendered without knowing who is looking at it.
function pref (key, value) {
  try {
    if (value === undefined) return window.localStorage.getItem('lg.' + key)
    window.localStorage.setItem('lg.' + key, value)
  } catch (e) { /* private browsing; defaults are fine */ }
  return value
}

function applyTheme (choice) {
  if (choice === 'light' || choice === 'dark') {
    document.documentElement.setAttribute('data-theme', choice)
  } else {
    // No attribute at all is the "system" state — prefers-color-scheme decides.
    document.documentElement.removeAttribute('data-theme')
  }
}
applyTheme(pref('theme') || 'system')

function themeSwitch () {
  var current = pref('theme') || 'system'
  var wrap = el('div', { class: 'theme', role: 'group', 'aria-label': 'Colour theme' })
  ;[['system', 'Auto'], ['light', 'Light'], ['dark', 'Dark']].forEach(function (pair) {
    wrap.appendChild(el('button', {
      type: 'button',
      text: pair[1],
      title: pair[0] === 'system' ? 'Follow the system setting' : pair[1],
      'aria-pressed': current === pair[0] ? 'true' : 'false',
      onclick: function () {
        pref('theme', pair[0])
        applyTheme(pair[0])
        render()
      }
    }))
  })
  return wrap
}

// ---- api
// A 401 anywhere means the session went away, so every call funnels back to
// the login form — except the login call itself, which answers 401 for the
// ordinary reason that the token was wrong. Without that exemption, logging in
// badly re-renders the page and throws away the error message you needed to
// read, which looks exactly like the button doing nothing.
function api (method, path, body, keepOn401) {
  var opts = {
    method: method,
    credentials: 'same-origin',
    headers: { 'x-lg-dashboard': '1' }
  }
  if (body !== undefined) {
    opts.headers['content-type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  return fetch(path, opts).then(function (res) {
    if (res.status === 401 && !keepOn401) {
      showLogin(); throw new Error('Session expired. Log in again.')
    }
    return res.text().then(function (text) {
      var data = null
      try { data = JSON.parse(text) } catch (e) { /* not json */ }
      if (!res.ok) throw new Error((data && (data.message || data.error)) || ('HTTP ' + res.status))
      return data
    })
  })
}

// ---- passkeys
//
// WebAuthn speaks ArrayBuffers and JSON does not, so every binary field is
// base64url on the wire and converted at the edge here. Nothing else in this
// page touches these two functions.
function b64uToBuf (value) {
  var padded = String(value).replace(/-/g, '+').replace(/_/g, '/')
  var binary = atob(padded + '='.repeat((4 - padded.length % 4) % 4))
  var bytes = new Uint8Array(binary.length)
  for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}
function bufToB64u (buffer) {
  var bytes = new Uint8Array(buffer)
  var binary = ''
  for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  // Doubled backslashes on purpose: this whole page is one template literal,
  // and a singly-escaped character class collapses on the way out into a regex
  // the browser refuses to parse. See the dashboard parse test.
  return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '')
}

function passkeysSupported () {
  return typeof window.PublicKeyCredential === 'function' &&
    Boolean(navigator.credentials) && Boolean(navigator.credentials.create)
}

// A cancelled Face ID prompt throws the same NotAllowedError as a real
// failure, and "not allowed" is a poor thing to show someone who simply
// changed their mind.
function passkeyError (err) {
  if (err && err.name === 'NotAllowedError') return 'Passkey prompt was dismissed.'
  if (err && err.name === 'InvalidStateError') return 'This device already has a passkey registered here.'
  return (err && err.message) || 'The passkey could not be used.'
}

function passkeyLogin () {
  return api('POST', '/v1/admin/passkey/challenge', {}, true).then(function (opts) {
    return navigator.credentials.get({
      publicKey: {
        challenge: b64uToBuf(opts.challenge),
        rpId: opts.rpId,
        userVerification: opts.userVerification,
        timeout: opts.timeout
      }
    })
  }).then(function (cred) {
    if (!cred) throw new Error('No passkey was returned.')
    return api('POST', '/v1/admin/passkey/session', {
      credential: {
        id: cred.id,
        type: cred.type,
        response: {
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
          authenticatorData: bufToB64u(cred.response.authenticatorData),
          signature: bufToB64u(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
        }
      }
    }, true)
  })
}

function passkeyRegister (label) {
  return api('POST', '/v1/admin/passkeys/challenge', {}).then(function (opts) {
    return navigator.credentials.create({
      publicKey: {
        challenge: b64uToBuf(opts.challenge),
        rp: opts.rp,
        user: {
          id: b64uToBuf(opts.user.id),
          name: opts.user.name,
          displayName: opts.user.displayName
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        authenticatorSelection: opts.authenticatorSelection,
        attestation: opts.attestation,
        timeout: opts.timeout,
        excludeCredentials: (opts.excludeCredentials || []).map(function (c) {
          return { type: c.type, id: b64uToBuf(c.id) }
        })
      }
    })
  }).then(function (cred) {
    if (!cred) throw new Error('No passkey was created.')
    return api('POST', '/v1/admin/passkeys', {
      label: label,
      credential: {
        id: cred.id,
        type: cred.type,
        response: {
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
          attestationObject: bufToB64u(cred.response.attestationObject)
        }
      }
    })
  })
}

// ---- formatting
function ago (seconds) {
  if (!seconds) return 'never'
  var n = Math.abs(Math.floor(Date.now() / 1000) - seconds)
  if (n < 90) return n + 's ago'
  if (n < 5400) return Math.round(n / 60) + 'm ago'
  if (n < 172800) return Math.round(n / 3600) + 'h ago'
  return Math.round(n / 86400) + 'd ago'
}
function stamp (seconds) {
  if (!seconds) return '—'
  return new Date(seconds * 1000).toISOString().replace('T', ' ').slice(0, 16) + 'Z'
}
function when (seconds) { return seconds ? stamp(seconds) + '  (' + ago(seconds) + ')' : '—' }

// The same rule the seat check uses. A dashboard that disagrees with the
// server about whether a machine still holds a seat is worse than none.
function machineState (row) {
  if (row.released_at) return { label: 'released', cls: '', mark: '-' }
  var age = Math.floor(Date.now() / 1000) - row.last_seen
  var stale = row.ephemeral ? state.config.ephemeralStaleSeconds : state.config.staleSeconds
  if (age > stale) return { label: 'stale, seat freed', cls: 'warn', mark: '!' }
  if (age > state.config.heartbeatSeconds * 2) return { label: 'quiet', cls: 'warn', mark: '!' }
  return { label: 'healthy', cls: 'ok', mark: '*' }
}

// ---- chrome
function shell (view, body) {
  clear(root)
  var nav = el('nav', null, [
    navButton('Overview', '#/', view === 'overview'),
    navButton('Sharing', '#/sharing', view === 'sharing'),
    navButton('New licence', '#/new', view === 'new'),
    navButton('Products', '#/products', view === 'products'),
    navButton('Passkeys', '#/passkeys', view === 'passkeys')
  ])
  root.appendChild(el('header', null, [
    el('h1', { text: 'license-guard' }),
    el('span', { class: 'host', text: location.host }),
    el('span', { class: 'spacer' }),
    nav,
    themeSwitch(),
    el('button', {
      class: 'btn',
      onclick: function () {
        stopLive()
        api('DELETE', '/v1/admin/session').then(showLogin).catch(function () { showLogin() })
      },
      text: 'Log out'
    })
  ]))
  var main = el('main')
  if (state.msg) {
    main.appendChild(el('div', { class: 'msg ' + state.msg.kind, text: state.msg.text }))
    state.msg = null
  }
  body.forEach(function (n) { main.appendChild(n) })
  root.appendChild(main)
  root.appendChild(el('footer', null, [
    'Seats count distinct deployments. A seat frees itself after ' +
    Math.round((state.config.staleSeconds || 0) / 86400) + ' days without a check-in (' +
    Math.round((state.config.ephemeralStaleSeconds || 0) / 3600) + 'h for an ephemeral id).'
  ]))
}

function navButton (label, hash, current) {
  return el('button', {
    text: label,
    'aria-current': current ? 'page' : null,
    onclick: function () { location.hash = hash }
  })
}

// ---- login
function showLogin (message) {
  clear(root)
  var input = el('input', { type: 'password', autocomplete: 'current-password', autofocus: 'true' })
  var note = el('div', { class: 'msg bad', text: message || '' })
  var form = el('form', {
    onsubmit: function (event) {
      event.preventDefault()
      note.textContent = ''
      api('POST', '/v1/admin/session', { token: input.value }, true)
        .then(function () { input.value = ''; route() })
        .catch(function (err) { note.textContent = err.message })
    }
  }, [
    el('label', null, [el('span', { text: 'Admin token' }), input]),
    message ? note : note,
    el('button', { class: 'btn primary', type: 'submit', text: 'Log in' })
  ])
  // The passkey button comes first because it is the way in that does not
  // involve a secret being pasted anywhere. The token form stays below it: it
  // is the only way to register the first passkey, and the only way back in
  // when the device holding the passkey is gone.
  var passkeyButton = el('button', {
    class: 'btn primary wide',
    type: 'button',
    text: 'Sign in with a passkey',
    onclick: function () {
      note.textContent = ''
      passkeyButton.disabled = true
      passkeyButton.textContent = 'Waiting for your device…'
      passkeyLogin()
        .then(function () { route() })
        .catch(function (err) {
          passkeyButton.disabled = false
          passkeyButton.textContent = 'Sign in with a passkey'
          note.textContent = passkeyError(err)
        })
    }
  })

  root.appendChild(el('main', { class: 'login' }, [
    el('h2', { text: 'license-guard' }),
    passkeysSupported() ? passkeyButton : null,
    passkeysSupported() ? el('div', { class: 'or', text: 'or' }) : null,
    el('p', { class: 'lede', text: 'The token is exchanged for a session cookie and is not stored in this page.' }),
    form
  ]))
  if (!passkeysSupported()) input.focus()
}

// ---- overview
function isFlagged (l) {
  return Boolean(l.overSeats || l.countries > 1 || l.networks > Math.max(1, l.seats))
}

function matches (l, query) {
  if (!query) return true
  var hay = (l.customer + ' ' + l.id + ' ' + l.product_id + ' ' + (l.email || '') + ' ' +
    (l.plan || '') + ' ' + (l.features || []).join(' ')).toLowerCase()
  // Every word has to appear somewhere, in any order. "north bank" finds
  // Northwind Bank; a single substring match would not.
  return query.toLowerCase().split(/\\s+/).filter(Boolean).every(function (word) {
    return hay.indexOf(word) !== -1
  })
}

var SORTS = {
  flagged: function (a, b) { return (isFlagged(b) - isFlagged(a)) || b.live - a.live },
  customer: function (a, b) { return String(a.customer).localeCompare(String(b.customer)) },
  seats: function (a, b) { return b.live - a.live || b.seats - a.seats },
  networks: function (a, b) { return (b.networks || 0) - (a.networks || 0) },
  seen: function (a, b) { return (b.last_seen || 0) - (a.last_seen || 0) }
}

function viewOverview () {
  var live = 0, seats = 0, flagged = 0
  state.licenses.forEach(function (l) {
    live += l.live
    seats += l.seats
    if (isFlagged(l)) flagged++
  })

  var cards = el('div', { class: 'cards' }, [
    card(String(state.licenses.length), 'licences'),
    card(String(live), 'live deployments'),
    card(live + ' / ' + seats, 'seats in use'),
    card(String(flagged), 'need a look', flagged > 0)
  ])

  var shown = state.licenses
    .filter(function (l) { return !state.product || l.product_id === state.product })
    .filter(function (l) { return matches(l, state.query) })
    .slice()
    .sort(SORTS[state.sort] || SORTS.flagged)

  var search = el('input', {
    class: 'search', type: 'search', 'data-focus': 'search',
    placeholder: 'Search customer, licence, product…', value: state.query,
    'aria-label': 'Search licences'
  })
  search.addEventListener('input', function () { state.query = search.value; render() })

  var productFilter = el('select', { 'data-focus': 'product', 'aria-label': 'Filter by product' },
    [el('option', { value: '', text: 'All products' })].concat(
      state.products.map(function (p) {
        return el('option', { value: p.id, text: p.name || p.id })
      })))
  productFilter.value = state.product
  productFilter.addEventListener('change', function () {
    state.product = productFilter.value
    render()
  })

  var sort = el('select', { 'data-focus': 'sort', 'aria-label': 'Sort licences' }, [
    el('option', { value: 'flagged', text: 'Needs a look first' }),
    el('option', { value: 'seats', text: 'Most seats used' }),
    el('option', { value: 'networks', text: 'Most networks' }),
    el('option', { value: 'seen', text: 'Most recently seen' }),
    el('option', { value: 'customer', text: 'Customer A–Z' })
  ])
  sort.value = state.sort
  sort.addEventListener('change', function () { state.sort = sort.value; render() })

  var rows = shown.map(function (l) {
    var pct = l.seats ? Math.min(100, Math.round((l.live / l.seats) * 100)) : 0
    return el('tr', {
      class: 'click',
      onclick: function () { location.hash = '#/licence/' + l.id }
    }, [
      el('td', { 'data-label': 'Customer' }, [
        el('div', { text: l.customer }),
        el('div', { class: 'mono dim', text: l.id })
      ]),
      el('td', { class: 'mono', 'data-label': 'Product', text: l.product_id }),
      el('td', { 'data-label': 'Seats' }, [
        el('div', { text: l.live + ' / ' + l.seats }),
        el('div', { class: 'bar' + (l.overSeats ? ' over' : '') }, [
          el('i', { styles: { width: pct + '%' } })
        ])
      ]),
      el('td', { 'data-label': 'Networks', text: String(l.networks || 0) }),
      el('td', { 'data-label': 'Last seen', text: ago(l.last_seen) }),
      el('td', { 'data-label': 'Status' }, [statusTag(l)])
    ])
  })

  shell('overview', [
    el('h2', { text: 'Customers' }),
    el('p', { class: 'lede', text: 'Every licence, with seats counted the way the server counts them.' }),
    cards,
    el('h3', { text: 'Licences' }),
    state.licenses.length
      ? el('div', { class: 'toolbar' }, [search, productFilter, sort, liveToggle()])
      : null,
    state.licenses.length === 0
      ? el('div', { class: 'empty', text: 'No licences yet. Register a product, then mint one.' })
      : rows.length === 0
        ? el('div', { class: 'empty', text: 'Nothing matches that.' })
        : el('table', null, [
          el('thead', null, [el('tr', null, [
            el('th', { text: 'Customer' }), el('th', { text: 'Product' }),
            el('th', { text: 'Seats' }), el('th', { text: 'Networks' }),
            el('th', { text: 'Last seen' }), el('th', { text: 'Status' })
          ])]),
          el('tbody', null, rows)
        ]),
    rows.length && rows.length !== state.licenses.length
      ? el('p', { class: 'lede', text: 'Showing ' + rows.length + ' of ' + state.licenses.length + '.' })
      : null
  ].filter(Boolean))
}

// ---- sharing
function viewSharing () {
  if (!state.report) {
    api('GET', '/v1/admin/report?days=30')
      .then(function (data) { state.report = data; render() })
      .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; viewOverview() })
    shell('sharing', [el('h2', { text: 'Sharing' }), el('div', { class: 'empty', text: 'Loading…' })])
    return
  }

  var rows = (state.report.licenses || []).slice().sort(function (a, b) {
    return (b.networks || 0) - (a.networks || 0) || (b.instances || 0) - (a.instances || 0)
  })
  var flagged = rows.filter(function (r) { return r.sharingSuspected || r.overSeats })

  shell('sharing', [
    el('h2', { text: 'Sharing' }),
    el('p', { class: 'lede', text: 'Sort on networks, not on instances. Two deployments in one ' +
      'datacentre is a customer who grew. Three instances on three networks in three countries, ' +
      'sold to one company, is a key doing the rounds.' }),
    el('div', { class: 'toolbar' }, [liveToggle()]),
    flagged.length
      ? el('div', { class: 'msg bad', text: flagged.length + ' of ' + rows.length +
        ' licences are worth a look.' })
      : el('div', { class: 'msg ok', text: 'Nothing flagged in the last ' +
        state.report.windowDays + ' days.' }),
    rows.length
      ? el('table', null, [
        el('thead', null, [el('tr', null, [
          el('th', { text: 'Customer' }), el('th', { text: 'Seats' }), el('th', { text: 'Live' }),
          el('th', { text: 'Networks' }), el('th', { text: 'Countries' }), el('th', { text: 'Signal' })
        ])]),
        el('tbody', null, rows.map(function (r) {
          return el('tr', {
            class: 'click' + (r.sharingSuspected || r.overSeats ? '' : ' stale'),
            onclick: function () { location.hash = '#/licence/' + r.id }
          }, [
            el('td', { 'data-label': 'Customer' }, [
              el('div', { text: r.customer }),
              el('div', { class: 'mono dim', text: r.id })
            ]),
            el('td', { 'data-label': 'Seats', text: String(r.seats) }),
            el('td', { 'data-label': 'Live', text: String(r.instances || 0) }),
            el('td', { 'data-label': 'Networks', text: String(r.networks || 0) }),
            el('td', { 'data-label': 'Countries', text: String(r.countries || 0) }),
            el('td', { 'data-label': 'Signal' }, [
              r.overSeats
                ? el('span', { class: 'tag bad', text: 'over seats' })
                : r.sharingSuspected
                  ? el('span', { class: 'tag warn', text: 'sharing suspected' })
                  : el('span', { class: 'tag ok', text: 'as expected' })
            ])
          ])
        }))
      ])
      : el('div', { class: 'empty', text: 'No licences yet.' }),
    el('p', { class: 'lede', text: 'This is the only sharing detection that reliably works. ' +
      'Someone who strips the guard and runs one quiet copy is invisible here and always will be.' })
  ])
}

function card (n, k, flag) {
  return el('div', { class: 'card' + (flag ? ' flag' : '') }, [
    el('div', { class: 'n', text: n }), el('div', { class: 'k', text: k })
  ])
}

function statusTag (l) {
  if (l.status !== 'active') return el('span', { class: 'tag bad', text: l.status })
  if (l.expires_at && l.expires_at < Math.floor(Date.now() / 1000)) {
    return el('span', { class: 'tag bad', text: 'expired' })
  }
  if (l.overSeats) return el('span', { class: 'tag bad', text: 'over seats' })
  if (l.countries > 1) return el('span', { class: 'tag warn', text: 'multi-country' })
  if (l.networks > Math.max(1, l.seats)) return el('span', { class: 'tag warn', text: 'many networks' })
  return el('span', { class: 'tag ok', text: 'active' })
}

// ---- one customer
function viewLicence (id) {
  var licence = null
  state.licenses.forEach(function (l) { if (l.id === id) licence = l })
  if (!licence) { location.hash = '#/'; return }

  api('GET', '/v1/admin/deployments?license=' + encodeURIComponent(id) + '&limit=300')
    .then(function (data) {
      state.detail = { id: id, data: data }
      renderLicence(licence, data)
    })
    .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; shell('overview', []) })
}

/**
 * Edit the things that legitimately change over a licence's life.
 *
 * Not the key — only its hash was kept, so there is nothing to change it to.
 * Not the watermark — it is stamped into artefacts the customer has already
 * produced, and matching those next year is the entire reason it exists.
 */
function editForm (l) {
  var customer = el('input', { value: l.customer, required: 'true' })
  var email = el('input', { type: 'email', value: l.email || '' })
  var seats = el('input', { type: 'number', min: '1', step: '1', value: String(l.seats) })
  var plan = el('input', { value: l.plan || '' })
  var features = el('input', { value: (l.features || []).join(', ') })
  var expires = el('input', {
    type: 'date',
    value: l.expires_at ? new Date(l.expires_at * 1000).toISOString().slice(0, 10) : ''
  })
  var notes = el('input', { value: l.notes || '' })
  var save = el('button', { class: 'btn primary', type: 'submit', text: 'Save changes' })

  return el('form', {
    onsubmit: function (event) {
      event.preventDefault()
      save.disabled = true
      api('PATCH', '/v1/admin/licenses', {
        id: l.id,
        customer: customer.value.trim(),
        email: email.value.trim() || null,
        seats: Number(seats.value),
        plan: plan.value.trim(),
        features: features.value.split(',').map(function (f) { return f.trim() }).filter(Boolean),
        // A date input gives midnight UTC on that day; the licence should be
        // good for all of it, so expiry lands at the end.
        expiresAt: expires.value ? Math.floor(Date.parse(expires.value) / 1000) + 86399 : null,
        notes: notes.value.trim() || null
      }).then(function (data) {
        state.editing = false
        state.msg = data.changed.length
          ? { kind: 'ok', text: 'Updated ' + data.changed.join(', ') + '.' +
              (data.notice ? ' ' + data.notice : '') }
          : { kind: 'ok', text: 'Nothing changed.' }
        return load()
      }).then(function () { render() })
        .catch(function (err) {
          save.disabled = false
          state.msg = { kind: 'bad', text: err.message }
          render()
        })
    }
  }, [
    el('label', null, [el('span', { text: 'Customer' }), customer]),
    el('label', null, [el('span', { text: 'Email' }), email]),
    el('div', { class: 'row' }, [
      el('label', null, [el('span', { text: 'Seats' }), seats]),
      el('label', null, [el('span', { text: 'Plan' }), plan])
    ]),
    el('label', null, [el('span', { text: 'Features, comma separated' }), features]),
    el('label', null, [el('span', { text: 'Expires (blank = never)' }), expires]),
    el('label', null, [el('span', { text: 'Notes' }), notes]),
    el('div', { class: 'toolbar' }, [
      save,
      el('button', {
        class: 'btn', type: 'button', text: 'Cancel',
        onclick: function () { state.editing = false; render() }
      })
    ])
  ])
}

function renderLicence (l, data) {
  var facts = el('dl', null, [])
  ;[
    ['Licence', l.id], ['Product', l.product_id], ['Plan', l.plan],
    ['Features', l.features.length ? l.features.join(', ') : 'none'],
    ['Watermark', l.watermark], ['Email', l.email || '—'],
    ['Expires', l.expires_at ? stamp(l.expires_at) : 'never'],
    ['Created', stamp(l.created_at)], ['Notes', l.notes || '—']
  ].forEach(function (pair) {
    facts.appendChild(el('dt', { text: pair[0] }))
    facts.appendChild(el('dd', { class: 'mono', text: String(pair[1]) }))
  })

  var machines = (data.instances || []).map(function (row) {
    var st = machineState(row)
    var dl = el('dl', null, [])
    ;[
      ['host', [row.hostname || '(not reported)',
        row.platform ? row.platform + '/' + row.arch : null,
        row.container ? 'in ' + row.container : null].filter(Boolean).join('   ')],
      ['running', (row.app_version || 'unknown') +
        (row.node_version ? '   on node ' + row.node_version : '') +
        (row.ephemeral ? '   ephemeral id' : '')],
      ['first seen', when(row.first_seen)],
      ['last seen', when(row.last_seen)],
      ['activations', String(row.activations)],
      ['network', [row.asn ? 'AS' + row.asn + (row.as_org ? ' ' + row.as_org : '') : null,
        row.country, row.colo ? 'via ' + row.colo : null,
        row.ip_hash ? 'ip ' + String(row.ip_hash).slice(0, 8) : null].filter(Boolean).join('   ') ||
        '(not recorded)'],
      row.released_at ? ['released', when(row.released_at)] : null
    ].filter(Boolean).forEach(function (pair) {
      dl.appendChild(el('dt', { text: pair[0] }))
      dl.appendChild(el('dd', { text: pair[1] }))
    })

    return el('div', { class: 'machine' }, [
      el('div', { class: 'top' }, [
        el('span', { class: 'tag ' + st.cls, text: st.label }),
        el('span', { class: 'fp', text: row.fingerprint }),
        el('span', { class: 'grow' }),
        row.released_at
          ? null
          : el('button', {
            class: 'btn danger', text: 'Release seat',
            onclick: function () { releaseSeat(row.id, l.id) }
          })
      ]),
      dl
    ])
  })

  var seen = {}
  ;(data.instances || []).forEach(function (row) { seen[row.fingerprint] = true })
  var refused = (data.events || []).filter(function (e) {
    return e.outcome === 'denied' && !seen[e.fingerprint]
  })

  shell('overview', [
    el('h2', { text: l.customer }),
    el('p', { class: 'lede', text: l.live + ' of ' + l.seats + ' seats in use' +
      (l.overSeats ? ' — over the limit' : '') }),
    el('div', { class: 'toolbar' }, [
      el('button', { class: 'btn', text: '← All customers', onclick: function () { location.hash = '#/' } }),
      el('button', {
        class: 'btn', text: state.editing ? 'Stop editing' : 'Edit licence',
        onclick: function () { state.editing = !state.editing; render() }
      }),
      l.status === 'active'
        ? el('button', { class: 'btn danger', text: 'Revoke licence', onclick: function () { revoke(l) } })
        : el('button', {
          class: 'btn', text: 'Reactivate',
          onclick: function () { setStatus(l, 'active') }
        }),
      liveToggle()
    ].filter(Boolean)),
    el('h3', { text: 'Licence' }),
    state.editing ? editForm(l) : el('div', { class: 'panel' }, [facts]),
    el('h3', { text: 'Machines (' + machines.length + ')' }),
    machines.length ? el('div', null, machines)
      : el('div', { class: 'empty', text: 'Nothing has activated on this licence yet.' }),
    refused.length ? el('h3', { text: 'Refused (' + refused.length + ')' }) : null,
    refused.length ? el('div', { class: 'panel' }, refused.slice(0, 20).map(function (e) {
      return el('div', { class: 'evt' }, [
        el('span', { class: 'w', text: stamp(e.at) }),
        el('span', { text: e.kind + ' ' + (e.detail || e.outcome) }),
        el('span', { class: 'dim', text: e.fingerprint || '(no fingerprint sent)' })
      ])
    })) : null,
    el('h3', { text: 'Recent events' }),
    el('div', { class: 'panel' }, ((data.events || []).slice(0, 40).map(function (e) {
      return el('div', { class: 'evt' }, [
        el('span', { class: 'w', text: stamp(e.at) }),
        el('span', { text: e.kind + ' ' + e.outcome }),
        el('span', { class: 'dim', text: e.detail || '' })
      ])
    })))
  ].filter(Boolean))
}

function releaseSeat (instanceId, licenceId) {
  api('POST', '/v1/admin/release', { instanceId: instanceId })
    .then(function () {
      state.msg = { kind: 'ok', text: 'Seat released. It is free immediately.' }
      return load()
    })
    .then(function () { viewLicence(licenceId) })
    .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; viewLicence(licenceId) })
}

function revoke (l) {
  if (!window.confirm('Revoke ' + l.customer + '? Every activation and heartbeat is refused ' +
    'from now on. Tokens already issued keep working until they expire, up to ' +
    Math.round((state.config.tokenTtlSeconds || 0) / 86400) + ' days.')) return
  api('POST', '/v1/admin/revoke', { id: l.id, status: 'revoked' })
    .then(function () {
      state.msg = { kind: 'ok', text: l.customer + ' is revoked.' }
      return load()
    })
    .then(function () { location.hash = '#/' ; route() })
    .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; route() })
}

function setStatus (l, status) {
  api('PATCH', '/v1/admin/licenses', { id: l.id, status: status })
    .then(function () {
      state.msg = { kind: 'ok', text: l.customer + ' is ' + status + ' again.' }
      return load()
    })
    .then(function () { render() })
    .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; render() })
}

// ---- new licence
function viewNew () {
  if (!state.products.length) {
    shell('new', [
      el('h2', { text: 'New licence' }),
      el('div', { class: 'empty', text: 'Register a product first — a licence has to belong to one.' }),
      el('p', null, [el('button', { class: 'btn primary', text: 'Go to products',
        onclick: function () { location.hash = '#/products' } })])
    ])
    return
  }

  var product = el('select', null, state.products.map(function (p) {
    return el('option', { value: p.id, text: p.name ? p.name + '  (' + p.id + ')' : p.id })
  }))
  var customer = el('input', { required: 'true', placeholder: 'Northwind Bank' })
  var email = el('input', { type: 'email', placeholder: 'ops@northwind.example' })
  var seats = el('input', { type: 'number', min: '1', step: '1', value: '1', required: 'true' })
  var plan = el('input', { value: 'standard' })
  var features = el('input', { placeholder: 'reports, sso' })
  var days = el('input', { type: 'number', min: '1', step: '1', placeholder: 'never' })
  var submit = el('button', { class: 'btn primary', type: 'submit', text: 'Mint licence' })

  var body = []
  if (state.mintedKey) {
    var k = state.mintedKey
    state.mintedKey = null
    body.push(el('div', { class: 'keybox' }, [
      el('div', { text: 'Licence for ' + k.customer }),
      el('div', { class: 'key', text: k.licenseKey }),
      el('div', { class: 'dim', text: 'Shown once. Only the SHA-256 is stored, so there is no ' +
        'way to show it again — copy it now and send it to the customer.' }),
      el('div', { class: 'gap' }, [
        el('button', { class: 'btn', text: 'Copy key', onclick: function (e) {
          navigator.clipboard.writeText(k.licenseKey).then(function () {
            e.target.textContent = 'Copied'
          })
        } }),
        ' ',
        el('button', { class: 'btn', text: 'Open customer',
          onclick: function () { location.hash = '#/licence/' + k.id } })
      ])
    ]))
  }

  body.push(el('h2', { text: 'New licence' }))
  body.push(el('p', { class: 'lede', text: 'Seats count distinct deployments, not users.' }))
  body.push(el('form', {
    onsubmit: function (event) {
      event.preventDefault()
      submit.disabled = true
      api('POST', '/v1/admin/licenses', {
        product: product.value,
        customer: customer.value.trim(),
        email: email.value.trim() || null,
        seats: Number(seats.value),
        plan: plan.value.trim() || 'standard',
        features: features.value.split(',').map(function (f) { return f.trim() }).filter(Boolean),
        expiresAt: days.value
          ? Math.floor(Date.now() / 1000) + Math.round(Number(days.value) * 86400)
          : null
      }).then(function (data) {
        state.mintedKey = { licenseKey: data.licenseKey, id: data.id, customer: customer.value.trim() }
        return load()
      }).then(function () { viewNew() })
        .catch(function (err) {
          submit.disabled = false
          state.msg = { kind: 'bad', text: err.message }
          viewNew()
        })
    }
  }, [
    el('label', null, [el('span', { text: 'Product' }), product]),
    el('label', null, [el('span', { text: 'Customer' }), customer]),
    el('label', null, [el('span', { text: 'Email (optional)' }), email]),
    el('div', { class: 'row' }, [
      el('label', null, [el('span', { text: 'Seats' }), seats]),
      el('label', null, [el('span', { text: 'Plan' }), plan])
    ]),
    el('label', null, [el('span', { text: 'Features, comma separated' }), features]),
    el('label', null, [el('span', { text: 'Expires in days (blank = never)' }), days]),
    submit
  ]))

  shell('new', body)
}

// ---- products
function viewProducts () {
  var id = el('input', { required: 'true', placeholder: 'acme-core' })
  var name = el('input', { placeholder: 'Acme Core' })
  var coreKey = el('input', { placeholder: 'blank = generate a new one' })

  var rows = state.products.map(function (p) {
    // The list this row came from no longer carries the key, so revealing one
    // is a round trip. That is the point: the key reaches this page only for
    // the product someone actually clicked, and the server records that it did.
    var reveal = el('button', { class: 'btn', text: 'Reveal core key', onclick: function (e) {
      var btn = e.target
      btn.disabled = true
      btn.textContent = 'Revealing…'
      api('POST', '/v1/admin/products/key', { id: p.id })
        .then(function (data) {
          btn.replaceWith(el('span', { class: 'mono', text: data.coreKey }))
        })
        .catch(function (err) {
          state.msg = { kind: 'bad', text: err.message }
          viewProducts()
        })
    } })
    return el('tr', null, [
      el('td', { class: 'mono', text: p.id }),
      el('td', { text: p.name || '' }),
      el('td', { text: String(p.licenses) }),
      el('td', { text: stamp(p.created_at) }),
      el('td', null, [reveal])
    ])
  })

  shell('products', [
    el('h2', { text: 'Products' }),
    el('p', { class: 'lede', text: 'A product owns the AES key its .lgc builds are packed with. ' +
      'Every licensed deployment of it receives that key on activation.' }),
    state.products.length
      ? el('table', null, [
        el('thead', null, [el('tr', null, [
          el('th', { text: 'Id' }), el('th', { text: 'Name' }), el('th', { text: 'Licences' }),
          el('th', { text: 'Created' }), el('th', { text: 'Core key' })
        ])]),
        el('tbody', null, rows)
      ])
      : el('div', { class: 'empty', text: 'No products yet.' }),
    el('h3', { text: 'Register or update' }),
    el('form', {
      onsubmit: function (event) {
        event.preventDefault()
        api('POST', '/v1/admin/products', {
          id: id.value.trim(),
          name: name.value.trim() || id.value.trim(),
          coreKey: coreKey.value.trim() || undefined
        }).then(function () {
          state.msg = { kind: 'ok', text: 'Saved. Pack your core with this product\\'s key.' }
          return load()
        }).then(viewProducts)
          .catch(function (err) { state.msg = { kind: 'bad', text: err.message }; viewProducts() })
      }
    }, [
      el('label', null, [el('span', { text: 'Id, as passed to protect({ product })' }), id]),
      el('label', null, [el('span', { text: 'Name' }), name]),
      el('label', null, [el('span', { text: 'Core key, base64 AES-256' }), coreKey]),
      el('button', { class: 'btn primary', type: 'submit', text: 'Save product' })
    ])
  ])
}

// ---- passkeys view
//
// This view fetches its own list rather than joining load(). Passkeys change
// about once a year; making every page load ask for them would be three extra
// round trips a minute to watch a table that never moves.
function viewPasskeys () {
  api('GET', '/v1/admin/passkeys').then(function (data) {
    renderPasskeys(data.passkeys || [])
  }).catch(function (err) {
    state.msg = { kind: 'bad', text: err.message }
    renderPasskeys([])
  })
}

function renderPasskeys (passkeys) {
  var label = el('input', { placeholder: "This MacBook, Milon's iPhone…" })

  var register = el('button', {
    class: 'btn primary',
    type: 'submit',
    text: 'Register this device'
  })

  var rows = passkeys.map(function (k) {
    return el('tr', null, [
      el('td', { text: k.label || '—' }),
      el('td', { text: k.alg === -7 ? 'ES256' : k.alg === -257 ? 'RS256' : String(k.alg) }),
      el('td', { text: stamp(k.created_at) }),
      el('td', { text: k.last_used_at ? when(k.last_used_at) : 'never' }),
      el('td', null, [el('button', {
        class: 'btn danger',
        text: 'Remove',
        onclick: function () {
          api('DELETE', '/v1/admin/passkeys', { id: k.id }).then(function () {
            state.msg = { kind: 'ok', text: 'Passkey removed.' }
            viewPasskeys()
          }).catch(function (err) {
            state.msg = { kind: 'bad', text: err.message }
            viewPasskeys()
          })
        }
      })])
    ])
  })

  shell('passkeys', [
    el('h2', { text: 'Passkeys' }),
    el('p', { class: 'lede', text: 'A passkey signs a challenge from this server with a key that never ' +
      'leaves your device. Registering one needs the admin token, which is also what gets you back in ' +
      'if every registered device is lost — so keep it somewhere you can still reach.' }),
    passkeys.length
      ? el('table', null, [
        el('thead', null, [el('tr', null, [
          el('th', { text: 'Device' }), el('th', { text: 'Algorithm' }), el('th', { text: 'Registered' }),
          el('th', { text: 'Last used' }), el('th', { text: '' })
        ])]),
        el('tbody', null, rows)
      ])
      : el('div', { class: 'empty', text: 'No passkeys yet. Register this device to stop pasting the token.' }),
    passkeysSupported()
      ? el('form', {
        onsubmit: function (event) {
          event.preventDefault()
          register.disabled = true
          register.textContent = 'Waiting for your device…'
          passkeyRegister(label.value.trim())
            .then(function () {
              state.msg = { kind: 'ok', text: 'Passkey registered. It will be offered at the next sign-in.' }
              viewPasskeys()
            })
            .catch(function (err) {
              register.disabled = false
              register.textContent = 'Register this device'
              state.msg = { kind: 'bad', text: passkeyError(err) }
              viewPasskeys()
            })
        }
      }, [
        el('h3', { text: 'Register a device' }),
        el('label', null, [el('span', { text: 'Name it, so you know which one to remove later' }), label]),
        register
      ])
      : el('div', { class: 'msg bad', text: 'This browser does not support WebAuthn, so no passkey can be registered here.' })
  ])
}

// ---- routing
function load () {
  return Promise.all([
    api('GET', '/v1/admin/licenses'),
    api('GET', '/v1/admin/products')
  ]).then(function (both) {
    state.licenses = both[0].licenses
    state.config = both[0].config
    state.products = both[1].products
    state.refreshedAt = Math.floor(Date.now() / 1000)
  })
}

function findLicence (id) {
  var found = null
  state.licenses.forEach(function (l) { if (l.id === id) found = l })
  return found
}

/**
 * Draw the current route from state already in hand.
 *
 * Split from route() so a filter keystroke, a theme click or a live refresh can
 * redraw without a round trip. Focus is carried across the redraw by a
 * data-focus key, because the search box redraws the page on every character
 * and a search box that loses the caret after one letter is not a search box.
 */
function render () {
  var active = document.activeElement
  var key = active && active.getAttribute ? active.getAttribute('data-focus') : null
  var start = key && active.selectionStart
  var end = key && active.selectionEnd

  var hash = location.hash || '#/'
  if (hash.indexOf('#/licence/') === 0) {
    var id = hash.slice('#/licence/'.length)
    var licence = findLicence(id)
    if (!licence) { location.hash = '#/'; return }
    if (state.detail && state.detail.id === id) renderLicence(licence, state.detail.data)
    else { viewLicence(id); return }
  } else if (hash === '#/sharing') viewSharing()
  else if (hash === '#/new') viewNew()
  else if (hash === '#/products') viewProducts()
  else if (hash === '#/passkeys') viewPasskeys()
  else viewOverview()

  if (key) {
    var next = document.querySelector('[data-focus="' + key + '"]')
    if (next) {
      next.focus()
      if (start !== null && start !== undefined && next.setSelectionRange) {
        try { next.setSelectionRange(start, end) } catch (e) { /* not a text input */ }
      }
    }
  }
}

function route () {
  state.detail = null
  state.editing = false
  load().then(render).catch(function (err) {
    if (err.message.indexOf('Session') !== 0) {
      clear(root)
      root.appendChild(el('main', null, [el('div', { class: 'msg bad', text: err.message })]))
    }
  })
}

// ---- live refresh
//
// Only the two views that show moving data refresh themselves. Redrawing a form
// underneath someone as they fill it in would be actively hostile, so New
// licence, Products and Passkeys are left alone.
function liveable () {
  var hash = location.hash || '#/'
  return hash === '#/' || hash === '#/sharing' || hash.indexOf('#/licence/') === 0
}

function startLive () {
  stopLive()
  if (!liveable()) return
  state.timer = window.setInterval(function () {
    if (!liveable()) { stopLive(); return }
    var detailId = state.detail && state.detail.id
    load()
      .then(function () {
        if (!detailId) return null
        return api('GET', '/v1/admin/deployments?license=' + encodeURIComponent(detailId) + '&limit=300')
          .then(function (data) { state.detail = { id: detailId, data: data } })
      })
      .then(function () {
        if (state.report) return api('GET', '/v1/admin/report?days=30')
          .then(function (data) { state.report = data })
      })
      .then(render)
      .catch(function () { stopLive() })
  }, 30000)
}

function stopLive () {
  if (state.timer) { window.clearInterval(state.timer); state.timer = null }
}

function liveToggle () {
  var on = pref('live') === '1'
  if (on && !state.timer) startLive()
  var box = el('input', {
    type: 'checkbox', id: 'lg-live', 'data-focus': 'live'
  })
  box.checked = on
  box.addEventListener('change', function () {
    pref('live', box.checked ? '1' : '0')
    if (box.checked) startLive(); else stopLive()
    render()
  })
  return el('label', { class: 'live', for: 'lg-live' }, [
    box,
    on ? 'Live · updated ' + ago(state.refreshedAt) : 'Live'
  ])
}

window.addEventListener('hashchange', function () {
  route()
  if (pref('live') === '1') startLive(); else stopLive()
})

// A 401 here is the normal first load, not an error.
fetch('/v1/admin/session', { credentials: 'same-origin', headers: { 'x-lg-dashboard': '1' } })
  .then(function (res) {
    if (!res.ok) return showLogin()
    route()
    if (pref('live') === '1') startLive()
  })
  .catch(function () { showLogin() })
</script>
</body>
</html>
`
