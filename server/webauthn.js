/**
 * WebAuthn verification, with no dependencies.
 *
 * The Worker bundles nothing and has no `nodejs_compat`, so the parts of
 * WebAuthn that libraries normally hide are written out here: enough CBOR to
 * read an attestation object, enough COSE to turn a credential's public key
 * into a JWK, and the ASN.1 unwrapping that ECDSA signatures need before
 * WebCrypto will look at them.
 *
 * The scope is deliberately narrow. Attestation is requested as `none` and is
 * not verified, because verifying it answers "what brand of authenticator is
 * this" — a question that matters when an enterprise is deciding whether to
 * trust hardware it did not buy, and does not matter when the person
 * registering the key is already holding the admin token. Two algorithms are
 * supported, ES256 and RS256, which between them cover every platform
 * authenticator and every security key worth owning.
 */

/* ------------------------------------------------------------------ *
 * Bytes
 * ------------------------------------------------------------------ */

export function fromBase64url (value) {
  const padded = String(value).replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - padded.length % 4) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export function toBase64url (bytes) {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function concat (a, b) {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function sameBytes (a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

async function sha256 (bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

/** Thrown for every failed check, so callers can answer with one 401. */
export class WebAuthnError extends Error {}

function fail (message) {
  throw new WebAuthnError(message)
}

/* ------------------------------------------------------------------ *
 * CBOR
 * ------------------------------------------------------------------ */

/**
 * Just enough CBOR to read what WebAuthn sends.
 *
 * Two structures arrive in this format and no others: the attestation object,
 * which is a map of three well-known keys, and the credential public key,
 * which is a COSE map of small integers. Both are produced by the
 * authenticator, not by the page, but "produced by the authenticator" is not
 * the same as trustworthy — the bytes still arrive through a browser this
 * server does not control, so every length is checked against what is actually
 * there rather than trusted to be sane.
 *
 * Indefinite-length items are refused outright. Nothing in WebAuthn emits
 * them, and accepting them would mean writing a streaming parser for a format
 * this file only needs to read three keys out of.
 */
export function decodeCbor (bytes, start = 0) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  function need (offset, count) {
    if (offset + count > bytes.length) fail('CBOR ended mid-value.')
  }

  function readLength (offset, minor) {
    if (minor < 24) return { value: minor, next: offset }
    if (minor === 24) { need(offset, 1); return { value: view.getUint8(offset), next: offset + 1 } }
    if (minor === 25) { need(offset, 2); return { value: view.getUint16(offset), next: offset + 2 } }
    if (minor === 26) { need(offset, 4); return { value: view.getUint32(offset), next: offset + 4 } }
    if (minor === 27) {
      need(offset, 8)
      const big = view.getBigUint64(offset)
      // A length that does not fit in a JS number cannot describe a real
      // payload here; refusing it is safer than silently losing precision.
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) fail('CBOR length out of range.')
      return { value: Number(big), next: offset + 8 }
    }
    fail('CBOR indefinite lengths are not supported.')
  }

  function decodeAt (offset) {
    need(offset, 1)
    const initial = view.getUint8(offset)
    const major = initial >> 5
    const minor = initial & 0x1f
    const len = readLength(offset + 1, minor)

    switch (major) {
      case 0:
        return { value: len.value, next: len.next }
      case 1:
        return { value: -1 - len.value, next: len.next }
      case 2: {
        need(len.next, len.value)
        return { value: bytes.subarray(len.next, len.next + len.value), next: len.next + len.value }
      }
      case 3: {
        need(len.next, len.value)
        const text = new TextDecoder().decode(bytes.subarray(len.next, len.next + len.value))
        return { value: text, next: len.next + len.value }
      }
      case 4: {
        const items = []
        let cursor = len.next
        for (let i = 0; i < len.value; i++) {
          const item = decodeAt(cursor)
          items.push(item.value)
          cursor = item.next
        }
        return { value: items, next: cursor }
      }
      case 5: {
        const map = new Map()
        let cursor = len.next
        for (let i = 0; i < len.value; i++) {
          const key = decodeAt(cursor)
          const value = decodeAt(key.next)
          map.set(key.value, value.value)
          cursor = value.next
        }
        return { value: map, next: cursor }
      }
      case 7: {
        if (minor === 20) return { value: false, next: len.next }
        if (minor === 21) return { value: true, next: len.next }
        if (minor === 22) return { value: null, next: len.next }
        if (minor === 23) return { value: undefined, next: len.next }
        // Floats are read only so the cursor lands in the right place; no
        // WebAuthn field this file reads is ever a float.
        if (minor === 25) { need(len.next, 2); return { value: null, next: len.next + 2 } }
        if (minor === 26) { need(len.next, 4); return { value: view.getFloat32(len.next), next: len.next + 4 } }
        if (minor === 27) { need(len.next, 8); return { value: view.getFloat64(len.next), next: len.next + 8 } }
        return fail('Unsupported CBOR simple value.')
      }
      default:
        return fail(`Unsupported CBOR major type ${major}.`)
    }
  }

  return decodeAt(start)
}

/* ------------------------------------------------------------------ *
 * COSE keys
 * ------------------------------------------------------------------ */

export const ES256 = -7
export const RS256 = -257

/**
 * A COSE key as WebCrypto wants it.
 *
 * COSE labels everything with small integers — 1 is the key type, 3 is the
 * algorithm, and the negative labels are per-type parameters. JWK is the one
 * import format that lets us hand over EC coordinates and RSA components
 * without hand-building DER, so the conversion stops there.
 */
export function coseToJwk (cose) {
  if (!(cose instanceof Map)) fail('Credential public key is not a COSE map.')
  const kty = cose.get(1)
  const alg = cose.get(3)

  if (alg !== ES256 && alg !== RS256) {
    fail(`Unsupported credential algorithm ${alg}. This server accepts ES256 and RS256.`)
  }

  if (kty === 2) {
    if (alg !== ES256) fail('An EC2 key must be ES256 here.')
    if (cose.get(-1) !== 1) fail('Only the P-256 curve is supported.')
    const x = cose.get(-2)
    const y = cose.get(-3)
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) fail('EC key is missing a coordinate.')
    if (x.length !== 32 || y.length !== 32) fail('EC coordinates are the wrong length for P-256.')
    return { alg, jwk: { kty: 'EC', crv: 'P-256', x: toBase64url(x), y: toBase64url(y) } }
  }

  if (kty === 3) {
    if (alg !== RS256) fail('An RSA key must be RS256 here.')
    const n = cose.get(-1)
    const e = cose.get(-2)
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array)) fail('RSA key is missing a component.')
    return {
      alg,
      jwk: { kty: 'RSA', n: toBase64url(trimLeadingZeros(n)), e: toBase64url(trimLeadingZeros(e)) }
    }
  }

  return fail(`Unsupported COSE key type ${kty}.`)
}

function trimLeadingZeros (bytes) {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++
  return bytes.subarray(i)
}

function importParams (alg) {
  return alg === ES256
    ? { name: 'ECDSA', namedCurve: 'P-256' }
    : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
}

function verifyParams (alg) {
  return alg === ES256 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' }
}

/**
 * ECDSA signatures arrive as a DER SEQUENCE of two INTEGERs; WebCrypto wants
 * the raw r‖s pair. DER integers are signed, so a component whose top bit is
 * set carries a leading zero byte that has to come off, and a short component
 * has to be padded back out to 32 bytes — both of which happen often enough
 * that getting them wrong yields a signature that verifies most of the time.
 */
export function derToRaw (der) {
  if (der[0] !== 0x30) fail('ECDSA signature is not a DER sequence.')

  // The sequence header is two bytes for every signature this will ever see;
  // a long-form length would mean a component over 127 bytes, which P-256
  // cannot produce.
  let offset = 2
  if (der[1] & 0x80) fail('Unexpected long-form length in ECDSA signature.')

  const readInt = () => {
    if (der[offset] !== 0x02) fail('ECDSA signature component is not an INTEGER.')
    const length = der[offset + 1]
    const start = offset + 2
    if (start + length > der.length) fail('ECDSA signature ended mid-component.')
    offset = start + length
    return trimLeadingZeros(der.subarray(start, start + length))
  }

  const r = readInt()
  const s = readInt()
  if (r.length > 32 || s.length > 32) fail('ECDSA signature component is too large for P-256.')

  const raw = new Uint8Array(64)
  raw.set(r, 32 - r.length)
  raw.set(s, 64 - s.length)
  return raw
}

/* ------------------------------------------------------------------ *
 * Authenticator data
 * ------------------------------------------------------------------ */

const FLAG_UP = 0x01
const FLAG_UV = 0x04
const FLAG_AT = 0x40

/**
 * The fixed 37-byte header every authenticator sends, plus the attested
 * credential that only registration carries.
 */
export function parseAuthData (authData) {
  if (!(authData instanceof Uint8Array) || authData.length < 37) {
    fail('Authenticator data is too short.')
  }
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength)
  const flags = authData[32]

  const parsed = {
    rpIdHash: authData.subarray(0, 32),
    flags,
    userPresent: Boolean(flags & FLAG_UP),
    userVerified: Boolean(flags & FLAG_UV),
    attested: Boolean(flags & FLAG_AT),
    signCount: view.getUint32(33),
    credentialId: null,
    publicKey: null
  }

  if (!parsed.attested) return parsed

  if (authData.length < 55) fail('Attested credential data is truncated.')
  const idLength = view.getUint16(53)
  const idStart = 55
  if (idStart + idLength > authData.length) fail('Credential id runs past the end of authenticator data.')

  parsed.credentialId = authData.subarray(idStart, idStart + idLength)
  parsed.publicKey = decodeCbor(authData, idStart + idLength).value
  return parsed
}

/* ------------------------------------------------------------------ *
 * The two ceremonies
 * ------------------------------------------------------------------ */

/**
 * The checks both ceremonies share: that the browser signed over the challenge
 * we issued, for the origin we serve, and that the authenticator was talking
 * about our relying party.
 *
 * The challenge comparison is the load-bearing one. It is what makes an
 * assertion good exactly once, and it is why the caller has to hand in a
 * challenge it has already deleted from storage.
 */
async function checkClientData (clientDataJSON, expected, type) {
  let clientData
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataJSON))
  } catch {
    return fail('clientDataJSON is not JSON.')
  }

  if (clientData.type !== type) fail(`Expected a ${type} ceremony, got ${clientData.type}.`)
  if (typeof clientData.challenge !== 'string' || clientData.challenge !== expected.challenge) {
    fail('Challenge does not match the one this server issued.')
  }
  if (clientData.origin !== expected.origin) {
    fail(`Origin ${clientData.origin} is not ${expected.origin}.`)
  }
  return clientData
}

async function checkAuthData (parsed, expected) {
  const rpIdHash = await sha256(new TextEncoder().encode(expected.rpId))
  if (!sameBytes(parsed.rpIdHash, rpIdHash)) fail('Authenticator signed for a different relying party.')
  if (!parsed.userPresent) fail('The authenticator did not report user presence.')
  // Registration asks for `userVerification: 'required'`, so anything that
  // comes back unverified either ignored that or is not the ceremony we asked
  // for. Either way it is not the Face ID prompt the operator thinks it is.
  if (!parsed.userVerified) fail('The authenticator did not verify the user.')
}

/**
 * Registration. Returns the record to store.
 *
 * The attestation statement is parsed past but not inspected — see the note at
 * the top of this file.
 */
export async function verifyRegistration (credential, expected) {
  const response = credential?.response
  if (!response?.clientDataJSON || !response?.attestationObject) {
    fail('Registration response is missing clientDataJSON or attestationObject.')
  }

  await checkClientData(fromBase64url(response.clientDataJSON), expected, 'webauthn.create')

  const attestation = decodeCbor(fromBase64url(response.attestationObject)).value
  if (!(attestation instanceof Map)) fail('Attestation object is not a CBOR map.')

  const authData = attestation.get('authData')
  const parsed = parseAuthData(authData)
  await checkAuthData(parsed, expected)
  if (!parsed.attested) fail('Registration produced no attested credential data.')

  const { alg, jwk } = coseToJwk(parsed.publicKey)

  // Import it once here rather than trusting it at login: a key that WebCrypto
  // will not accept should be rejected while the operator is standing at the
  // browser, not months later when it is the only way in.
  await crypto.subtle.importKey('jwk', jwk, importParams(alg), false, ['verify'])

  return {
    id: toBase64url(parsed.credentialId),
    jwk,
    alg,
    signCount: parsed.signCount,
    format: attestation.get('fmt') || 'none'
  }
}

/**
 * Login. `lookup` is given the credential id and returns the stored record, or
 * null — which is what keeps this function ignorant of the database.
 */
export async function verifyAssertion (credential, expected, lookup) {
  const response = credential?.response
  if (!response?.clientDataJSON || !response?.authenticatorData || !response?.signature) {
    fail('Assertion is missing clientDataJSON, authenticatorData or signature.')
  }

  const id = typeof credential.id === 'string' ? credential.id : ''
  if (!id) fail('Assertion has no credential id.')

  const stored = await lookup(id)
  if (!stored) fail('That passkey is not registered on this server.')

  await checkClientData(fromBase64url(response.clientDataJSON), expected, 'webauthn.get')

  const authDataBytes = fromBase64url(response.authenticatorData)
  const parsed = parseAuthData(authDataBytes)
  await checkAuthData(parsed, expected)

  const signed = concat(authDataBytes, await sha256(fromBase64url(response.clientDataJSON)))
  let signature = fromBase64url(response.signature)
  if (stored.alg === ES256) signature = derToRaw(signature)

  const key = await crypto.subtle.importKey('jwk', stored.jwk, importParams(stored.alg), false, ['verify'])
  const ok = await crypto.subtle.verify(verifyParams(stored.alg), key, signature, signed)
  if (!ok) fail('Signature does not verify against the stored public key.')

  // A counter that goes backwards is the one signal WebAuthn gives that a
  // credential has been copied. Authenticators that do not implement counters
  // report zero forever, and a zero here has to stay allowed or every passkey
  // in iCloud Keychain would be rejected.
  if (parsed.signCount !== 0 && parsed.signCount <= stored.signCount) {
    fail('Signature counter went backwards, which suggests a cloned authenticator.')
  }

  return { id, signCount: parsed.signCount }
}
