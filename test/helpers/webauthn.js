'use strict'

const crypto = require('crypto')

/**
 * An authenticator, in about as few lines as one can be written.
 *
 * The point of this file is that the server's WebAuthn code is never handed a
 * fixture it helped produce. Everything below is built the way a real
 * authenticator builds it — CBOR encoded here, decoded there; signed here with
 * node:crypto, verified there with WebCrypto — so a test passes only when two
 * independent implementations agree. A recorded blob from a real device would
 * prove the same thing once, and then prove nothing the day the code changes.
 *
 * It can also lie on request, which is most of what it is for: wrong origin,
 * wrong challenge, wrong relying party, a counter that goes backwards, a
 * signature over the wrong bytes.
 */

const b64u = (buf) => Buffer.from(buf).toString('base64url')

/* ---- CBOR, encoding only ---- */

function cborHead (major, length) {
  if (length < 24) return Buffer.from([(major << 5) | length])
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length])
  if (length < 0x10000) {
    const b = Buffer.alloc(3)
    b[0] = (major << 5) | 25
    b.writeUInt16BE(length, 1)
    return b
  }
  const b = Buffer.alloc(5)
  b[0] = (major << 5) | 26
  b.writeUInt32BE(length, 1)
  return b
}

function cborInt (value) {
  return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value)
}

function cborBytes (bytes) {
  return Buffer.concat([cborHead(2, bytes.length), Buffer.from(bytes)])
}

function cborText (text) {
  const bytes = Buffer.from(text, 'utf8')
  return Buffer.concat([cborHead(3, bytes.length), bytes])
}

/** Entries are [key, value] with values already encoded. */
function cborMap (entries) {
  return Buffer.concat([
    cborHead(5, entries.length),
    ...entries.map(([key, value]) => Buffer.concat([
      typeof key === 'number' ? cborInt(key) : cborText(key),
      value
    ]))
  ])
}

/* ---- the authenticator ---- */

const FLAG_UP = 0x01
const FLAG_UV = 0x04
const FLAG_AT = 0x40

function createAuthenticator ({ rpId = 'localhost', algorithm = 'ES256' } = {}) {
  const isEc = algorithm === 'ES256'
  const { publicKey, privateKey } = isEc
    ? crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })

  const credentialId = crypto.randomBytes(32)
  let signCount = 0

  const coseKey = () => {
    if (isEc) {
      // The uncompressed point is 0x04 ‖ x ‖ y.
      const point = publicKey.export({ format: 'der', type: 'spki' }).subarray(-65)
      return cborMap([
        [1, cborInt(2)], [3, cborInt(-7)], [-1, cborInt(1)],
        [-2, cborBytes(point.subarray(1, 33))],
        [-3, cborBytes(point.subarray(33, 65))]
      ])
    }
    const jwk = publicKey.export({ format: 'jwk' })
    return cborMap([
      [1, cborInt(3)], [3, cborInt(-257)],
      [-1, cborBytes(Buffer.from(jwk.n, 'base64url'))],
      [-2, cborBytes(Buffer.from(jwk.e, 'base64url'))]
    ])
  }

  const authData = ({ attested, rpIdOverride, flags, counter }) => {
    const rpIdHash = crypto.createHash('sha256').update(rpIdOverride ?? rpId).digest()
    const header = Buffer.alloc(37)
    rpIdHash.copy(header, 0)
    header[32] = flags ?? (attested ? FLAG_UP | FLAG_UV | FLAG_AT : FLAG_UP | FLAG_UV)
    header.writeUInt32BE(counter ?? signCount, 33)
    if (!attested) return header

    const key = coseKey()
    const attested_ = Buffer.alloc(18)
    // AAGUID stays zero: `attestation: 'none'` is what the server asks for and
    // a zero aaguid is what a privacy-preserving authenticator returns.
    attested_.writeUInt16BE(credentialId.length, 16)
    return Buffer.concat([header, attested_, credentialId, key])
  }

  const clientData = (type, challenge, origin) =>
    Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8')

  const sign = (data) => isEc
    ? crypto.sign('sha256', data, privateKey) // DER, as a real authenticator emits
    : crypto.sign('sha256', data, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING })

  return {
    get credentialId () { return b64u(credentialId) },
    get signCount () { return signCount },

    register ({ challenge, origin, rpIdOverride, flags, type = 'webauthn.create' } = {}) {
      const client = clientData(type, challenge, origin)
      const data = authData({ attested: true, rpIdOverride, flags })
      const attestation = cborMap([
        ['fmt', cborText('none')],
        ['attStmt', cborMap([])],
        ['authData', cborBytes(data)]
      ])
      return {
        id: b64u(credentialId),
        type: 'public-key',
        response: { clientDataJSON: b64u(client), attestationObject: b64u(attestation) }
      }
    },

    /**
     * `corrupt` signs over bytes the server will not reconstruct, which is the
     * only way to test the signature check without also breaking a earlier one.
     */
    assert ({ challenge, origin, rpIdOverride, flags, counter, corrupt, idOverride, type = 'webauthn.get' } = {}) {
      signCount = counter ?? signCount + 1
      const client = clientData(type, challenge, origin)
      const data = authData({ attested: false, rpIdOverride, flags, counter: signCount })
      const signed = Buffer.concat([data, crypto.createHash('sha256').update(client).digest()])
      const signature = sign(corrupt ? Buffer.concat([signed, Buffer.from('x')]) : signed)
      return {
        id: idOverride ?? b64u(credentialId),
        type: 'public-key',
        response: {
          clientDataJSON: b64u(client),
          authenticatorData: b64u(data),
          signature: b64u(signature),
          userHandle: b64u(Buffer.from('admin'))
        }
      }
    }
  }
}

module.exports = { createAuthenticator, FLAG_UP, FLAG_UV, FLAG_AT }
