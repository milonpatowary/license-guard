'use strict'

const crypto = require('crypto')
const { seal, open, randomKey } = require('./aes')
const { CoreIntegrityError, ConfigurationError } = require('./errors')

/**
 * The `.lgc` container: your core module, encrypted, with a readable label.
 *
 *   magic      4 bytes  "LGC1"
 *   metaLen    2 bytes  big-endian
 *   meta       JSON, in the clear
 *   iv        12 bytes
 *   tag       16 bytes
 *   body       ciphertext
 *
 * The metadata is deliberately not encrypted. The loader has to know which
 * product and which build it is holding *before* it can ask the licence server
 * for a key, and a support engineer looking at a customer's install directory
 * should be able to answer "which version is this" without any secrets at all.
 * It is covered by the authentication tag, so it is readable but not editable.
 *
 * `buildId` is a hash of the plaintext. It is what lets you match a leaked file
 * back to a build you shipped, and combined with `watermark` — which is
 * per-customer — it is what lets you match it back to *who* you shipped it to.
 */
const MAGIC = Buffer.from('LGC1', 'ascii')

function packCore ({ source, key = randomKey(), meta = {} } = {}) {
  if (typeof source !== 'string' && !Buffer.isBuffer(source)) {
    throw new ConfigurationError('packCore() needs the module source as a string or Buffer.')
  }
  const plaintext = Buffer.from(source)
  const fullMeta = {
    ...meta,
    buildId: crypto.createHash('sha256').update(plaintext).digest('hex').slice(0, 16),
    bytes: plaintext.length,
    packedAt: new Date().toISOString()
  }

  const metaBytes = Buffer.from(JSON.stringify(fullMeta), 'utf8')
  if (metaBytes.length > 0xffff) {
    throw new ConfigurationError('The core metadata is larger than 64 KiB.')
  }
  const header = buildHeader(metaBytes)
  const { iv, tag, body } = seal(plaintext, key, header)

  return {
    file: Buffer.concat([header, iv, tag, body]),
    key: Buffer.from(key).toString('base64'),
    meta: fullMeta
  }
}

/** Read the label without the key. Never throws on a well-formed file. */
function readCoreMeta (file) {
  const buffer = Buffer.from(file)
  if (buffer.length < 6 || !buffer.subarray(0, 4).equals(MAGIC)) {
    throw new CoreIntegrityError(
      'This is not a license-guard core file (the "LGC1" magic bytes are missing).'
    )
  }
  const metaLength = buffer.readUInt16BE(4)
  const metaEnd = 6 + metaLength
  if (buffer.length < metaEnd) throw new CoreIntegrityError('The core file is truncated.')
  try {
    return JSON.parse(buffer.subarray(6, metaEnd).toString('utf8'))
  } catch {
    throw new CoreIntegrityError('The core file metadata is not valid JSON.')
  }
}

function unpackCore (file, key) {
  const buffer = Buffer.from(file)
  const meta = readCoreMeta(buffer)
  const metaLength = buffer.readUInt16BE(4)
  const metaEnd = 6 + metaLength

  const iv = buffer.subarray(metaEnd, metaEnd + 12)
  const tag = buffer.subarray(metaEnd + 12, metaEnd + 28)
  const body = buffer.subarray(metaEnd + 28)
  if (body.length === 0) throw new CoreIntegrityError('The core file has no payload.')

  const source = open({ iv, tag, body }, key, buffer.subarray(0, metaEnd), 'core file')
  return { source: source.toString('utf8'), meta }
}

function buildHeader (metaBytes) {
  const length = Buffer.alloc(2)
  length.writeUInt16BE(metaBytes.length)
  return Buffer.concat([MAGIC, length, metaBytes])
}

module.exports = { packCore, unpackCore, readCoreMeta, MAGIC }
