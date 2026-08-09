declare module '@devmilon/license-guard' {
  /** 'active' and 'grace' both mean fully functional. 'degraded' does too. */
  export type GuardStatus = 'inactive' | 'active' | 'grace' | 'degraded'

  export interface TokenClaims {
    /** Token id — what a revocation list names. */
    jti?: string
    /** Issuer (your licence server's host). */
    iss?: string
    /** Product id. */
    prd: string
    /** Licence id — the subscription, not the customer's secret key. */
    lic: string
    /** Customer label. */
    cus?: string
    /** Deployment fingerprint this token is bound to; null means portable. */
    fp?: string | null
    /** Per-licence watermark, for stamping into generated artefacts. */
    wm?: string
    plan?: string
    /** Feature flags this licence includes. */
    fea?: string[]
    seats?: number
    iat?: number
    nbf?: number
    /** Expiry, seconds since epoch. */
    exp: number
    /** Seconds of grace after `exp` during which the product keeps working. */
    grc?: number
    /** Suggested check-in interval, seconds. */
    hbt?: number
    [claim: string]: unknown
  }

  export interface LicenseSnapshot {
    status: GuardStatus
    product: string
    fingerprint: string
    /** True when no durable instance id could be written to disk. */
    ephemeral: boolean
    claims: TokenClaims | null
    customer: string | null
    plan: string | null
    features: string[]
    watermark: string | null
    seats: number | null
    /** Base64 AES-256 key for the encrypted core. */
    coreKey: string | null
    expiresAt: number | null
    graceEndsAt: number | null
    notice: string | null
  }

  export interface StateChange {
    from: GuardStatus
    to: GuardStatus
    reason?: string
    source?: string
  }

  export interface GuardOptions {
    product: string
    version?: string
    /** The `lgpk1_…` public key this build trusts. Safe to commit. */
    publicKey: string
    /** Licence server base URL. Required unless `offlineLicense` is given. */
    endpoint?: string
    licenseKey?: string
    stateDir?: string
    /**
     * Fold hostname and MAC into the fingerprint. Off by default — it makes the
     * id stricter and far less stable. On-premise hardware only.
     */
    includeHost?: boolean
    /** For air-gapped installs: the bundle from `license-guard issue --offline`. */
    offlineLicense?: { token: string; coreKey?: string | null } | string | null
    telemetry?: 'full' | 'minimal' | false
    heartbeat?: boolean
    now?: () => number
    logger?: Partial<Console> | null
    onStateChange?: (change: StateChange) => void
    /**
     * Called when the licence could not be confirmed and grace has run out.
     * The product has NOT been stopped; what happens next is yours to decide.
     */
    onDegrade?: (detail: { product: string; fingerprint: string; reason: string }) => void
    transport?: Transport | null
    fingerprint?: Fingerprint | null
    setIntervalImpl?: typeof setInterval
    clearIntervalImpl?: typeof clearInterval
  }

  export interface Guard {
    activate (): Promise<LicenseSnapshot>
    heartbeat (): Promise<LicenseSnapshot>
    readonly status: GuardStatus
    readonly fingerprint: Fingerprint
    snapshot (): LicenseSnapshot
    has (feature: string): boolean
    /** Throws LicenseMismatchError if the feature is absent. */
    require (feature: string): void
    stop (): void
    reset (): void
  }

  export interface Fingerprint {
    id: string
    ephemeral: boolean
    ephemeralReason: string | null
    stateDir: string
    components: {
      hostname: string
      platform: string
      arch: string
      macHash: string | null
      cpus: number | null
      container: string | null
      node: string
      instanceSource: 'env' | 'disk' | 'created' | 'unavailable'
    }
  }

  export interface Transport {
    endpoint: string
    post (pathname: string, body: unknown): Promise<{ status: number; data: any; raw?: string }>
  }

  export interface CoreMeta {
    product?: string
    version?: string
    watermark?: string | null
    buildId: string
    bytes: number
    packedAt: string
    [key: string]: unknown
  }

  export interface ProtectOptions extends GuardOptions {
    /** Path to the `.lgc` file. Omit to activate without loading anything. */
    coreFile?: string
    resolveFrom?: string
    /** Extra bindings injected into the encrypted module's scope. */
    context?: Record<string, unknown>
  }

  export interface ProtectResult<T = any> {
    core: T
    license: LicenseSnapshot
    guard: Guard
    build?: CoreMeta
  }

  export function protect<T = any> (options: ProtectOptions): Promise<ProtectResult<T>>
  export function createGuard (options: GuardOptions): Guard

  export function loadEncryptedModule<T = any> (options: {
    file?: string
    buffer?: Buffer | Uint8Array
    key: string | Buffer
    resolveFrom?: string
    expect?: { product?: string; version?: string }
    context?: Record<string, unknown>
  }): { exports: T; meta: CoreMeta }

  export function inspectCore (file: string): CoreMeta

  export function packCore (options: {
    source: string | Buffer
    key?: string | Buffer
    meta?: Record<string, unknown>
  }): { file: Buffer; key: string; meta: CoreMeta }

  export function unpackCore (
    file: Buffer | Uint8Array, key: string | Buffer
  ): { source: string; meta: CoreMeta }

  export function readCoreMeta (file: Buffer | Uint8Array): CoreMeta

  export function computeFingerprint (options: {
    product: string
    stateDir?: string
    includeHost?: boolean
  }): Fingerprint

  export function resolveStateDir (product: string, override?: string): string

  export function sign (claims: TokenClaims, secretKey: string): string

  export function verify (token: string, publicKey: string, options?: {
    now?: number
    product?: string | null
    fingerprint?: string | null
    clockSkewSeconds?: number
  }): {
    claims: TokenClaims
    state: 'active' | 'grace'
    expiresAt: number
    graceEndsAt: number
  }

  /** Reads a token without checking it. Never use this to make a decision. */
  export function decodeUnverified (token: string): TokenClaims

  export function generateKeyPair (): {
    publicKey: string
    secretKey: string
    /** base64 PKCS8, for `wrangler secret put SIGNING_KEY`. */
    workerSecret: string
  }

  export function publicKeyFor (secretKey: string): string
  /** The same key as base64 PKCS8, for `wrangler secret put SIGNING_KEY`. */
  export function workerSecretFor (secretKey: string): string
  export function importPublicKey (value: string): import('crypto').KeyObject
  export function importSecretKey (value: string): import('crypto').KeyObject

  export function createTransport (options: {
    endpoint: string
    fetchImpl?: typeof fetch
    timeoutMs?: number
    totalTimeoutMs?: number
    retries?: number
    userAgent?: string
    sleep?: (ms: number) => Promise<void>
    random?: () => number
  }): Transport

  export function createVault (options: {
    stateDir: string
    fingerprintId: string
    fileName?: string
  }): {
    file: string
    read (): unknown | null
    write (value: unknown): boolean
    clear (): boolean
  }

  export const SDK_VERSION: string

  export class LicenseError extends Error {
    code: string
    /** True only when the licence is provably wrong. Never for a network failure. */
    fatal: boolean
  }
  export class LicenseInvalidError extends LicenseError {}
  export class LicenseMismatchError extends LicenseError {}
  export class LicenseRevokedError extends LicenseError {}
  export class SeatLimitError extends LicenseError {
    seats?: number
    used?: number
  }
  export class LicenseExpiredError extends LicenseError {}
  export class LicenseServerError extends LicenseError {}
  export class CoreIntegrityError extends LicenseError {}
  export class ConfigurationError extends LicenseError {}
}
