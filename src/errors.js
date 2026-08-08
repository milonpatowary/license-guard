'use strict'

/**
 * The error taxonomy is the licence policy.
 *
 * Everything this library does eventually reduces to one question: does the
 * product keep running? Getting that wrong in the strict direction is worse
 * than piracy — if your licence server has an outage and every customer's
 * production stops, you have caused a bigger incident than a leaked tarball
 * ever would. So the errors are split by whether they are *evidence of a
 * problem with the licence* or *evidence of a problem reaching the server*,
 * and only the first kind is allowed to stop anything.
 *
 *   fatal: true   the licence itself is bad — forged, revoked, for another
 *                 product, or for another machine. There is no legitimate
 *                 deployment in which this happens, so it stops.
 *
 *   fatal: false  we could not confirm the licence right now. A network
 *                 failure, a 502, a DNS outage, an expired-but-recently-valid
 *                 cached token. The product runs on cache and retries.
 */
class LicenseError extends Error {
  constructor (message, code, details = {}) {
    super(message)
    this.name = this.constructor.name
    this.code = code
    this.fatal = false
    Object.assign(this, details)
    Error.captureStackTrace?.(this, this.constructor)
  }
}

/** The token could not be parsed, or its signature does not verify. */
class LicenseInvalidError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'license_invalid', details)
    this.fatal = true
  }
}

/** A valid token, but not for this product, version, or machine. */
class LicenseMismatchError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'license_mismatch', details)
    this.fatal = true
  }
}

/** The server knows this key and has withdrawn it. */
class LicenseRevokedError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'license_revoked', details)
    this.fatal = true
  }
}

/**
 * More distinct machines than the licence allows.
 *
 * Fatal, but only for the machine that tipped it over — existing instances
 * keep their tokens. Growing past your seat count is a sales conversation,
 * not a reason to take down the deployments already paid for.
 */
class SeatLimitError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'seat_limit', details)
    this.fatal = true
  }
}

/** Past `exp`, and past the grace window on top of it. */
class LicenseExpiredError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'license_expired', details)
    this.fatal = false
  }
}

/** The licence server could not be reached, or did not answer usefully. */
class LicenseServerError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'server_unreachable', details)
    this.fatal = false
  }
}

/**
 * The encrypted core failed to decrypt or failed its authentication tag.
 *
 * Fatal, and deliberately so: this is the one case where continuing would mean
 * executing bytes that something has tampered with.
 */
class CoreIntegrityError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'core_integrity', details)
    this.fatal = true
  }
}

/** Wrong arguments to this library, not a licensing condition at all. */
class ConfigurationError extends LicenseError {
  constructor (message, details = {}) {
    super(message, 'configuration', details)
    this.fatal = true
  }
}

module.exports = {
  LicenseError,
  LicenseInvalidError,
  LicenseMismatchError,
  LicenseRevokedError,
  SeatLimitError,
  LicenseExpiredError,
  LicenseServerError,
  CoreIntegrityError,
  ConfigurationError
}
