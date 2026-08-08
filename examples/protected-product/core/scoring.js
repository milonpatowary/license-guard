'use strict'

/**
 * The part you sell.
 *
 * This file never ships. `license-guard pack` turns it into `core.lgc`, and the
 * published package contains only the encrypted version. Keep it in the private
 * repository, keep the plaintext out of the tarball, and let the build step be
 * the only thing that reads it.
 *
 * Two bindings are available here that an ordinary module would not have:
 * `license` and `guard`, injected by the loader. They are how the protected
 * code reaches the customer's plan and watermark.
 */

/* global license */

function score (application) {
  // Stand-in for the domain logic that took years to get right.
  const base = (application.income / Math.max(application.debt, 1)) * 100
  const adjusted = base - application.missedPayments * 12
  return Math.max(0, Math.min(999, Math.round(adjusted)))
}

/**
 * Anything the product emits carries the licence watermark.
 *
 * This is the part that pays off. When a competitor's deck contains one of your
 * generated reports, or a customer's "internal tool" turns out to be reselling
 * your output, the mark says which licence produced it. It costs nothing, it
 * cannot be reverse-engineered out of documents already in the wild, and it
 * works against the leak you will actually have.
 */
function report (applications) {
  return {
    generatedAt: new Date().toISOString(),
    issuedTo: license.customer,
    mark: license.watermark,
    rows: applications.map((a) => ({ id: a.id, score: score(a) }))
  }
}

function explain (application) {
  if (!license.features.includes('explanations')) {
    // Feature gating lives inside the encrypted core, which is the only place
    // it is worth anything. The same check in the open wrapper is a one-line
    // patch away from being deleted.
    throw new Error('Score explanations are not included in this plan.')
  }
  return {
    score: score(application),
    factors: [
      { factor: 'debt-to-income', weight: 0.7 },
      { factor: 'missed payments', weight: 0.3 }
    ]
  }
}

module.exports = { score, report, explain }
