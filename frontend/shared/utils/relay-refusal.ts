/**
 * Explaining a relay 401 without guessing.
 *
 * The relay answers every failed operator check with a bare "unauthorized":
 * a stale signature, a clock skew, a wrong `u` tag, a payload-hash mismatch
 * and a non-operator key are indistinguishable to the caller, by design —
 * saying which check failed would help an attacker tune the next attempt.
 *
 * So the dashboard must not assert a single cause. It can, however, know one
 * of them for certain: it measured how long the signature took, and NIP-98
 * events expire. That case is named precisely; the rest are listed as
 * possibilities, with a pointer to the relay log, which does record the
 * actual reason.
 */

/** The relay's own default for `moderation.max_event_age_seconds`. */
export const NIP98_DEFAULT_MAX_AGE_SECONDS = 60

export interface RelayRefusalContext {
  /** How long the signer took to return a signature, in milliseconds. */
  signingMs?: number
  /** The pubkey the operator signed into the dashboard with. */
  signedInPubkey?: string
  /** The relay's freshness window, when known. */
  maxAgeSeconds?: number
}

export interface RelayRefusal {
  /** The single most likely cause, when one can be established. */
  headline: string
  /** Everything that could produce this refusal, most actionable first. */
  causes: string[]
}

export function describeRelayRefusal(context: RelayRefusalContext = {}): RelayRefusal {
  const maxAge = context.maxAgeSeconds ?? NIP98_DEFAULT_MAX_AGE_SECONDS
  const signingSeconds = context.signingMs === undefined ? undefined : Math.round(context.signingMs / 1000)

  // Known for certain: the signature was already expired when it was sent.
  if (signingSeconds !== undefined && signingSeconds > maxAge) {
    return {
      headline: `Your signature took ${signingSeconds} seconds to approve, and the relay rejects any older than ${maxAge}. Try again and approve promptly.`,
      causes: []
    }
  }

  const causes = [
    `The signature expired before it arrived — the relay rejects any older than ${maxAge} seconds, so a slow approval or a clock more than ${maxAge} seconds out will fail.`,
    'The key you signed with is not the relay\'s configured operator. The dashboard\'s NUXT_ADMIN_PUBKEY and the relay\'s moderation.admin_pubkey are set separately and must name the same key.',
    'The relay is reached at a different path than the one signed, which a reverse proxy that rewrites paths would cause.'
  ]

  if (context.signedInPubkey) {
    causes[1] = `The key you signed with is not the relay's configured operator. You signed in as ${context.signedInPubkey}; the dashboard's NUXT_ADMIN_PUBKEY and the relay's moderation.admin_pubkey are set separately and must name the same key.`
  }

  return {
    headline: 'The relay refused this request, and does not say which check failed.',
    causes
  }
}

/** Where the actual reason is recorded. */
export const RELAY_REFUSAL_LOG_HINT
  = 'The relay logs the real reason: look for "operator request rejected" in its output.'
