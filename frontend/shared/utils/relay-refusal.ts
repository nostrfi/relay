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
  /** The pubkey that actually signed the refused request. */
  signingPubkey?: string
  /** The path signed into the `u` tag. */
  signedPath?: string
  /** The relay's freshness window, when known. */
  maxAgeSeconds?: number

  /* Facts observed by the server proxy, which turn guesses into checks. */

  /** The relay's own clock, in unix seconds. */
  relayTimeSeconds?: number
  /** The relay's public NIP-11 pubkey. */
  relayPubkey?: string
  /** The path the relay was actually asked for. */
  requestedPath?: string
  /** This browser's clock, injectable for testing. */
  browserTimeSeconds?: number
  /** The relay's own account of what failed, when it is safe to give one. */
  relayReason?: string
}

export interface RelayRefusal {
  /** The single most likely cause, when one can be established. */
  headline: string
  /** Everything that could produce this refusal, most actionable first. */
  causes: string[]
}

export function describeRelayRefusal(context: RelayRefusalContext = {}): RelayRefusal {
  const maxAge = context.maxAgeSeconds ?? NIP98_DEFAULT_MAX_AGE_SECONDS

  // The relay's own words, when it gave any. Nothing inferred here can beat
  // the account of the party that did the rejecting.
  if (context.relayReason) {
    return {
      headline: `The relay rejected the request: ${context.relayReason}`,
      causes: context.relayReason.includes('different host than this relay')
        ? [
            'The dashboard signs for the address in your browser\'s address bar, and the relay accepts only the address it is configured for (shown in brackets). Open the dashboard at that address, or set auth.relay_url, or moderation.api_origin, to the one you use.'
          ]
        : []
    }
  }
  const signingSeconds = context.signingMs === undefined ? undefined : Math.round(context.signingMs / 1000)

  // Known for certain: the signature was already expired when it was sent.
  if (signingSeconds !== undefined && signingSeconds > maxAge) {
    return {
      headline: `Your signature took ${signingSeconds} seconds to approve, and the relay rejects any older than ${maxAge}. Try again and approve promptly.`,
      causes: []
    }
  }

  // Known for certain: the two clocks disagree by more than the window, so
  // any signature this browser makes is already outside it.
  const browserTime = context.browserTimeSeconds ?? Math.floor(Date.now() / 1000)
  if (context.relayTimeSeconds !== undefined) {
    const skew = Math.abs(context.relayTimeSeconds - browserTime)
    if (skew > maxAge) {
      const direction = context.relayTimeSeconds > browserTime ? 'ahead of' : 'behind'
      return {
        headline: `The relay's clock is ${skew} seconds ${direction} this browser's, and it rejects signatures more than ${maxAge} seconds old. Fix the clock on either machine — no signature from here can satisfy it until then.`,
        causes: []
      }
    }
  }

  // Known for certain: the relay was asked for a path other than the one
  // signed, which its u-tag check compares exactly.
  if (context.signedPath && context.requestedPath && context.signedPath !== context.requestedPath) {
    return {
      headline: `The request was signed for ${context.signedPath} but the relay was asked for ${context.requestedPath}. The relay compares those exactly, so the signature cannot match.`,
      causes: []
    }
  }

  // Known for certain: the request was signed by a different key than the
  // session was opened with. The relay refuses it, and no relay-side
  // setting can make it work — the signer is holding the wrong account.
  if (context.signingPubkey && context.signedInPubkey && context.signingPubkey !== context.signedInPubkey) {
    return {
      headline: `This request was signed by ${context.signingPubkey}, but you signed in as ${context.signedInPubkey}. Your signer is holding a different account than the one this session belongs to.`,
      causes: []
    }
  }

  // The relay's published NIP-11 pubkey is deliberately not compared with
  // the signer here. It names the owner, and administrators sign with keys
  // of their own (nostrfi/relay#55), so a difference is no evidence of
  // anything.

  const causes = [
    `The signature expired before it arrived — the relay rejects any older than ${maxAge} seconds, so a slow approval or a clock more than ${maxAge} seconds out will fail.`,
    'The key you signed with is not the relay\'s owner or one of its administrators — it may have been revoked since you signed in.',
    'The relay is reached at a different path than the one signed, which a reverse proxy that rewrites paths would cause.'
  ]

  if (context.signedInPubkey) {
    causes[1] = `The key you signed with is not the relay's owner or one of its administrators. You signed in as ${context.signedInPubkey}; if you are an administrator, the owner may have revoked that grant since.`
  }

  return {
    headline: 'The relay refused this request, and does not say which check failed.',
    causes
  }
}

/** Where the actual reason is recorded. */
export const RELAY_REFUSAL_LOG_HINT
  = 'The relay logs the real reason: look for "operator request rejected" in its output.'

export interface RelayRefusedError extends Error {
  refusal: RelayRefusal
  /** Empty when the cause is established: pointing at the log would then
   *  read as if we had not just named it. */
  logHint: string
}

/** Builds the error both the configuration and moderation pages render. */
export function createRelayRefusalError(context: RelayRefusalContext = {}): RelayRefusedError {
  const refusal = describeRelayRefusal(context)
  const error = new Error(refusal.headline) as RelayRefusedError
  error.refusal = refusal
  error.logHint = refusal.causes.length > 0 ? RELAY_REFUSAL_LOG_HINT : ''
  return error
}

/**
 * Pulls the proxy's diagnostics out of a thrown fetch error.
 *
 * `$fetch` throws with `error.data` set to the *whole* error body, so a
 * route that answered `createError({ data })` lands at `error.data.data`.
 * Reading one level too shallow silently yields nothing and the diagnosis
 * quietly degrades to guesswork — which is exactly what happened before
 * this helper existed, so it is tested rather than assumed.
 */
export function refusalDiagnosticsFrom(cause: unknown): Partial<RelayRefusalContext> {
  const body = (cause as { data?: Record<string, unknown> })?.data
  if (!body || typeof body !== 'object') {
    return {}
  }

  const nested = (body as { data?: Record<string, unknown> }).data
  const facts = (nested && typeof nested === 'object' ? nested : body) as Partial<RelayRefusalContext>

  // Only the fields this module understands, so an unrelated error body
  // cannot smuggle values into the diagnosis.
  return {
    relayTimeSeconds: typeof facts.relayTimeSeconds === 'number' ? facts.relayTimeSeconds : undefined,
    relayPubkey: typeof facts.relayPubkey === 'string' ? facts.relayPubkey : undefined,
    requestedPath: typeof facts.requestedPath === 'string' ? facts.requestedPath : undefined,
    relayReason: typeof facts.relayReason === 'string' ? facts.relayReason : undefined
  }
}
