import type { SessionState } from '~~/shared/types/session'

/**
 * Opens a dashboard session for the relay's owner or one of its
 * administrators.
 *
 * Two signatures arrive together, from the same key:
 *
 *   - Authorization: a NIP-98 event over this endpoint carrying a
 *     server-issued challenge, which proves the caller holds the key now;
 *   - X-Relay-Authorization, with the body: a NIP-86 `whoami` signed for
 *     the relay, forwarded verbatim, whose answer says what that key may do.
 *
 * The relay decides the role (D4, nostrfi/relay#56); this route holds no
 * list of administrators. The `whoami` goes through here rather than the
 * moderation proxy because that proxy needs a session, and this keeps the
 * rate limit and the one-time challenge in front of the relay call — there
 * is no endpoint that answers "is X an admin?" without both.
 */

/**
 * How old the signed login event may be.
 *
 * Longer than the relay's 60-second NIP-98 window on purpose: the browser
 * signs this event first and the relay's `whoami` second, so this one waits
 * out the operator's second approval too. Replay is already bounded by the
 * challenge it carries, which is redeemable once and only within its own
 * lifetime, so allowing that same lifetime here widens nothing.
 */
const MAX_EVENT_AGE_SECONDS = CHALLENGE_TTL_SECONDS

/**
 * How far in the future the login event may be dated. That is only clock
 * skew, which the second approval does not affect, so it keeps the relay's
 * 60 seconds.
 */
const MAX_EVENT_FUTURE_SECONDS = 60

/** Attempts per address before login refuses; signature checks cost CPU. */
const LOGIN_RATE_LIMIT = { limit: 10, windowMs: 60_000 }

export default defineEventHandler(async (event): Promise<SessionState> => {
  const address = getRequestIP(event, { xForwardedFor: true }) ?? 'unknown'
  if (!allowRequest(`login:${address}`, LOGIN_RATE_LIMIT)) {
    throw createError({ statusCode: 429, statusMessage: 'Too many login attempts' })
  }

  const unauthorized = createError({ statusCode: 401, statusMessage: 'Unauthorized' })

  let verified
  try {
    verified = verifyNip98Header(getRequestHeader(event, 'authorization'), {
      // getRequestURL, not event.path: Nitro strips app.baseURL ('/admin')
      // for route matching, but the browser signs the public path it
      // actually requested, which still carries the prefix.
      path: getRequestURL(event).pathname,
      method: 'POST',
      maxAgeSeconds: MAX_EVENT_AGE_SECONDS,
      maxFutureSeconds: MAX_EVENT_FUTURE_SECONDS
    })
  } catch (error) {
    // Logged server-side with the reason; the client is told only that it
    // failed, so a probe cannot learn which check it tripped.
    console.warn('dashboard login rejected: NIP-98 verification failed:', (error as Error).message)
    throw unauthorized
  }

  if (!consumeChallenge(verified.challenge)) {
    console.warn('dashboard login rejected: unknown, expired, or reused challenge')
    throw unauthorized
  }

  // Only now, with the challenge spent, is the relay asked anything.
  const outcome = await askRelayWhoami(
    event,
    verified.pubkey,
    getRequestHeader(event, 'x-relay-authorization'),
    await readRawBody(event, 'utf8')
  )

  if (outcome.kind !== 'role') {
    const relayReason = (outcome.answer?.parsed as { reason?: unknown } | null)?.reason
    if (outcome.answer && !outcome.answer.response.ok && typeof relayReason === 'string' && relayReason !== '') {
      // A verification failure of the relay-bound signature (clock skew, a
      // path a proxy rewrote): safe to explain, as the relay itself judged,
      // and otherwise undiagnosable from the browser.
      console.warn('dashboard login rejected: the relay refused the whoami signature:', relayReason)
      throw await relayRefusal(event, outcome.answer, '/')
    }
    // Identity stays generic, exactly as before administrators existed: a
    // stranger learns nothing about which keys matter.
    console.warn('dashboard login rejected: the relay names no role for pubkey', verified.pubkey)
    throw unauthorized
  }

  await startAdminSession(event, verified.pubkey, outcome.role)
  console.info('dashboard session opened', verified.pubkey, outcome.role)

  return { authenticated: true, pubkey: verified.pubkey, role: outcome.role, roleRecheckDue: false }
})
