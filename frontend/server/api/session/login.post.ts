import type { SessionState } from '~~/shared/types/session'

/**
 * Opens a dashboard session for a pubkey that proves key ownership by
 * signing a NIP-98 event over this endpoint, carrying a server-issued
 * challenge. The signed event travels in the Authorization header, exactly
 * as the relay's NIP-86 API expects one, so the whole codebase has a single
 * convention for pubkey-authenticated HTTP.
 */

/** The signed event must be recent, matching the relay's NIP-98 default. */
const MAX_EVENT_AGE_SECONDS = 60

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
      maxAgeSeconds: MAX_EVENT_AGE_SECONDS
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

  const adminPubkey = await resolveAdminPubkey(event)
  if (!adminPubkey || verified.pubkey !== adminPubkey) {
    console.warn('dashboard login rejected: pubkey is not the configured operator', verified.pubkey)
    throw unauthorized
  }

  await startAdminSession(event, verified.pubkey)
  console.info('dashboard session opened', verified.pubkey)

  return { authenticated: true, pubkey: verified.pubkey }
})
