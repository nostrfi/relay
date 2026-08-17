import type { SessionState } from '~~/shared/types/session'

/**
 * Reports the current session. Deliberately answers 200 with
 * authenticated: false rather than 401 — route middleware polls this on
 * every navigation to decide whether to redirect, and an unauthenticated
 * visitor arriving at the login page is the expected case, not an error.
 */
export default defineEventHandler(async (event): Promise<SessionState> => {
  const { pubkey } = await getAdminSession(event)
  return pubkey ? { authenticated: true, pubkey } : { authenticated: false }
})
