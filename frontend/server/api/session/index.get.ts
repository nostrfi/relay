import type { SessionState } from '~~/shared/types/session'
import { roleRecheckDue } from '~~/shared/utils/session-role'

/**
 * Reports the current session. Deliberately answers 200 with
 * authenticated: false rather than 401 — route middleware polls this on
 * every navigation to decide whether to redirect, and an unauthenticated
 * visitor arriving at the login page is the expected case, not an error.
 *
 * It cannot ask the relay about the role itself, because only the browser
 * can sign. It reports when the last confirmation has lapsed; signed relay
 * calls renew it as they pass through, and the Metrics view, which makes
 * none, signs a `whoami` for /api/session/recheck (D5).
 */
export default defineEventHandler(async (event): Promise<SessionState> => {
  const session = await getActiveAdminSession(event)
  if (!session) {
    return { authenticated: false }
  }
  return {
    authenticated: true,
    pubkey: session.pubkey,
    role: session.role,
    roleRecheckDue: roleRecheckDue(session.roleCheckedAt)
  }
})
