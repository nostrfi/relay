import type { SessionState } from '~~/shared/types/session'

/**
 * Re-confirms the session's role with a `whoami` the browser signed (D5,
 * nostrfi/relay#56).
 *
 * Called when /api/session reports roleRecheckDue. A key the relay still
 * names as owner or admin keeps its session, with the role refreshed (an
 * owner change in config.yaml shows up here too); a key it no longer
 * recognises loses it.
 */

/** Same budget as login: each attempt verifies a signature on the relay. */
const RECHECK_RATE_LIMIT = { limit: 10, windowMs: 60_000 }

export default defineEventHandler(async (event): Promise<SessionState> => {
  const session = await requireAdminSession(event)

  if (!allowRequest(`recheck:${session.pubkey}`, RECHECK_RATE_LIMIT)) {
    throw createError({ statusCode: 429, statusMessage: 'Too many re-check attempts' })
  }

  const outcome = await askRelayWhoami(
    event,
    session.pubkey,
    getRequestHeader(event, 'authorization'),
    await readRawBody(event, 'utf8')
  )

  if (outcome.kind === 'role') {
    await confirmAdminRole(event, outcome.role)
    return { authenticated: true, pubkey: session.pubkey, role: outcome.role, roleRecheckDue: false }
  }

  if (outcome.evidence === 'revoked') {
    console.warn('dashboard session ended at re-check: the relay no longer recognises the signed-in key', session.pubkey)
    await endAdminSession(event)
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized', data: { sessionEnded: true } })
  }

  // A verification failure or a malformed request says nothing about the
  // role, so the session stays and the browser can try again.
  if (outcome.answer) {
    throw await relayRefusal(event, outcome.answer, '/')
  }
  throw createError({ statusCode: 400, statusMessage: 'Expected a signed whoami request' })
})
