import type { SessionState } from '~~/shared/types/session'
import { signerPubkeyOf } from '~~/shared/utils/session-role'

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

  const authorization = getRequestHeader(event, 'authorization')
  const outcome = await askRelayWhoami(
    event,
    session.pubkey,
    authorization,
    await readRawBody(event, 'utf8')
  )

  if (outcome.kind === 'role') {
    // False when the session was logged out, or replaced by a new sign-in,
    // while the relay was answering: the re-check must not bring it back.
    // No sessionEnded flag, though. Something else ended this session, and
    // the browser may already hold its replacement, possibly for the same
    // key and possibly from another tab. Flagging it would make the client
    // log out, and the logout would end that replacement.
    if (!await confirmAdminRole(event, outcome.role)) {
      throw createError({ statusCode: 401, statusMessage: 'Not authenticated' })
    }
    return { authenticated: true, pubkey: session.pubkey, role: outcome.role, roleRecheckDue: false }
  }

  // Only a refusal of the session's own key says anything about the session,
  // as in forwardSignedRequest.
  if (outcome.evidence === 'revoked' && signerPubkeyOf(authorization) === session.pubkey) {
    console.warn('dashboard session ended at re-check: the relay no longer recognises the signed-in key', session.pubkey)
    await endAdminSession(event)
    throw createError({ statusCode: 401, statusMessage: 'Unauthorized', data: { sessionEnded: true } })
  }

  // A verification failure or a malformed request says nothing about the
  // role, so the session stays and the browser can try again.
  if (outcome.answer?.response.ok) {
    // The relay answered, but not about this session's key (another key
    // signed the whoami). Passing its 200 through would read as success.
    throw createError({ statusCode: 403, statusMessage: 'The relay did not confirm the signed-in key' })
  }
  if (outcome.answer) {
    throw await relayRefusal(event, outcome.answer, '/')
  }
  throw createError({ statusCode: 400, statusMessage: 'Expected a signed whoami request' })
})
