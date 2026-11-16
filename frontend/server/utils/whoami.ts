import type { H3Event } from 'h3'
import type { DashboardRole } from '~~/shared/types/session'
import { isWhoamiBody, roleEvidenceFrom, roleFromWhoami, type RoleEvidence } from '~~/shared/utils/session-role'

/**
 * Asks the relay what role a key holds, with a `whoami` the browser signed
 * (D4, nostrfi/relay#56). The relay is the only source of truth: the
 * dashboard holds no list of administrators, and there is no unsigned way
 * to ask "is X an admin?".
 */

export type WhoamiOutcome
  = | { kind: 'role', role: DashboardRole }
    /** Neither owner nor admin, or a signature from another key. */
    | { kind: 'refused', evidence: RoleEvidence, answer?: RelayAnswer }

/** Relay `whoami` should be instant; a stuck relay must not hang sign-in. */
const WHOAMI_TIMEOUT_MS = 10_000

export async function askRelayWhoami(
  event: H3Event,
  expectedPubkey: string,
  authorization: string | undefined,
  body: string | undefined
): Promise<WhoamiOutcome> {
  if (!authorization || !body || !isWhoamiBody(body)) {
    return { kind: 'refused', evidence: 'unknown' }
  }

  const answer = await postToRelay(event, {
    relayPath: '/',
    contentType: 'application/nostr+json+rpc',
    authorization,
    body,
    timeoutMs: WHOAMI_TIMEOUT_MS
  })

  if (answer.response.status >= 500) {
    throw createError({
      statusCode: 502,
      statusMessage: `The relay could not answer (${answer.response.status})`
    })
  }

  const role = answer.response.ok ? roleFromWhoami(answer.parsed, expectedPubkey) : null
  if (role) {
    return { kind: 'role', role }
  }
  const reason = (answer.parsed as { reason?: unknown } | null)?.reason
  return { kind: 'refused', evidence: roleEvidenceFrom(answer.response.status, reason), answer }
}
