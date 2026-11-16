import type { H3Event } from 'h3'
import { roleEvidenceFrom, signerPubkeyOf } from '~~/shared/utils/session-role'

/**
 * Forwarding a browser-signed request to the relay.
 *
 * Every privileged relay call is signed in the browser and verified by the
 * relay; the dashboard server only forwards it. That forwarding used to be
 * repeated in each proxy route. It lives here now because sign-in needs it
 * too (the relay's `whoami`, nostrfi/relay#56), and because each forward is
 * also the dashboard's cheapest evidence about the signer's role.
 *
 * The body is never re-serialized: NIP-98's payload tag hashes the exact
 * bytes, so any reformatting would make the relay refuse a valid signature.
 */

export interface RelayPost {
  /** The relay path, e.g. `/` for NIP-86 or `/api/config`. */
  relayPath: string
  contentType: string
  authorization: string
  body: string
  /** Bounds how long the relay gets to answer; unbounded when absent. */
  timeoutMs?: number
}

export interface RelayAnswer {
  response: Response
  parsed: unknown
  relayUrl: string
}

/**
 * Posts to the relay and parses its JSON answer, whatever the status. An
 * unreachable relay, a timeout or a non-JSON answer is thrown as a 5xx: the
 * caller must be able to tell an outage from a refusal.
 */
export async function postToRelay(event: H3Event, post: RelayPost): Promise<RelayAnswer> {
  const { relayApiBase } = useRuntimeConfig(event)
  const relayUrl = post.relayPath === '/'
    ? relayApiBase
    : `${relayApiBase.replace(/\/$/, '')}${post.relayPath}`

  let response: Response
  try {
    response = await fetch(relayUrl, {
      method: 'POST',
      headers: {
        'Content-Type': post.contentType,
        'Authorization': post.authorization
      },
      body: post.body,
      signal: post.timeoutMs ? AbortSignal.timeout(post.timeoutMs) : undefined
    })
  } catch (cause) {
    const timedOut = (cause as Error)?.name === 'TimeoutError'
    throw createError({
      statusCode: timedOut ? 504 : 502,
      statusMessage: timedOut
        ? `The relay did not answer within ${(post.timeoutMs ?? 0) / 1000} seconds`
        : `The relay could not be reached: ${(cause as Error)?.message ?? 'unknown error'}`
    })
  }

  const text = await response.text()

  // The middle of a three-process chain — browser, this server, relay — used
  // to be the only part that left no trace, so "the relay was never called"
  // could not be told from "the relay answered nothing" (nostrfi/workspace#49).
  console.info(`relay request proxied: relay=${relayUrl} status=${response.status} bytes=${text.length}`)

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw createError({
      statusCode: 502,
      statusMessage: `Relay returned a non-JSON response (${response.status})`
    })
  }

  return { response, parsed, relayUrl }
}

/** The refusal a proxy route throws when the relay says no. */
export async function relayRefusal(event: H3Event, answer: RelayAnswer, requestedPath: string, extra: Record<string, unknown> = {}) {
  const { relayApiBase } = useRuntimeConfig(event)
  const parsed = answer.parsed as { error?: string, reason?: string } | null
  return createError({
    statusCode: answer.response.status,
    statusMessage: parsed?.error ?? 'The relay refused the request',
    // The relay will not say which check failed. These are the facts that
    // let the browser test the likely causes instead of listing them. The
    // relay explains a verification failure (stale signature, bad path,
    // malformed header) but never an identity one. See
    // shared/utils/relay-refusal.ts.
    data: {
      relayReason: parsed?.reason,
      ...extra,
      ...await collectRefusalDiagnostics(relayApiBase, answer.response, requestedPath)
    }
  })
}

export interface SignedForward {
  relayPath: string
  contentType: string
  timeoutMs?: number
}

/**
 * The whole of a signed proxy route after its session check: read the
 * browser's signed request, forward it, and return the relay's answer or
 * throw its refusal.
 *
 * Along the way it keeps the session's role honest. When the request was
 * signed by the session's own key, the relay's answer is evidence: accepted
 * means the role still holds, and a bare identity refusal means it no
 * longer does — the key was revoked — so the session ends there and then,
 * without waiting for the re-check interval. A forged header cannot abuse
 * this: it can only end the session of whoever sent it.
 */
export async function forwardSignedRequest(event: H3Event, sessionPubkey: string, forward: SignedForward): Promise<unknown> {
  const authorization = getRequestHeader(event, 'authorization')
  if (!authorization) {
    throw createError({ statusCode: 400, statusMessage: 'Missing relay authorization header' })
  }

  const body = await readRawBody(event, 'utf8')
  if (!body) {
    throw createError({ statusCode: 400, statusMessage: 'Missing request body' })
  }

  const answer = await postToRelay(event, { ...forward, authorization, body })
  const parsed = answer.parsed as { reason?: unknown } | null

  let sessionEnded = false
  if (signerPubkeyOf(authorization) === sessionPubkey) {
    const evidence = roleEvidenceFrom(answer.response.status, parsed?.reason)
    if (evidence === 'confirmed') {
      await confirmAdminRole(event)
    } else if (evidence === 'revoked') {
      console.warn('dashboard session ended: the relay no longer recognises the signed-in key', sessionPubkey)
      await endAdminSession(event)
      sessionEnded = true
    }
  }

  if (!answer.response.ok) {
    throw await relayRefusal(event, answer, forward.relayPath, sessionEnded ? { sessionEnded: true } : {})
  }

  return answer.parsed
}
