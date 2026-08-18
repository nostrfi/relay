import type { EventQueryRequest, EventQueryResponse } from '~~/shared/types/events'
import { createRelayRefusalError, refusalDiagnosticsFrom } from '~~/shared/utils/relay-refusal'

/**
 * Reads stored events from the relay.
 *
 * Signed in the browser like every other privileged relay call: the endpoint
 * is publicly reachable, so the relay authorizes it itself and the dashboard
 * server only forwards.
 *
 * Every query therefore costs one signature. That is why the page runs a
 * query on an explicit action and pages a hundred at a time, rather than
 * filtering as the operator types — with a remote signer, each keystroke
 * would otherwise be a round trip and an approval.
 */
export function useEvents() {
  const { sign } = useRelayRequest()
  const { state } = useAdminSession()

  async function query(request: EventQueryRequest): Promise<EventQueryResponse> {
    // The relay serves this at /api/events/query, which is the path signed
    // into the u tag — not the dashboard route the request is sent to.
    const { authorization, body, signingMs, pubkey, signedPath }
      = await withSigner(state.value?.pubkey, signer => sign(signer, '/api/events/query', request))

    try {
      return await $fetch<EventQueryResponse>('/api/events/query', {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authorization
        }
      })
    } catch (cause) {
      if ((cause as { statusCode?: number })?.statusCode !== 401) {
        throw cause
      }
      // A refused operator check, which the relay will not explain.
      throw createRelayRefusalError({
        signingMs,
        signedInPubkey: state.value?.pubkey,
        signingPubkey: pubkey,
        signedPath,
        ...refusalDiagnosticsFrom(cause)
      })
    }
  }

  return { query }
}
