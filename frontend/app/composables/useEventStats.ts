import type { EventStatsRequest, EventStatsResponse } from '~~/shared/types/event-stats'
import { createRelayRefusalError, refusalDiagnosticsFrom } from '~~/shared/utils/relay-refusal'

/**
 * Reads event counts from the relay.
 *
 * Signed like every other privileged relay call, through the shared signer
 * queue, so a chart refresh cannot collide with a signature another part of
 * the dashboard is already asking for.
 */
export function useEventStats() {
  const { sign } = useRelayRequest()
  const { state } = useAdminSession()

  async function fetchStats(request: EventStatsRequest): Promise<EventStatsResponse> {
    const { authorization, body, signingMs, pubkey, signedPath }
      = await withSigner(state.value?.pubkey, signer => sign(signer, '/api/events/stats', request))

    try {
      return await $fetch<EventStatsResponse>('/api/events/stats', {
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
      throw createRelayRefusalError({
        signingMs,
        signedInPubkey: state.value?.pubkey,
        signingPubkey: pubkey,
        signedPath,
        ...refusalDiagnosticsFrom(cause)
      })
    }
  }

  return { fetchStats }
}
