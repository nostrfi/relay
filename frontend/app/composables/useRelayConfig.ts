import type { RelayConfig } from '~~/shared/types/relay-config'
import { RELAY_REFUSAL_LOG_HINT, describeRelayRefusal } from '~~/shared/utils/relay-refusal'

/**
 * Reads the relay's effective operational configuration.
 *
 * Signed in the browser like every other privileged relay call — the
 * endpoint is publicly reachable, so the relay authorizes it itself.
 */
export interface RelayRefusedError extends Error {
  refusal: ReturnType<typeof describeRelayRefusal>
  logHint: string
}

export function useRelayConfig() {
  const { sign } = useRelayRequest()
  const { state } = useAdminSession()

  async function fetchConfig(): Promise<RelayConfig> {
    const signer = await acquireSigner()
    try {
      // The relay serves this at /api/config, which is the path signed into
      // the u tag — not the dashboard route the request is sent to.
      const { authorization, body, signingMs } = await sign(signer, '/api/config', {})

      try {
        return await $fetch<RelayConfig>('/api/config', {
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
        // The relay will not say which check failed, so neither will we.
        const refusal = describeRelayRefusal({ signingMs, signedInPubkey: state.value?.pubkey })
        const error = new Error(refusal.headline) as RelayRefusedError
        error.refusal = refusal
        // Only point at the log when we are listing possibilities. When the
        // cause is established, sending the operator to grep for it reads as
        // if we had not just told them.
        error.logHint = refusal.causes.length > 0 ? RELAY_REFUSAL_LOG_HINT : ''
        throw error
      }
    } finally {
      await signer.close()
    }
  }

  return { fetchConfig }
}
