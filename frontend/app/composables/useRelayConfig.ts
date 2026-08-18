import type { RelayConfig } from '~~/shared/types/relay-config'
import { createRelayRefusalError, refusalDiagnosticsFrom } from '~~/shared/utils/relay-refusal'

/**
 * Reads the relay's effective operational configuration.
 *
 * Signed in the browser like every other privileged relay call — the
 * endpoint is publicly reachable, so the relay authorizes it itself.
 */
export function useRelayConfig() {
  const { sign } = useRelayRequest()
  const { state } = useAdminSession()

  async function fetchConfig(): Promise<RelayConfig> {
    // Signed through the shared signer queue, so this cannot collide with a
    // signature another part of the dashboard is already asking for.
    // The relay serves this at /api/config, which is the path signed into
    // the u tag — not the dashboard route the request is sent to.
    const { authorization, body, signingMs, pubkey, signedPath }
      = await withSigner(state.value?.pubkey, signer => sign(signer, '/api/config', {}))

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
      throw createRelayRefusalError({
        signingMs,
        signedInPubkey: state.value?.pubkey,
        signingPubkey: pubkey,
        signedPath,
        ...refusalDiagnosticsFrom(cause)
      })
    }
  }

  return { fetchConfig }
}
