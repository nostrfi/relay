import type { RelayConfig } from '~~/shared/types/relay-config'

/**
 * Reads the relay's effective operational configuration.
 *
 * Signed in the browser like every other privileged relay call — the
 * endpoint is publicly reachable, so the relay authorizes it itself.
 */
export function useRelayConfig() {
  const { sign } = useRelayRequest()

  async function fetchConfig(): Promise<RelayConfig> {
    const signer = await acquireSigner()
    try {
      // The relay serves this at /api/config, which is the path signed into
      // the u tag — not the dashboard route the request is sent to.
      const { authorization, body } = await sign(signer, '/api/config', {})

      return await $fetch<RelayConfig>('/api/config', {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authorization
        }
      })
    } finally {
      await signer.close()
    }
  }

  return { fetchConfig }
}
