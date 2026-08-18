import { buildRelayAuthTemplate } from '~~/shared/utils/relay-auth'

/**
 * Builds the NIP-98 Authorization header for a call the *relay* will
 * verify, signed in the browser by the operator's key.
 *
 * The dashboard server holds no key and the relay accepts nothing else, so
 * every privileged relay call carries its own signature and the Nitro layer
 * only forwards it. See CODINGSTANDARDS.md, "Authentication and sessions".
 *
 * The template construction lives in shared/utils/relay-auth.ts so it can be
 * tested without a browser.
 */
export interface SignedRelayRequest {
  authorization: string
  body: string
  /**
   * How long the signer took to return. NIP-98 events expire, so a slow
   * approval is a refusal the dashboard can name precisely instead of
   * guessing — see shared/utils/relay-refusal.ts.
   */
  signingMs: number
}

export function useRelayRequest() {
  /**
   * Signs `payload` for a relay path, returning the header and the exact
   * body string to send with it.
   */
  async function sign(signer: Signer, path: string, payload: unknown): Promise<SignedRelayRequest> {
    const body = JSON.stringify(payload)
    const template = await buildRelayAuthTemplate({ path, origin: window.location.origin, body })

    const startedAt = Date.now()
    const signed = await signer.signEvent(template)

    return {
      authorization: `Nostr ${btoa(JSON.stringify(signed))}`,
      body,
      signingMs: Date.now() - startedAt
    }
  }

  return { sign }
}
