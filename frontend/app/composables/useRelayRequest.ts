import type { EventTemplate } from 'nostr-tools/pure'

const NIP98_AUTH_KIND = 27235

/**
 * Builds the NIP-98 Authorization header for a call the *relay* will
 * verify, signed in the browser by the operator's key.
 *
 * The dashboard server holds no key and the relay accepts nothing else, so
 * every privileged relay call carries its own signature and the Nitro layer
 * only forwards it. See CODINGSTANDARDS.md, "Authentication and sessions".
 */

/**
 * Hex-encoded SHA-256 of the exact body bytes, for NIP-98's payload tag.
 * The caller must send this same string as the request body: re-serializing
 * the JSON anywhere in between changes the bytes and the relay's hash check
 * fails.
 */
async function sha256Hex(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
  return [...new Uint8Array(digest)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * The URL to sign into the `u` tag.
 *
 * It must name the path the *relay* observes, not the dashboard path the
 * browser called. The relay serves its management API from the same URI as
 * the WebSocket endpoint — `/`, with no query — and behind the Caddy overlay
 * that is exactly this origin's root, since only `/admin*` is routed to the
 * dashboard.
 */
export function relayUrlFor(path: string, origin: string): string {
  return new URL(path, origin).toString()
}

export interface SignedRelayRequest {
  authorization: string
  body: string
}

export function useRelayRequest() {
  /**
   * Signs `payload` for a relay path, returning the header and the exact
   * body string to send with it.
   */
  async function sign(signer: Signer, path: string, payload: unknown): Promise<SignedRelayRequest> {
    const body = JSON.stringify(payload)

    const template: EventTemplate = {
      kind: NIP98_AUTH_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', relayUrlFor(path, window.location.origin)],
        ['method', 'POST'],
        ['payload', await sha256Hex(body)]
      ],
      content: ''
    }

    const signed = await signer.signEvent(template)

    return {
      authorization: `Nostr ${btoa(JSON.stringify(signed))}`,
      body
    }
  }

  return { sign }
}
