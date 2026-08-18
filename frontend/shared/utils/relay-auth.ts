import type { EventTemplate } from 'nostr-tools/pure'

/**
 * The pure half of building a NIP-98 authorization for a relay-bound call.
 *
 * Kept out of the composable so it can be tested directly: this is the part
 * that broke in nostrfi/workspace#35 and fails only against a real relay,
 * where the symptom is an opaque 401.
 */

export const NIP98_AUTH_KIND = 27235

/**
 * Hex-encoded SHA-256 of the exact body bytes, for NIP-98's payload tag.
 *
 * The caller must send this same string as the request body. Re-serializing
 * the JSON anywhere in between — including a proxy that parses and re-emits
 * it — changes the bytes and the relay's hash check fails.
 */
export async function sha256Hex(body: string): Promise<string> {
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

export interface RelayAuthInput {
  path: string
  origin: string
  /** The exact body string that will be sent. */
  body: string
  /** Unix seconds; injectable so the template is testable. */
  createdAt?: number
}

export async function buildRelayAuthTemplate(input: RelayAuthInput): Promise<EventTemplate> {
  return {
    kind: NIP98_AUTH_KIND,
    created_at: input.createdAt ?? Math.floor(Date.now() / 1000),
    tags: [
      ['u', relayUrlFor(input.path, input.origin)],
      ['method', 'POST'],
      ['payload', await sha256Hex(input.body)]
    ],
    content: ''
  }
}
