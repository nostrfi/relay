import type { RelayInfo } from '~~/shared/types/relay-info'

/**
 * Facts gathered when the relay refuses an operator request.
 *
 * The relay will not say which check failed, and should not. But most of
 * its checks compare the request against something observable, so the
 * dashboard can test them itself instead of listing possibilities: the
 * relay's clock arrives in a response header, its operator identity is
 * published in NIP-11, and the path it was asked for is known here.
 */
export interface RelayRefusalDiagnostics {
  /** The relay's own clock, from the Date header of its refusal. */
  relayTimeSeconds?: number
  /** The relay's public NIP-11 pubkey, which moderation.admin_pubkey defaults to. */
  relayPubkey?: string
  /** The path the relay was actually asked for. */
  requestedPath: string
}

export async function collectRefusalDiagnostics(
  relayApiBase: string,
  refusal: Response,
  requestedPath: string
): Promise<RelayRefusalDiagnostics> {
  const diagnostics: RelayRefusalDiagnostics = { requestedPath }

  const date = refusal.headers.get('date')
  if (date) {
    const parsed = Date.parse(date)
    if (!Number.isNaN(parsed)) {
      diagnostics.relayTimeSeconds = Math.floor(parsed / 1000)
    }
  }

  // Public information: the relay serves this document to anyone.
  try {
    const info = await $fetch<RelayInfo>(relayApiBase, {
      headers: { Accept: 'application/nostr+json' }
    })
    diagnostics.relayPubkey = info.pubkey
  } catch {
    // A diagnosis is a convenience; failing to gather one must not replace
    // the refusal the caller actually needs to hear about.
  }

  return diagnostics
}
