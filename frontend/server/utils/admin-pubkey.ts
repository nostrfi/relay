import type { H3Event } from 'h3'
import type { RelayInfo } from '~~/shared/types/relay-info'

/**
 * Which pubkey may open a dashboard session.
 *
 * NUXT_ADMIN_PUBKEY when set; otherwise the relay's NIP-11 pubkey, mirroring
 * how the relay defaults moderation.admin_pubkey to relay_info.pubkey. The
 * two must name the same operator, but this value is only a UI gate: the
 * relay authorizes real actions itself, so a stale value here lets someone
 * reach the dashboard, never mutate relay state.
 */

const NIP11_CACHE_MS = 5 * 60 * 1000

let cached: { pubkey: string, fetchedAt: number } | null = null

export async function resolveAdminPubkey(event: H3Event): Promise<string> {
  const { adminPubkey, relayApiBase } = useRuntimeConfig(event)
  if (adminPubkey) {
    return adminPubkey
  }

  const now = Date.now()
  if (cached && now - cached.fetchedAt < NIP11_CACHE_MS) {
    return cached.pubkey
  }

  const info = await $fetch<RelayInfo>(relayApiBase, {
    headers: { Accept: 'application/nostr+json' }
  })

  const pubkey = info.pubkey ?? ''
  cached = { pubkey, fetchedAt: now }
  return pubkey
}

/** Test seam: drops the cached NIP-11 lookup. */
export function resetAdminPubkeyCache(): void {
  cached = null
}
