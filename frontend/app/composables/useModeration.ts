import type {
  BannedEvent,
  BannedPubkey,
  BlockedIP,
  Nip86Response
} from '~~/shared/types/moderation'

/**
 * One function per NIP-86 method the relay supports. Each returns the
 * relay's envelope unchanged, so a method-level `error` reaches the UI as
 * the relay worded it — those strings are written to be caller-safe, and
 * they are the only place the operator learns why a value was refused.
 */
export function useModeration() {
  const { sign } = useRelayRequest()

  async function call<T>(method: string, params: unknown[]): Promise<Nip86Response<T>> {
    const signer = await acquireSigner()
    try {
      // The relay serves NIP-86 from its root, so that is the path signed
      // into the u tag — not the dashboard route this request is sent to.
      const { authorization, body } = await sign(signer, '/', { method, params })

      return await $fetch<Nip86Response<T>>('/api/moderation/rpc', {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authorization
        }
      })
    } finally {
      // A NIP-46 signer holds a live relay subscription.
      await signer.close()
    }
  }

  return {
    listBannedPubkeys: () => call<BannedPubkey[]>('listbannedpubkeys', []),
    banPubkey: (pubkey: string, reason: string) => call<boolean>('banpubkey', reason ? [pubkey, reason] : [pubkey]),
    unbanPubkey: (pubkey: string) => call<boolean>('unbanpubkey', [pubkey]),

    listBannedEvents: () => call<BannedEvent[]>('listbannedevents', []),
    banEvent: (id: string, reason: string) => call<boolean>('banevent', reason ? [id, reason] : [id]),
    allowEvent: (id: string) => call<boolean>('allowevent', [id]),

    listBlockedIPs: () => call<BlockedIP[]>('listblockedips', []),
    blockIP: (ip: string, reason: string) => call<boolean>('blockip', reason ? [ip, reason] : [ip]),
    unblockIP: (ip: string) => call<boolean>('unblockip', [ip])
  }
}
