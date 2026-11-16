import type {
  BannedEvent,
  BannedPubkey,
  BlockedIP
} from '~~/shared/types/moderation'

/**
 * One function per NIP-86 method the relay supports. Each returns the
 * relay's envelope unchanged, so a method-level `error` reaches the UI as
 * the relay worded it — those strings are written to be caller-safe, and
 * they are the only place the operator learns why a value was refused.
 */
export function useModeration() {
  const { call } = useNip86()

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
