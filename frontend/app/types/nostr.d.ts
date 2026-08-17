import type { WindowNostr } from 'nostr-tools/nip07'

declare global {
  interface Window {
    /** Injected by a NIP-07 signing extension, when the operator has one. */
    nostr?: WindowNostr
  }
}

export {}
