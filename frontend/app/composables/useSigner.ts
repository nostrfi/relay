import type { EventTemplate, VerifiedEvent } from 'nostr-tools/pure'
import { generateSecretKey } from 'nostr-tools/pure'
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46'
import { bytesToHex, hexToBytes } from 'nostr-tools/utils'

/**
 * One signing interface over both supported signers, so feature tickets
 * (nostrfi/workspace#36-#39) can request a signature without knowing whether
 * a browser extension or a remote bunker is behind it.
 */
export interface Signer {
  kind: 'nip07' | 'nip46'
  getPublicKey(): Promise<string>
  signEvent(template: EventTemplate): Promise<VerifiedEvent>
  /** Releases any remote connection. Safe to call more than once. */
  close(): Promise<void>
}

/**
 * The NIP-46 client keypair and bunker URL, persisted so a page reload does
 * not require re-pairing with the remote signer.
 *
 * This is the *client* key of the signer session — the credential the bunker
 * knows this browser by — not the operator's identity key, which never
 * leaves the bunker. It is still a secret in localStorage, readable by any
 * script on this origin, so logout clears it and the bunker can revoke the
 * session independently.
 */
const BUNKER_STORAGE_KEY = 'nf-admin-bunker'

interface StoredBunker {
  clientSecretKey: string
  bunkerUrl: string
}

function readStoredBunker(): StoredBunker | null {
  if (import.meta.server) {
    return null
  }
  const raw = window.localStorage.getItem(BUNKER_STORAGE_KEY)
  if (!raw) {
    return null
  }
  try {
    return JSON.parse(raw) as StoredBunker
  } catch {
    window.localStorage.removeItem(BUNKER_STORAGE_KEY)
    return null
  }
}

export function clearStoredBunker(): void {
  if (import.meta.client) {
    window.localStorage.removeItem(BUNKER_STORAGE_KEY)
  }
}

export function hasNip07(): boolean {
  return import.meta.client && typeof window.nostr !== 'undefined'
}

export function nip07Signer(): Signer {
  const extension = import.meta.client ? window.nostr : undefined
  if (!extension) {
    throw new Error('No NIP-07 signing extension found in this browser')
  }

  return {
    kind: 'nip07',
    getPublicKey: () => extension.getPublicKey(),
    signEvent: template => extension.signEvent(template),
    close: async () => {}
  }
}

/**
 * Connects to a remote signer from a bunker:// URL or a name@domain NIP-05
 * identifier, persisting the pairing for later reloads.
 */
export async function bunkerSigner(input: string): Promise<Signer> {
  const pointer = await parseBunkerInput(input)
  if (!pointer) {
    throw new Error('Not a valid bunker:// URL or NIP-05 identifier')
  }

  const clientSecretKey = generateSecretKey()
  const signer = BunkerSigner.fromBunker(clientSecretKey, pointer)
  await signer.connect()

  if (import.meta.client) {
    window.localStorage.setItem(BUNKER_STORAGE_KEY, JSON.stringify({
      clientSecretKey: bytesToHex(clientSecretKey),
      bunkerUrl: input
    } satisfies StoredBunker))
  }

  return wrapBunker(signer)
}

/**
 * Rebuilds the bunker signer from persisted pairing data, or returns null
 * when this browser has never paired (or the pairing no longer works).
 */
export async function restoreBunkerSigner(): Promise<Signer | null> {
  const stored = readStoredBunker()
  if (!stored) {
    return null
  }

  try {
    const pointer = await parseBunkerInput(stored.bunkerUrl)
    if (!pointer) {
      throw new Error('stored bunker URL no longer parses')
    }
    const signer = BunkerSigner.fromBunker(hexToBytes(stored.clientSecretKey), pointer)
    await signer.connect()
    return wrapBunker(signer)
  } catch {
    clearStoredBunker()
    return null
  }
}

function wrapBunker(signer: BunkerSigner): Signer {
  return {
    kind: 'nip46',
    getPublicKey: () => signer.getPublicKey(),
    signEvent: template => signer.signEvent(template),
    close: () => signer.close()
  }
}
