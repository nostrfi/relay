import { decode } from 'nostr-tools/nip19'

/**
 * Client-side mirrors of the relay's checks on `assignrole`
 * (admin.ValidatePubkey, admin.ValidateLabel and ErrOwnerNotGrantable in
 * backend/internal/domain/admin/entity.go).
 *
 * As with moderation-validation.ts, these spare the owner a signer prompt
 * for a value the relay would refuse. The relay stays the enforcement.
 */

const HEX_PUBKEY = /^[0-9a-f]{64}$/

export const MAX_ADMINISTRATOR_LABEL_LENGTH = 100

export type AdministratorKeyResult = { pubkey: string, error?: undefined } | { pubkey?: undefined, error: string }

/**
 * Reads an administrator key typed as an `npub` or as 64 lowercase hex
 * characters, and returns the hex form the relay stores.
 *
 * An `nsec` is refused by name: someone pasting one has just exposed a
 * private key, and should be told so rather than only "not valid".
 */
export function parseAdministratorKey(input: string, ownerPubkey?: string): AdministratorKeyResult {
  const value = input.trim()
  if (value === '') {
    return { error: 'Enter an npub or a 64-character hex pubkey' }
  }

  let pubkey: string
  if (value.startsWith('nsec1')) {
    return { error: 'That is a private key (nsec). Never paste it here — use the administrator\'s public key (npub).' }
  } else if (value.startsWith('npub1')) {
    try {
      const decoded = decode(value)
      if (decoded.type !== 'npub') {
        return { error: 'Not a valid npub' }
      }
      pubkey = decoded.data
    } catch {
      return { error: 'Not a valid npub: check it was copied in full' }
    }
  } else if (/^n[a-z]+1/.test(value)) {
    return { error: 'Use an npub or a hex pubkey, not another kind of Nostr identifier' }
  } else if (HEX_PUBKEY.test(value)) {
    pubkey = value
  } else if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return { error: 'Hex pubkeys must be lowercase' }
  } else {
    return { error: 'Not a valid key: enter an npub or 64 lowercase hex characters' }
  }

  if (ownerPubkey !== undefined && pubkey === ownerPubkey) {
    return { error: 'That is the owner\'s key. The owner comes from the relay configuration and cannot be made an administrator.' }
  }
  return { pubkey }
}

export function validateAdministratorLabel(label: string): string | null {
  // Code points, to match the relay's rune count.
  if ([...label].length > MAX_ADMINISTRATOR_LABEL_LENGTH) {
    return `Label must be ${MAX_ADMINISTRATOR_LABEL_LENGTH} characters or fewer`
  }
  if (label !== '' && label.trim() === '') {
    return 'Label must not be only whitespace'
  }
  return null
}
