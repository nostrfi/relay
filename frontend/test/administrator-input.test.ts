import { describe, expect, it } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { neventEncode, nprofileEncode, npubEncode, nsecEncode } from 'nostr-tools/nip19'
import {
  MAX_ADMINISTRATOR_LABEL_LENGTH,
  parseAdministratorKey,
  validateAdministratorLabel
} from '../shared/utils/administrator-input'

const secret = generateSecretKey()
const pubkey = getPublicKey(secret)
const owner = getPublicKey(generateSecretKey())

describe('parseAdministratorKey', () => {
  it('accepts lowercase hex', () => {
    expect(parseAdministratorKey(pubkey, owner)).toEqual({ pubkey })
  })

  it('decodes an npub to hex', () => {
    expect(parseAdministratorKey(npubEncode(pubkey), owner)).toEqual({ pubkey })
  })

  it('trims surrounding whitespace', () => {
    expect(parseAdministratorKey(`  ${npubEncode(pubkey)}\n`, owner)).toEqual({ pubkey })
  })

  it('refuses an nsec and warns that it is a private key', () => {
    expect(parseAdministratorKey(nsecEncode(secret), owner).error).toContain('private key')
  })

  it.each([
    ['nprofile', nprofileEncode({ pubkey })],
    ['nevent', neventEncode({ id: pubkey })]
  ])('refuses an %s', (_kind, value) => {
    expect(parseAdministratorKey(value, owner).error).toContain('not another kind')
  })

  it('refuses an npub with a broken checksum', () => {
    const npub = npubEncode(pubkey)
    const last = npub.at(-1) === 'q' ? 'p' : 'q'
    expect(parseAdministratorKey(npub.slice(0, -1) + last, owner).error).toContain('Not a valid npub')
  })

  it('refuses uppercase hex', () => {
    expect(parseAdministratorKey(pubkey.toUpperCase(), owner).error).toContain('lowercase')
  })

  it.each([
    ['too short', 'abc123'],
    ['too long', 'a'.repeat(65)],
    ['non-hex', 'z'.repeat(64)]
  ])('refuses a key that is %s', (_label, value) => {
    expect(parseAdministratorKey(value, owner).error).toContain('Not a valid key')
  })

  it('refuses an empty key', () => {
    expect(parseAdministratorKey('   ', owner).error).toContain('Enter')
  })

  it('refuses the owner, in hex or npub form', () => {
    expect(parseAdministratorKey(owner, owner).error).toContain('owner')
    expect(parseAdministratorKey(npubEncode(owner), owner).error).toContain('owner')
  })

  it('accepts any valid key when the owner is unknown', () => {
    expect(parseAdministratorKey(owner)).toEqual({ pubkey: owner })
  })
})

describe('validateAdministratorLabel', () => {
  it('accepts an empty label', () => {
    expect(validateAdministratorLabel('')).toBeNull()
  })

  it('accepts a label at the limit, counted in code points', () => {
    expect(validateAdministratorLabel('😀'.repeat(MAX_ADMINISTRATOR_LABEL_LENGTH))).toBeNull()
  })

  it('refuses a label over the limit', () => {
    expect(validateAdministratorLabel('a'.repeat(MAX_ADMINISTRATOR_LABEL_LENGTH + 1))).toContain('or fewer')
  })

  it('refuses a whitespace-only label', () => {
    expect(validateAdministratorLabel('   ')).toContain('whitespace')
  })
})
