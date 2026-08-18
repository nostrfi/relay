import { describe, expect, it } from 'vitest'
import {
  MAX_REASON_LENGTH,
  validateHexId,
  validateIpOrCidr,
  validateReason
} from '../shared/utils/moderation-validation'

describe('validateHexId', () => {
  it('accepts a 64-character lowercase hex id', () => {
    expect(validateHexId('a'.repeat(64), 'Pubkey')).toBeNull()
  })

  it('trims surrounding whitespace before judging', () => {
    expect(validateHexId(`  ${'a'.repeat(64)}  `, 'Pubkey')).toBeNull()
  })

  it.each([
    ['too short', 'abc123'],
    ['too long', 'a'.repeat(65)],
    ['uppercase hex', 'A'.repeat(64)],
    ['non-hex characters', 'z'.repeat(64)],
    ['npub form', `npub1${'q'.repeat(58)}`],
    ['empty', '']
  ])('rejects %s', (_label, value) => {
    expect(validateHexId(value, 'Pubkey')).toContain('64 lowercase hex')
  })

  it('names the field in its message', () => {
    expect(validateHexId('nope', 'Event ID')).toContain('Event ID')
  })
})

describe('validateIpOrCidr', () => {
  it.each([
    ['IPv4', '203.0.113.4'],
    ['IPv4 CIDR', '203.0.113.0/24'],
    ['IPv4 full range', '0.0.0.0/0'],
    ['IPv6', '2001:db8::1'],
    ['IPv6 CIDR', '2001:db8::/32'],
    ['loopback', '127.0.0.1']
  ])('accepts %s', (_label, value) => {
    expect(validateIpOrCidr(value)).toBeNull()
  })

  it.each([
    ['a word', 'banana'],
    ['an octet above 255', '999.0.0.1'],
    ['two slashes', '10.0.0.0/8/8'],
    ['empty', '']
  ])('rejects %s', (_label, value) => {
    expect(validateIpOrCidr(value)).not.toBeNull()
  })

  it('rejects a prefix beyond the address family width', () => {
    expect(validateIpOrCidr('10.0.0.0/99')).toContain('Prefix length')
    expect(validateIpOrCidr('2001:db8::/129')).toContain('Prefix length')
  })
})

describe('validateReason', () => {
  it('accepts an empty reason, which stays optional', () => {
    expect(validateReason('')).toBeNull()
  })

  it('accepts ordinary text', () => {
    expect(validateReason('repeated spam')).toBeNull()
  })

  it('rejects whitespace-only text, which would store a blank reason', () => {
    expect(validateReason('   ')).toContain('whitespace')
  })

  it('rejects text beyond the relay\'s limit', () => {
    expect(validateReason('x'.repeat(MAX_REASON_LENGTH + 1))).toContain('or fewer')
    expect(validateReason('x'.repeat(MAX_REASON_LENGTH))).toBeNull()
  })
})
