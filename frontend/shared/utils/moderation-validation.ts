/**
 * Client-side mirrors of the relay's validation
 * (backend/internal/interfaces/ws/management.go).
 *
 * These exist so the operator sees the problem before a signature is
 * requested — not as the enforcement, which stays on the relay for every
 * caller. Keep the two in step: a value accepted here and refused there is
 * a confusing round trip, and the reverse blocks a legitimate action.
 */

const HEX_ID = /^[0-9a-f]{64}$/

export function validateHexId(value: string, label: string): string | null {
  return HEX_ID.test(value.trim()) ? null : `${label} must be 64 lowercase hex characters`
}

export function validateIpOrCidr(value: string): string | null {
  const candidate = value.trim()
  if (candidate === '') {
    return 'Enter an IP address or CIDR range'
  }

  const [address, prefix, ...rest] = candidate.split('/')
  if (rest.length > 0 || address === undefined) {
    return 'Not a valid IP address or CIDR range'
  }

  const isV4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(address)
    && address.split('.').every(part => Number(part) <= 255)
  // Deliberately permissive on IPv6 shapes: the relay's net.ParseIP is the
  // authority, and rejecting something it would accept is the worse error.
  const isV6 = address.includes(':') && /^[0-9a-fA-F:.]+$/.test(address)

  if (!isV4 && !isV6) {
    return 'Not a valid IP address or CIDR range'
  }

  if (prefix !== undefined) {
    const bits = Number(prefix)
    const max = isV4 ? 32 : 128
    if (!/^\d+$/.test(prefix) || bits > max) {
      return `Prefix length must be between 0 and ${max}`
    }
  }

  return null
}

export const MAX_REASON_LENGTH = 500

export function validateReason(reason: string): string | null {
  if (reason.length > MAX_REASON_LENGTH) {
    return `Reason must be ${MAX_REASON_LENGTH} characters or fewer`
  }
  if (reason !== '' && reason.trim() === '') {
    return 'Reason must not be only whitespace'
  }
  return null
}
