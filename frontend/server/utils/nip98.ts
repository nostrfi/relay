import { verifyEvent } from 'nostr-tools/pure'
import type { Event as NostrEvent } from 'nostr-tools/pure'

/**
 * NIP-98 verification for the dashboard's own login endpoint.
 *
 * This mirrors backend/internal/interfaces/ws/nip98.go, which authenticates
 * the relay's NIP-86 management API, with two deliberate differences:
 *
 *   - the auth event carries a `challenge` tag holding a server-issued
 *     nonce (see server/utils/challenge.ts);
 *   - there is no `payload` tag, because the request body is empty — the
 *     event travels in the Authorization header, so it cannot contain a
 *     hash of a body that contains itself.
 */

const NIP98_AUTH_KIND = 27235
const AUTH_HEADER_PREFIX = 'Nostr '

/** Bounds the work done for an unauthenticated caller. */
const MAX_HEADER_BYTES = 8 * 1024

export interface Nip98Verified {
  pubkey: string
  challenge: string
}

export interface Nip98Expectation {
  /** Path this server observed, e.g. /admin/api/session/login. */
  path: string
  method: string
  maxAgeSeconds: number
}

export class Nip98Error extends Error {}

export function verifyNip98Header(header: string | undefined, expected: Nip98Expectation): Nip98Verified {
  if (!header || !header.startsWith(AUTH_HEADER_PREFIX)) {
    throw new Nip98Error('missing or malformed Authorization header')
  }

  const encoded = header.slice(AUTH_HEADER_PREFIX.length)
  if (encoded.length > MAX_HEADER_BYTES) {
    throw new Nip98Error('Authorization header too large')
  }

  let event: NostrEvent
  try {
    event = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'))
  } catch {
    throw new Nip98Error('invalid event JSON in Authorization header')
  }

  if (event?.kind !== NIP98_AUTH_KIND) {
    throw new Nip98Error(`expected kind ${NIP98_AUTH_KIND}`)
  }

  // verifyEvent checks the id hash and the Schnorr signature together, so a
  // tampered tag or pubkey fails here.
  if (!verifyEvent(event)) {
    throw new Nip98Error('signature verification failed')
  }

  const age = Math.abs(Math.floor(Date.now() / 1000) - event.created_at)
  if (age > expected.maxAgeSeconds) {
    throw new Nip98Error(`created_at is more than ${expected.maxAgeSeconds} seconds from now`)
  }

  const tag = (name: string): string => event.tags.find(t => t[0] === name)?.[1] ?? ''

  if (tag('method').toUpperCase() !== expected.method.toUpperCase()) {
    throw new Nip98Error('method tag does not match request method')
  }

  // Path only, like the Go implementation's sameRequestURL: Caddy terminates
  // TLS, so the scheme and host the browser signed are not what this process
  // observes.
  if (!sameRequestPath(tag('u'), expected.path)) {
    throw new Nip98Error('u tag does not match request URL')
  }

  const challenge = tag('challenge')
  if (!challenge) {
    throw new Nip98Error('missing required challenge tag')
  }

  return { pubkey: event.pubkey, challenge }
}

function sameRequestPath(u: string, observedPath: string): boolean {
  if (!u) {
    return false
  }
  let signed: URL
  try {
    signed = new URL(u)
  } catch {
    return false
  }
  const normalize = (path: string): string => (path === '' ? '/' : path)
  return normalize(signed.pathname) === normalize(observedPath) && signed.search === ''
}
