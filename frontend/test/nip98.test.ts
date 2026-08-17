import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { EventTemplate } from 'nostr-tools/pure'
import { Nip98Error, verifyNip98Header } from '../server/utils/nip98'

const LOGIN_PATH = '/admin/api/session/login'
const EXPECTED = { path: LOGIN_PATH, method: 'POST', maxAgeSeconds: 60 }

const secretKey = generateSecretKey()
const pubkey = getPublicKey(secretKey)

interface Overrides {
  kind?: number
  createdAt?: number
  u?: string
  method?: string
  challenge?: string | null
}

function authHeader(overrides: Overrides = {}, signWith = secretKey): string {
  const tags: string[][] = [
    ['u', overrides.u ?? `https://relay.example.com${LOGIN_PATH}`],
    ['method', overrides.method ?? 'POST']
  ]
  if (overrides.challenge !== null) {
    tags.push(['challenge', overrides.challenge ?? 'a'.repeat(64)])
  }

  const template: EventTemplate = {
    kind: overrides.kind ?? 27235,
    created_at: overrides.createdAt ?? Math.floor(Date.now() / 1000),
    tags,
    content: ''
  }

  return `Nostr ${Buffer.from(JSON.stringify(finalizeEvent(template, signWith))).toString('base64')}`
}

describe('verifyNip98Header', () => {
  it('accepts a correctly signed event and returns its pubkey and challenge', () => {
    const result = verifyNip98Header(authHeader(), EXPECTED)
    expect(result.pubkey).toBe(pubkey)
    expect(result.challenge).toBe('a'.repeat(64))
  })

  it('accepts a signature over a different scheme and host', () => {
    // Caddy terminates TLS, so only the path is comparable.
    const header = authHeader({ u: `http://localhost:3000${LOGIN_PATH}` })
    expect(verifyNip98Header(header, EXPECTED).pubkey).toBe(pubkey)
  })

  it.each([
    ['a missing header', undefined],
    ['a header without the Nostr prefix', 'Bearer something'],
    ['a header that is not base64 JSON', 'Nostr not-base64-json']
  ])('rejects %s', (_label, header) => {
    expect(() => verifyNip98Header(header, EXPECTED)).toThrow(Nip98Error)
  })

  it('rejects the wrong event kind', () => {
    expect(() => verifyNip98Header(authHeader({ kind: 1 }), EXPECTED)).toThrow(/kind/)
  })

  it('rejects a tampered event', () => {
    const header = authHeader()
    const raw = JSON.parse(Buffer.from(header.slice('Nostr '.length), 'base64').toString('utf8'))
    raw.tags.push(['challenge', 'b'.repeat(64)])
    const tampered = `Nostr ${Buffer.from(JSON.stringify(raw)).toString('base64')}`

    expect(() => verifyNip98Header(tampered, EXPECTED)).toThrow(/signature/)
  })

  it('rejects an event signed by a different key than it claims', () => {
    const header = authHeader({}, generateSecretKey())
    expect(verifyNip98Header(header, EXPECTED).pubkey).not.toBe(pubkey)
  })

  it('rejects a stale event', () => {
    const header = authHeader({ createdAt: Math.floor(Date.now() / 1000) - 120 })
    expect(() => verifyNip98Header(header, EXPECTED)).toThrow(/created_at/)
  })

  it('rejects an event signed for a different path', () => {
    const header = authHeader({ u: 'https://relay.example.com/admin/api/session/logout' })
    expect(() => verifyNip98Header(header, EXPECTED)).toThrow(/u tag/)
  })

  it('rejects an event signed for a different method', () => {
    expect(() => verifyNip98Header(authHeader({ method: 'GET' }), EXPECTED)).toThrow(/method/)
  })

  it('rejects an event with no challenge tag', () => {
    expect(() => verifyNip98Header(authHeader({ challenge: null }), EXPECTED)).toThrow(/challenge/)
  })
})
