import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { finalizeEvent, generateSecretKey, verifyEvent } from 'nostr-tools/pure'
import { NIP98_AUTH_KIND, buildRelayAuthTemplate, relayUrlFor, sha256Hex } from '../shared/utils/relay-auth'

const ORIGIN = 'https://relay.example.com'

describe('relayUrlFor', () => {
  it('names the relay root, which is the path the relay observes', () => {
    expect(relayUrlFor('/', ORIGIN)).toBe(`${ORIGIN}/`)
    expect(new URL(relayUrlFor('/', ORIGIN)).pathname).toBe('/')
  })

  it('carries no query string, which the relay compares exactly', () => {
    expect(new URL(relayUrlFor('/', ORIGIN)).search).toBe('')
  })

  it('does not pick up the dashboard base path', () => {
    // Signing /admin/... would be refused: the relay serves NIP-86 from its
    // own root, and only /admin* is routed to the dashboard.
    expect(relayUrlFor('/', 'https://relay.example.com')).not.toContain('/admin')
  })
})

describe('sha256Hex', () => {
  it('matches a known SHA-256 digest', async () => {
    // The relay hashes the raw request bytes with the same algorithm.
    expect(await sha256Hex('')).toBe(createHash('sha256').update('').digest('hex'))
    expect(await sha256Hex('{"method":"listbannedpubkeys","params":[]}'))
      .toBe(createHash('sha256').update('{"method":"listbannedpubkeys","params":[]}').digest('hex'))
  })

  it('hashes bytes, so equivalent JSON with different spacing differs', async () => {
    const compact = await sha256Hex('{"a":1}')
    const spaced = await sha256Hex('{ "a": 1 }')
    expect(compact).not.toBe(spaced)
  })

  it('handles non-ASCII content', async () => {
    const body = '{"reason":"réseau abusif"}'
    expect(await sha256Hex(body)).toBe(createHash('sha256').update(body, 'utf8').digest('hex'))
  })
})

describe('buildRelayAuthTemplate', () => {
  const body = '{"method":"banpubkey","params":["abc","spam"]}'

  it('produces a kind-27235 event with the tags the relay checks', async () => {
    const template = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body, createdAt: 1_700_000_000 })

    expect(template.kind).toBe(NIP98_AUTH_KIND)
    expect(template.created_at).toBe(1_700_000_000)
    expect(template.content).toBe('')

    const tags = Object.fromEntries(template.tags.map(([k, v]) => [k, v]))
    expect(tags.u).toBe(`${ORIGIN}/`)
    expect(tags.method).toBe('POST')
    expect(tags.payload).toBe(createHash('sha256').update(body).digest('hex'))
  })

  it('hashes the exact body it was given, not a re-serialized copy', async () => {
    // A proxy that parsed and re-emitted this JSON would change the bytes
    // and invalidate the signature, which is why the body travels as a
    // string end to end.
    const reserialized = JSON.stringify(JSON.parse(body))
    const original = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body })
    const roundTripped = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body: reserialized })

    const payloadOf = (t: { tags: string[][] }) => t.tags.find(x => x[0] === 'payload')?.[1]
    expect(payloadOf(original)).toBe(payloadOf(roundTripped)) // identical here…

    const spaced = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body: `${body} ` })
    expect(payloadOf(spaced)).not.toBe(payloadOf(original)) // …but any byte difference shows
  })

  it('signs into an event the relay can verify', async () => {
    const template = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body })
    const signed = finalizeEvent(template, generateSecretKey())
    expect(verifyEvent(signed)).toBe(true)
  })

  it('defaults created_at to now, which the relay checks for freshness', async () => {
    const before = Math.floor(Date.now() / 1000)
    const template = await buildRelayAuthTemplate({ path: '/', origin: ORIGIN, body })
    expect(template.created_at).toBeGreaterThanOrEqual(before)
    expect(template.created_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1)
  })
})
