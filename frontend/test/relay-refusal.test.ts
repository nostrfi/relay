import { describe, expect, it } from 'vitest'
import {
  NIP98_DEFAULT_MAX_AGE_SECONDS,
  RELAY_REFUSAL_LOG_HINT,
  describeRelayRefusal
} from '../shared/utils/relay-refusal'

const PUBKEY = 'ec642f38bfef46ab7bcdb5aea1dcdc98ca20cbb4cec7fa1066cafbb5a8b07008'

describe('describeRelayRefusal', () => {
  it('names a slow approval precisely, because that one is knowable', () => {
    // The client measured it, so this is not a guess. A stale signature is
    // the most likely cause when a human had to approve a prompt.
    const refusal = describeRelayRefusal({ signingMs: 95_000 })
    expect(refusal.headline).toContain('95 seconds')
    expect(refusal.headline).toContain(String(NIP98_DEFAULT_MAX_AGE_SECONDS))
    expect(refusal.headline).toContain('Try again')
    expect(refusal.causes).toEqual([])
  })

  it('respects a relay window other than the default', () => {
    expect(describeRelayRefusal({ signingMs: 45_000, maxAgeSeconds: 30 }).headline).toContain('30')
    // Inside a longer window, it is no longer the known cause.
    expect(describeRelayRefusal({ signingMs: 45_000, maxAgeSeconds: 120 }).causes.length).toBeGreaterThan(0)
  })

  it('does not assert a cause when the signature was prompt', () => {
    const refusal = describeRelayRefusal({ signingMs: 800, signedInPubkey: PUBKEY })
    expect(refusal.headline).toContain('does not say which check failed')
    expect(refusal.causes.length).toBe(3)
  })

  it('lists every cause that produces this refusal', () => {
    // Verified against the relay: a stale event, a non-operator key, and a
    // mismatched u tag all answer with an identical bare 401.
    const causes = describeRelayRefusal({ signingMs: 500 }).causes.join(' ')
    expect(causes).toContain('expired')
    expect(causes).toContain('operator')
    expect(causes).toContain('path')
  })

  it('names the signed-in key when it is known, without blaming it', () => {
    const refusal = describeRelayRefusal({ signingMs: 500, signedInPubkey: PUBKEY })
    const keyCause = refusal.causes.find(c => c.includes(PUBKEY))
    expect(keyCause).toBeDefined()
    expect(keyCause).toContain('NUXT_ADMIN_PUBKEY')
    expect(keyCause).toContain('moderation.admin_pubkey')
  })

  it('copes with an unmeasured signature', () => {
    const refusal = describeRelayRefusal({})
    expect(refusal.causes.length).toBe(3)
    expect(refusal.headline).toContain('refused')
  })

  it('points at the log that does know the answer', () => {
    expect(RELAY_REFUSAL_LOG_HINT).toContain('operator request rejected')
  })
})

describe('the log hint', () => {
  it('accompanies a list of possibilities', () => {
    expect(describeRelayRefusal({ signingMs: 500 }).causes.length).toBeGreaterThan(0)
  })

  it('is redundant once the cause is established', () => {
    // useRelayConfig suppresses it in this case: telling an operator to go
    // and find the reason, immediately after stating it, reads as if we had
    // not.
    expect(describeRelayRefusal({ signingMs: 95_000 }).causes).toEqual([])
  })
})
