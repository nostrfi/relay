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

describe('createRelayRefusalError', () => {
  it('carries the diagnosis both pages render', async () => {
    const { createRelayRefusalError } = await import('../shared/utils/relay-refusal')
    const error = createRelayRefusalError({ signingMs: 500, signedInPubkey: PUBKEY })

    expect(error).toBeInstanceOf(Error)
    expect(error.message).toBe(error.refusal.headline)
    expect(error.refusal.causes.length).toBe(3)
    expect(error.logHint).toBe(RELAY_REFUSAL_LOG_HINT)
  })

  it('drops the log hint once the cause is established', async () => {
    const { createRelayRefusalError } = await import('../shared/utils/relay-refusal')
    const error = createRelayRefusalError({ signingMs: 95_000 })

    expect(error.message).toContain('95 seconds')
    expect(error.logHint).toBe('')
  })
})

describe('describeRelayRefusal with observed facts', () => {
  const NOW = 1_800_000_000

  it('proves a clock skew rather than listing it as a possibility', () => {
    // The relay's own Date header against this browser's clock. No signature
    // made here can satisfy the relay until one of them is fixed, so saying
    // "try again" would be wrong.
    const refusal = describeRelayRefusal({
      signingMs: 500,
      browserTimeSeconds: NOW,
      relayTimeSeconds: NOW + 3600
    })
    expect(refusal.headline).toContain('3600 seconds ahead')
    expect(refusal.headline).toContain('Fix the clock')
    expect(refusal.causes).toEqual([])
  })

  it('reports which way the clocks disagree', () => {
    expect(describeRelayRefusal({ browserTimeSeconds: NOW, relayTimeSeconds: NOW - 600 }).headline)
      .toContain('600 seconds behind')
  })

  it('ignores a skew inside the window, which cannot be the cause', () => {
    const refusal = describeRelayRefusal({ browserTimeSeconds: NOW, relayTimeSeconds: NOW + 5 })
    expect(refusal.causes.length).toBeGreaterThan(0)
  })

  it('proves a path mismatch, which the relay compares exactly', () => {
    const refusal = describeRelayRefusal({
      signedPath: '/api/config',
      requestedPath: '/relay/api/config',
      browserTimeSeconds: NOW
    })
    expect(refusal.headline).toContain('/api/config')
    expect(refusal.headline).toContain('/relay/api/config')
    expect(refusal.causes).toEqual([])
  })

  it('says nothing about paths when they agree', () => {
    const refusal = describeRelayRefusal({
      signedPath: '/api/config',
      requestedPath: '/api/config',
      browserTimeSeconds: NOW
    })
    expect(refusal.headline).not.toContain('signed for')
  })

  it('names a key mismatch from the relay\'s public identity', () => {
    const refusal = describeRelayRefusal({
      signingPubkey: 'a'.repeat(64),
      relayPubkey: 'b'.repeat(64),
      browserTimeSeconds: NOW
    })
    expect(refusal.headline).toContain('a'.repeat(64))
    expect(refusal.headline).toContain('b'.repeat(64))
    expect(refusal.headline).toContain('moderation.admin_pubkey')
    expect(refusal.causes).toEqual([])
  })

  it('stays quiet when the signing key matches the published operator', () => {
    // The relay may still refuse — moderation.admin_pubkey can be set to a
    // third key — so this falls back to the list rather than claiming a cause.
    const refusal = describeRelayRefusal({
      signingPubkey: 'a'.repeat(64),
      relayPubkey: 'a'.repeat(64),
      browserTimeSeconds: NOW
    })
    expect(refusal.causes.length).toBe(3)
  })

  it('prefers the certain explanation over the merely likely one', () => {
    // Both a skew and a key mismatch are present; the skew is provable.
    const refusal = describeRelayRefusal({
      browserTimeSeconds: NOW,
      relayTimeSeconds: NOW + 3600,
      signingPubkey: 'a'.repeat(64),
      relayPubkey: 'b'.repeat(64)
    })
    expect(refusal.headline).toContain('clock')
  })

  it('falls back to possibilities when nothing was observable', () => {
    expect(describeRelayRefusal({ signingMs: 500, browserTimeSeconds: NOW }).causes.length).toBe(3)
  })
})

describe('refusalDiagnosticsFrom', () => {
  const facts = { relayTimeSeconds: 1_800_000_000, relayPubkey: 'a'.repeat(64), requestedPath: '/api/config' }

  it('reads the shape $fetch actually throws', async () => {
    const { refusalDiagnosticsFrom } = await import('../shared/utils/relay-refusal')
    // createError({ data }) arrives as error.data.data, one level deeper
    // than it is natural to assume. Reading too shallow silently produced
    // no diagnosis at all.
    expect(refusalDiagnosticsFrom({ data: { statusCode: 401, data: facts } })).toEqual(facts)
  })

  it('also accepts the flat shape, so the caller need not care', async () => {
    const { refusalDiagnosticsFrom } = await import('../shared/utils/relay-refusal')
    expect(refusalDiagnosticsFrom({ data: facts })).toEqual(facts)
  })

  it('yields nothing usable from an unrelated error', async () => {
    const { refusalDiagnosticsFrom } = await import('../shared/utils/relay-refusal')
    expect(refusalDiagnosticsFrom(new Error('network down'))).toEqual({
      relayTimeSeconds: undefined, relayPubkey: undefined, requestedPath: undefined
    })
    expect(refusalDiagnosticsFrom(undefined)).toEqual({})
  })

  it('ignores values of the wrong type rather than passing them through', async () => {
    const { refusalDiagnosticsFrom } = await import('../shared/utils/relay-refusal')
    const result = refusalDiagnosticsFrom({ data: { data: { relayPubkey: 42, requestedPath: null, relayTimeSeconds: 'soon' } } })
    expect(result).toEqual({ relayTimeSeconds: undefined, relayPubkey: undefined, requestedPath: undefined })
  })
})
