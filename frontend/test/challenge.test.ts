import { beforeEach, describe, expect, it, vi } from 'vitest'
import { consumeChallenge, issueChallenge, resetChallenges } from '../server/utils/challenge'

describe('login challenges', () => {
  beforeEach(() => {
    vi.useRealTimers()
    resetChallenges()
  })

  it('issues unique challenges', () => {
    const seen = new Set(Array.from({ length: 50 }, () => issueChallenge()))
    expect(seen.size).toBe(50)
  })

  it('accepts a challenge exactly once', () => {
    const challenge = issueChallenge()
    expect(consumeChallenge(challenge)).toBe(true)
    expect(consumeChallenge(challenge)).toBe(false)
  })

  it('rejects a challenge it never issued', () => {
    expect(consumeChallenge('0'.repeat(64))).toBe(false)
  })

  it('rejects a challenge after its time-to-live', () => {
    vi.useFakeTimers()
    const challenge = issueChallenge()

    vi.advanceTimersByTime(5 * 60 * 1000 + 1)

    expect(consumeChallenge(challenge)).toBe(false)
  })

  it('bounds how many challenges it holds', () => {
    const first = issueChallenge()
    for (let i = 0; i < 300; i++) {
      issueChallenge()
    }
    // The oldest was evicted rather than growing the map without limit.
    expect(consumeChallenge(first)).toBe(false)
  })
})
