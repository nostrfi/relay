import { beforeEach, describe, expect, it, vi } from 'vitest'
import { allowRequest, resetRateLimits } from '../server/utils/rate-limit'

const LIMIT = { limit: 3, windowMs: 60_000 }

describe('allowRequest', () => {
  beforeEach(() => {
    vi.useRealTimers()
    resetRateLimits()
  })

  it('allows up to the limit, then refuses', () => {
    expect([1, 2, 3].map(() => allowRequest('1.2.3.4', LIMIT))).toEqual([true, true, true])
    expect(allowRequest('1.2.3.4', LIMIT)).toBe(false)
  })

  it('tracks callers independently', () => {
    for (let i = 0; i < 3; i++) {
      allowRequest('1.2.3.4', LIMIT)
    }
    expect(allowRequest('5.6.7.8', LIMIT)).toBe(true)
  })

  it('lets a caller through again in the next window', () => {
    vi.useFakeTimers()
    for (let i = 0; i < 3; i++) {
      allowRequest('1.2.3.4', LIMIT)
    }
    expect(allowRequest('1.2.3.4', LIMIT)).toBe(false)

    vi.advanceTimersByTime(60_001)

    expect(allowRequest('1.2.3.4', LIMIT)).toBe(true)
  })
})
