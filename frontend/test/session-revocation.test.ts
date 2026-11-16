import { describe, expect, it } from 'vitest'
import { createSessionRevocations } from '../server/utils/session-revocation'

const HOUR_MS = 60 * 60 * 1000

describe('createSessionRevocations', () => {
  it('honours a session this process issued', () => {
    const revocations = createSessionRevocations('boot-1')
    expect(revocations.isLive({ sid: 's1', boot: 'boot-1' })).toBe(true)
  })

  it('stops honouring a revoked sid, whatever copy of the cookie carries it', () => {
    const revocations = createSessionRevocations('boot-1')
    const now = Date.now()
    revocations.revoke('s1', now + HOUR_MS, now)
    expect(revocations.isLive({ sid: 's1', boot: 'boot-1' })).toBe(false)
    expect(revocations.isLive({ sid: 's2', boot: 'boot-1' })).toBe(true)
  })

  it('refuses sessions issued before a restart', () => {
    // The revoked sids of the old process are gone, so none of its sessions
    // can be told apart from one that was logged out.
    const before = createSessionRevocations('boot-1')
    const after = createSessionRevocations('boot-2')
    expect(before.isLive({ sid: 's1', boot: 'boot-1' })).toBe(true)
    expect(after.isLive({ sid: 's1', boot: 'boot-1' })).toBe(false)
  })

  it('refuses a session with no sid or no boot', () => {
    const revocations = createSessionRevocations('boot-1')
    expect(revocations.isLive({ boot: 'boot-1' })).toBe(false)
    expect(revocations.isLive({ sid: 's1' })).toBe(false)
  })

  it('forgets a revocation once the cookie it guards has expired', () => {
    const revocations = createSessionRevocations('boot-1')
    const now = Date.now()
    revocations.revoke('s1', now + HOUR_MS, now)
    revocations.revoke('s2', now + 3 * HOUR_MS, now + 2 * HOUR_MS)
    expect(revocations.size()).toBe(1)
  })

  it('does not record a revocation that has already expired', () => {
    const revocations = createSessionRevocations('boot-1')
    const now = Date.now()
    revocations.revoke('s1', now - 1, now)
    expect(revocations.size()).toBe(0)
  })

  it('issues a fresh boot id per process by default', () => {
    expect(createSessionRevocations().bootId).not.toBe(createSessionRevocations().bootId)
  })
})
