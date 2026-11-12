import { describe, expect, it } from 'vitest'
import type { MetricsSnapshot } from '../shared/types/metrics'
import { formatUptime, gaugeSeries, relayStatus } from '../shared/utils/relay-status'

describe('relayStatus', () => {
  it.each([
    { ready: true, failing: false, paused: false, expected: 'ok' },
    { ready: false, failing: false, paused: false, expected: 'error' },
    { ready: true, failing: false, paused: true, expected: 'paused' },
    { ready: false, failing: false, paused: true, expected: 'paused' },
    // Before the first sample lands, nothing is known yet.
    { ready: null, failing: false, paused: false, expected: 'unknown' },
    // A failed read outranks everything: the last answer is no longer current.
    { ready: true, failing: true, paused: false, expected: 'unknown' },
    { ready: null, failing: true, paused: true, expected: 'unknown' }
  ] as const)('ready=$ready failing=$failing paused=$paused → $expected', ({ ready, failing, paused, expected }) => {
    expect(relayStatus(ready, failing, paused)).toBe(expected)
  })
})

describe('formatUptime', () => {
  const started = 1_700_000_000
  const at = (seconds: number) => (started + seconds) * 1000

  it.each([
    { elapsed: 0, expected: '0s' },
    { elapsed: 42, expected: '42s' },
    { elapsed: 60, expected: '1m' },
    { elapsed: 59 * 60 + 59, expected: '59m' },
    { elapsed: 3600, expected: '1h 0m' },
    { elapsed: 4 * 3600 + 12 * 60, expected: '4h 12m' },
    { elapsed: 86_400, expected: '1d 0h' },
    { elapsed: 3 * 86_400 + 4 * 3600 + 59 * 60, expected: '3d 4h' }
  ])('$elapsed seconds → $expected', ({ elapsed, expected }) => {
    expect(formatUptime(started, at(elapsed))).toBe(expected)
  })

  it('shows a dash when the relay does not report a start time', () => {
    expect(formatUptime(null, at(100))).toBe('—')
  })

  it('never goes negative when the clocks disagree', () => {
    expect(formatUptime(started, at(-5))).toBe('0s')
  })
})

describe('gaugeSeries', () => {
  const sample = (connectionsActive: number, processStartedAt: number | null): MetricsSnapshot => ({
    at: 0,
    processStartedAt,
    connectionsActive,
    subscriptionsActive: 0,
    eventsStored: 0,
    saveFailures: 0,
    messages: {},
    rejections: {},
    latency: []
  })

  it('reads the gauge from each sample in order', () => {
    expect(gaugeSeries([sample(3, 1), sample(5, 1), sample(4, 1)], 'connectionsActive')).toEqual([3, 5, 4])
  })

  it('breaks the line where the process changed', () => {
    expect(gaugeSeries([sample(9, 1), sample(10, 1), sample(1, 2)], 'connectionsActive')).toEqual([9, 10, null, 1])
  })

  it('does not invent a restart when the start time is unknown', () => {
    expect(gaugeSeries([sample(9, null), sample(1, 2)], 'connectionsActive')).toEqual([9, 1])
  })
})
