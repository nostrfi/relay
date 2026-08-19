import { describe, expect, it } from 'vitest'
import type { LatencyHistogram, MetricsSnapshot } from '../shared/types/metrics'
import {
  formatRate,
  labelledRates,
  meanSeconds,
  quantileFromBuckets,
  rateBetween,
  sampleAge
} from '../shared/utils/metric-rates'

const snapshot = (at: number, messages: Record<string, number>): MetricsSnapshot => ({
  at,
  connectionsActive: 0,
  subscriptionsActive: 0,
  eventsStored: 0,
  saveFailures: 0,
  messages,
  rejections: {},
  latency: []
})

describe('rateBetween', () => {
  it('divides by the time the samples actually took, not the interval intended', () => {
    // A page that polls "every 5s" does not poll while its tab is hidden;
    // dividing by 5 after a 30-second stall overstates the rate six-fold.
    const rate = rateBetween({ value: 100, at: 0 }, { value: 400, at: 30_000 })
    expect(rate.perSecond).toBe(10)
  })

  it('reports a counter going backwards as a restart, not a rate', () => {
    // Prometheus counters only rise; a fall means the relay restarted, and
    // the interval is lost rather than being a measurement of anything.
    const rate = rateBetween({ value: 5_000, at: 0 }, { value: 12, at: 5_000 })
    expect(rate).toEqual({ perSecond: null, reset: true })
  })

  // Raised in review of nostrfi/relay#30: a counter going backwards catches
  // most restarts, but not one where the new process passes the old value
  // before the next sample — a busy relay restarting between polls would
  // report the new process's whole count as one interval's traffic.
  it('detects a restart even when the counter has already passed its old value', () => {
    const rate = rateBetween(
      { value: 1, at: 0, processStartedAt: 1_700_000_000 },
      { value: 2, at: 5_000, processStartedAt: 1_700_000_900 }
    )
    expect(rate).toEqual({ perSecond: null, reset: true })
  })

  it('still rates normally while the process is the same', () => {
    const rate = rateBetween(
      { value: 10, at: 0, processStartedAt: 1_700_000_000 },
      { value: 20, at: 10_000, processStartedAt: 1_700_000_000 }
    )
    expect(rate.perSecond).toBe(1)
  })

  it('has no rate for a first sample', () => {
    expect(rateBetween(undefined, { value: 7, at: 1_000 })).toEqual({ perSecond: null, reset: false })
  })

  it('refuses to divide by a zero or negative interval', () => {
    expect(rateBetween({ value: 1, at: 5_000 }, { value: 9, at: 5_000 }).perSecond).toBeNull()
    expect(rateBetween({ value: 1, at: 9_000 }, { value: 9, at: 5_000 }).perSecond).toBeNull()
  })
})

describe('labelledRates', () => {
  it('rates every series and ranks by total', () => {
    const rates = labelledRates(
      snapshot(0, { EVENT: 10, REQ: 4 }),
      snapshot(10_000, { EVENT: 30, REQ: 6 }),
      'messages'
    )
    expect(rates.map(r => r.label)).toEqual(['EVENT', 'REQ'])
    expect(rates[0]!.rate.perSecond).toBe(2)
    expect(rates[1]!.rate.perSecond).toBeCloseTo(0.2, 5)
  })

  it('treats a label that only appears in the newer sample as starting from zero', () => {
    const rates = labelledRates(snapshot(0, {}), snapshot(10_000, { AUTH: 5 }), 'messages')
    expect(rates[0]!.rate.perSecond).toBeCloseTo(0.5, 5)
  })
})

describe('quantileFromBuckets', () => {
  const histogram: LatencyHistogram = {
    query: 'req',
    buckets: [
      { le: 0.005, count: 5 },
      { le: 0.01, count: 8 },
      { le: 0.1, count: 10 },
      { le: Number.POSITIVE_INFINITY, count: 10 }
    ],
    sum: 0.32,
    count: 10
  }

  it('interpolates inside the bucket the rank falls in', () => {
    // p50 is rank 5, the top of the first bucket.
    expect(quantileFromBuckets(histogram, 0.5)).toBeCloseTo(0.005, 6)
  })

  it('lands in the right bucket for a high quantile', () => {
    const p95 = quantileFromBuckets(histogram, 0.95)!
    expect(p95).toBeGreaterThan(0.01)
    expect(p95).toBeLessThanOrEqual(0.1)
  })

  it('says nothing when nothing was observed', () => {
    expect(quantileFromBuckets({ ...histogram, count: 0 }, 0.95)).toBeNull()
  })

  it('cannot claim more than the last finite bound when the rank is in +Inf', () => {
    const overflowing: LatencyHistogram = {
      query: 'req',
      buckets: [{ le: 0.01, count: 1 }, { le: Number.POSITIVE_INFINITY, count: 10 }],
      sum: 99,
      count: 10
    }
    expect(quantileFromBuckets(overflowing, 0.99)).toBe(0.01)
  })
})

describe('presentation', () => {
  // Also from that review: one event after a long pause is a rate below
  // 0.005, and two decimal places print it as 0.00/s — traffic that happened,
  // shown as traffic that did not.
  it('keeps a tiny rate distinguishable from none at all', () => {
    expect(formatRate({ perSecond: 0.004, reset: false })).toBe('<0.01/s')
    expect(formatRate({ perSecond: 0, reset: false })).toBe('0/s')
  })

  it('names a restart rather than printing a number for it', () => {
    expect(formatRate({ perSecond: null, reset: true })).toBe('restarted')
    expect(formatRate({ perSecond: null, reset: false })).toBe('—')
  })

  it('gives the mean only when there is something to average', () => {
    expect(meanSeconds({ query: 'req', buckets: [], sum: 2, count: 4 })).toBe(0.5)
    expect(meanSeconds({ query: 'req', buckets: [], sum: 0, count: 0 })).toBeNull()
  })

  it('says how old a sample is, so a stalled poller cannot look like a quiet relay', () => {
    expect(sampleAge(1_000_000, 1_005_000)).toBe('5s ago')
    expect(sampleAge(1_000_000, 1_000_000 + 125_000)).toBe('2m ago')
  })
})
