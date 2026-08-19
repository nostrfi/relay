import { describe, expect, it } from 'vitest'
import {
  RANGE_PRESETS,
  fillPeriods,
  formatCount,
  offsetLabel,
  periodLabel,
  rankKinds
} from '../shared/utils/event-stats'

const utc = (iso: string) => Math.floor(Date.parse(iso) / 1000)

describe('fillPeriods', () => {
  // The relay returns only periods that hold events. Drawn straight, three
  // bars read as three consecutive hours whether or not silent days sit
  // between them — the chart would be wrong without being empty.
  it('inserts zero-count periods for the silences between answers', () => {
    const points = fillPeriods(
      [{ start: utc('2026-03-10T00:00:00Z'), count: 4 }, { start: utc('2026-03-13T00:00:00Z'), count: 2 }],
      'day',
      utc('2026-03-10T00:00:00Z'),
      utc('2026-03-13T00:00:00Z')
    )
    expect(points.map(p => p.count)).toEqual([4, 0, 0, 2])
  })

  it('steps months by the calendar, not by 30 days', () => {
    // Adding 30 days four times lands on the 27th of April, not the 1st, and
    // every subsequent bucket would then miss its own data.
    const points = fillPeriods(
      [{ start: utc('2026-01-01T00:00:00Z'), count: 1 }, { start: utc('2026-04-01T00:00:00Z'), count: 3 }],
      'month',
      utc('2026-01-01T00:00:00Z'),
      utc('2026-04-01T00:00:00Z')
    )
    expect(points.map(p => new Date(p.start * 1000).toISOString().slice(0, 10))).toEqual([
      '2026-01-01', '2026-02-01', '2026-03-01', '2026-04-01'
    ])
    expect(points.map(p => p.count)).toEqual([1, 0, 0, 3])
  })

  // Found in review of nostrfi/relay#29: the relay's month starts are shifted
  // by the operator's offset, so stepping in UTC produced keys that never
  // match and every real monthly count rendered as zero.
  it('steps months in the same clock the relay bucketed in', () => {
    const offset = 2 * 3600 // UTC+2
    const march = Date.UTC(2026, 2, 1) / 1000 - offset
    const april = Date.UTC(2026, 3, 1) / 1000 - offset

    const points = fillPeriods(
      [{ start: march, count: 5 }, { start: april, count: 9 }],
      'month',
      march,
      april,
      offset
    )
    expect(points.map(p => p.count)).toEqual([5, 9])
  })

  // Also from that review: starting at the first returned period turned a
  // seven-day range whose activity is all today into a one-day chart.
  it('starts at the range boundary, not at the first event', () => {
    const points = fillPeriods(
      [{ start: utc('2026-03-16T00:00:00Z'), count: 3 }],
      'day',
      utc('2026-03-10T00:00:00Z'),
      utc('2026-03-16T00:00:00Z')
    )
    expect(points).toHaveLength(7)
    expect(points.map(p => p.count)).toEqual([0, 0, 0, 0, 0, 0, 3])
  })

  it('draws an axis of zeroes when the relay returned nothing at all', () => {
    const points = fillPeriods([], 'day', utc('2026-03-10T00:00:00Z'), utc('2026-03-12T00:00:00Z'))
    expect(points).toHaveLength(3)
    expect(points.every(p => p.count === 0)).toBe(true)
  })

  it('aligns weeks to Monday, as the relay does', () => {
    // 2026-03-12 is a Thursday; its week starts on the 9th.
    const points = fillPeriods([], 'week', utc('2026-03-12T00:00:00Z'), utc('2026-03-12T00:00:00Z'))
    expect(new Date(points[0]!.start * 1000).toISOString().slice(0, 10)).toBe('2026-03-09')
  })

  it('cannot run away on an absurd range', () => {
    const points = fillPeriods([], 'hour', utc('1990-01-01T00:00:00Z'), utc('2090-01-01T00:00:00Z'))
    expect(points.length).toBeLessThanOrEqual(5000)
  })
})

describe('rankKinds', () => {
  const kinds = [
    { kind: 1, count: 800 },
    { kind: 7, count: 200 },
    { kind: 1059, count: 100 }
  ]

  it('measures bars against the largest kind, so the tail stays legible', () => {
    const { ranked } = rankKinds(kinds)
    expect(ranked.map(k => k.fraction)).toEqual([1, 0.25, 0.125])
  })

  it('keeps the part-to-whole reading a pie would have given', () => {
    const { ranked } = rankKinds(kinds)
    expect(ranked[0]!.share).toBeCloseTo(0.727, 3)
  })

  it('names the kinds rather than showing bare numbers', () => {
    expect(rankKinds(kinds).ranked[0]!.label).toBe('Note (1)')
  })

  it('collects everything past the limit into a remainder', () => {
    const { ranked, remainder } = rankKinds(kinds, 2)
    expect(ranked).toHaveLength(2)
    expect(remainder).toBe(100)
  })

  it('survives an empty breakdown without dividing by zero', () => {
    const { ranked, remainder } = rankKinds([])
    expect(ranked).toEqual([])
    expect(remainder).toBe(0)
  })
})

describe('range presets', () => {
  it('gives the 12-month preset exactly twelve calendar buckets', () => {
    // A rolling 365 days crosses thirteen month boundaries unless it starts
    // on the first of a month, so the control would draw thirteen bars.
    const preset = RANGE_PRESETS.find(p => p.label === '12 months')!
    const until = Math.floor(Date.parse('2026-08-19T13:45:00Z') / 1000)
    const points = fillPeriods([], 'month', preset.since(until, 0), until, 0)
    expect(points).toHaveLength(12)
  })

  it('starts the monthly preset on a month boundary in the operator\'s clock', () => {
    const preset = RANGE_PRESETS.find(p => p.label === '12 months')!
    const offset = 5.5 * 3600 // UTC+5:30
    const since = preset.since(Math.floor(Date.parse('2026-08-19T13:45:00Z') / 1000), offset)
    const local = new Date((since + offset) * 1000)
    expect(local.getUTCDate()).toBe(1)
    expect(local.getUTCHours()).toBe(0)
  })
})

describe('labels', () => {
  it('shows the precision the granularity calls for', () => {
    const at = utc('2026-03-10T14:00:00Z')
    expect(periodLabel(at, 'month')).toMatch(/2026/)
    expect(periodLabel(at, 'day')).not.toMatch(/:/)
  })

  // A label rendered in the browser's local calendar while the bars were
  // bucketed at a fixed offset names the wrong day whenever the two differ,
  // which is every range crossing a daylight-saving change.
  it('renders in the clock the bars were bucketed in, not the browser\'s', () => {
    const midnightAtPlusTwo = Date.UTC(2026, 0, 15) / 1000 - 2 * 3600
    expect(periodLabel(midnightAtPlusTwo, 'day', 2 * 3600)).toBe('15 Jan')
    expect(periodLabel(midnightAtPlusTwo, 'hour', 2 * 3600)).toBe('00:00')
  })

  it('names the clock it used', () => {
    expect(offsetLabel(0)).toBe('UTC')
    expect(offsetLabel(2 * 3600)).toBe('UTC+02:00')
    expect(offsetLabel(-5.5 * 3600)).toBe('UTC−05:30')
  })

  it('separates thousands so counts compare down a column', () => {
    expect(formatCount(1234567)).toBe((1234567).toLocaleString())
  })
})
