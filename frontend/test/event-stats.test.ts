import { describe, expect, it } from 'vitest'
import {
  fillPeriods,
  formatCount,
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

describe('labels', () => {
  it('shows the precision the granularity calls for', () => {
    const at = utc('2026-03-10T14:00:00Z')
    expect(periodLabel(at, 'month')).toMatch(/2026/)
    expect(periodLabel(at, 'day')).not.toMatch(/:/)
  })

  it('separates thousands so counts compare down a column', () => {
    expect(formatCount(1234567)).toBe((1234567).toLocaleString())
  })
})
