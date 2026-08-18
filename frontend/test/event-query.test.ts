import { describe, expect, it } from 'vitest'
import type { StoredEvent } from '../shared/types/events'
import {
  EVENT_PAGE_SIZE,
  buildEventQuery,
  contentPreview,
  describeResults,
  emptyEventQueryForm,
  kindLabel,
  mergeEventPage,
  shortHex
} from '../shared/utils/event-query'

const form = (overrides: Partial<ReturnType<typeof emptyEventQueryForm>> = {}) => ({
  ...emptyEventQueryForm(),
  ...overrides
})

const storedEvent = (id: string): StoredEvent => ({
  id,
  pubkey: 'a'.repeat(64),
  created_at: 1_700_000_000,
  kind: 1,
  tags: [],
  content: 'stored',
  sig: 'b'.repeat(128)
})

describe('buildEventQuery', () => {
  it('always bounds the request, so no filter means one page rather than everything', () => {
    const { request, errors } = buildEventQuery(form())
    expect(errors).toEqual([])
    expect(request).toEqual({ limit: EVENT_PAGE_SIZE })
  })

  it('parses a comma-separated kind list', () => {
    expect(buildEventQuery(form({ kinds: '1, 7 , 1059' })).request?.kinds).toEqual([1, 7, 1059])
  })

  it('rejects a kind list that is not numbers, rather than sending NaN', () => {
    // Number('one') is NaN, which serializes as null and would filter on
    // nothing — the query would silently widen instead of failing.
    const { request, errors } = buildEventQuery(form({ kinds: '1, one' }))
    expect(request).toBeUndefined()
    expect(errors[0]).toContain('whole numbers')
  })

  it('accepts a hex prefix for author and id, because the relay matches prefixes', () => {
    const { request } = buildEventQuery(form({ author: 'A1B2C3D4', id: 'ff00ff00' }))
    expect(request?.authors).toEqual(['a1b2c3d4'])
    expect(request?.ids).toEqual(['ff00ff00'])
  })

  it('refuses a prefix too short to be a filter, and non-hex input', () => {
    expect(buildEventQuery(form({ author: 'a1' })).errors[0]).toContain('four characters')
    expect(buildEventQuery(form({ id: 'zzzz' })).errors[0]).toContain('hex')
  })

  it('needs both halves of a tag filter, and a single-letter name', () => {
    expect(buildEventQuery(form({ tagName: 'e' })).errors[0]).toContain('both a name and a value')
    expect(buildEventQuery(form({ tagValue: 'x' })).errors[0]).toContain('both a name and a value')
    expect(buildEventQuery(form({ tagName: 'expiration', tagValue: '1' })).errors[0]).toContain('single letter')
    expect(buildEventQuery(form({ tagName: 'e', tagValue: 'abc' })).request?.tags).toEqual({ e: ['abc'] })
  })

  it('converts the time range to unix seconds', () => {
    const { request } = buildEventQuery(form({ since: '2026-01-01T00:00', until: '2026-01-02T00:00' }))
    expect(request?.since).toBe(Math.floor(Date.parse('2026-01-01T00:00') / 1000))
    expect(request?.until).toBe(Math.floor(Date.parse('2026-01-02T00:00') / 1000))
  })

  it('catches a range that can match nothing', () => {
    const built = buildEventQuery(form({ since: '2026-02-01T00:00', until: '2026-01-01T00:00' }))
    expect(built.request).toBeUndefined()
    expect(built.errors[0]).toContain('after To')
  })

  it('enforces the relay\'s minimum content search locally, before a signature is spent', () => {
    expect(buildEventQuery(form({ content: 'ab' })).errors[0]).toContain('3 characters')
    expect(buildEventQuery(form({ content: 'abc' })).request?.content_contains).toBe('abc')
  })

  it('reports every problem at once rather than one per attempt', () => {
    const { errors } = buildEventQuery(form({ kinds: 'x', author: 'q', content: 'a' }))
    expect(errors).toHaveLength(3)
  })

  it('lets the paging cursor override the form\'s upper bound', () => {
    const { request } = buildEventQuery(form({ until: '2026-01-02T00:00' }), 1_699_999_000)
    expect(request?.until).toBe(1_699_999_000)
  })
})

describe('mergeEventPage', () => {
  it('drops events already held, because a timestamp cursor repeats its boundary', () => {
    const first = [storedEvent('a'), storedEvent('b')]
    const second = [storedEvent('b'), storedEvent('c')]
    expect(mergeEventPage(first, second).map(e => e.id)).toEqual(['a', 'b', 'c'])
  })

  it('keeps the order pages arrived in', () => {
    expect(mergeEventPage([storedEvent('a')], [storedEvent('b')]).map(e => e.id)).toEqual(['a', 'b'])
  })
})

describe('display helpers', () => {
  it('names the kinds this relay supports and leaves the rest as numbers', () => {
    expect(kindLabel(1)).toBe('Note (1)')
    expect(kindLabel(1059)).toBe('Gift wrap (1059)')
    expect(kindLabel(31337)).toBe('Kind 31337')
  })

  it('keeps a short identifier whole rather than adding an ellipsis to nothing', () => {
    expect(shortHex('abc')).toBe('abc')
    expect(shortHex('a'.repeat(64))).toBe(`${'a'.repeat(8)}…${'a'.repeat(6)}`)
  })

  it('flattens content to one line and marks where it was cut', () => {
    expect(contentPreview('line one\nline two')).toBe('line one line two')
    expect(contentPreview('x'.repeat(200))).toBe(`${'x'.repeat(90)}…`)
    expect(contentPreview('   ')).toBe('—')
  })
})

describe('describeResults', () => {
  // Before this, all four of these rendered as an empty table with no
  // message, which reads as "the relay has no events" — the report in
  // nostrfi/workspace#49 turned out to be a relay answering zero, and the
  // page gave the operator nothing to tell that from a page that never asked.
  it('tells a query that has not run from one that returned nothing', () => {
    expect(describeResults('idle', 0).emptyMessage).toContain('No query has run yet')
    expect(describeResults('ready', 0).emptyMessage).toContain('The relay answered')
  })

  it('says a query is in flight rather than showing an empty result', () => {
    expect(describeResults('running', 0).label).toBe('Running…')
  })

  it('marks a failed query, so stale rows are not read as current', () => {
    const failed = describeResults('failed', 12)
    expect(failed.label).toBe('Query failed')
    expect(failed.emptyMessage).toContain('reason is above')
  })

  it('counts what is shown, singular and plural', () => {
    expect(describeResults('ready', 1).label).toBe('1 event')
    expect(describeResults('ready', 71).label).toBe('71 events')
    expect(describeResults('ready', 71).emptyMessage).toBe('')
  })
})
