import type { EventQueryRequest, StoredEvent } from '~~/shared/types/events'

/**
 * Turning the browser's filter form into a request the relay will accept,
 * and the rows it answers with into something readable.
 *
 * Kept out of the page for the same reason the configuration view was: this
 * is where a wrong answer would be quiet. A filter built slightly wrong does
 * not fail — it returns the wrong events, and nothing on screen says so.
 */

/** One page of events. Every page costs the operator a signature. */
export const EVENT_PAGE_SIZE = 100

/** The relay refuses a shorter content search; it is an unindexed scan. */
export const MIN_CONTENT_SEARCH_LENGTH = 3

/** A hex id or pubkey, or a prefix of one — the relay matches prefixes. */
const HEX = /^[0-9a-f]+$/

/** Below this a prefix matches so much that it is not a filter. */
const MIN_HEX_PREFIX_LENGTH = 4

export interface EventQueryForm {
  /** Comma-separated kind numbers, e.g. "1, 7". */
  kinds: string
  /** Hex pubkey or prefix. */
  author: string
  /** Hex event id or prefix. */
  id: string
  /** Single-letter tag name, e.g. "e" or "p". */
  tagName: string
  tagValue: string
  /** datetime-local values, in the browser's own timezone. */
  since: string
  until: string
  content: string
}

export const emptyEventQueryForm = (): EventQueryForm => ({
  kinds: '',
  author: '',
  id: '',
  tagName: '',
  tagValue: '',
  since: '',
  until: '',
  content: ''
})

export interface EventQueryBuild {
  request?: EventQueryRequest
  /** Everything wrong with the form, so it is fixed in one pass. */
  errors: string[]
}

/**
 * Builds the request, or every reason it cannot be built.
 *
 * `until` overrides the form's own upper bound: it carries the cursor from
 * the previous page, which is how "Load more" continues a query rather than
 * re-running it.
 */
export function buildEventQuery(form: EventQueryForm, until?: number): EventQueryBuild {
  const errors: string[] = []
  const request: EventQueryRequest = { limit: EVENT_PAGE_SIZE }

  const kinds = form.kinds
    .split(',')
    .map(part => part.trim())
    .filter(part => part !== '')
  if (kinds.length > 0) {
    const parsed = kinds.map(Number)
    if (parsed.some(kind => !Number.isInteger(kind) || kind < 0)) {
      errors.push('Kinds must be whole numbers, separated by commas — for example 1, 7.')
    } else {
      request.kinds = parsed
    }
  }

  const author = form.author.trim().toLowerCase()
  if (author !== '') {
    if (!HEX.test(author) || author.length < MIN_HEX_PREFIX_LENGTH) {
      errors.push('Author must be a hex pubkey, or at least the first four characters of one.')
    } else {
      request.authors = [author]
    }
  }

  const id = form.id.trim().toLowerCase()
  if (id !== '') {
    if (!HEX.test(id) || id.length < MIN_HEX_PREFIX_LENGTH) {
      errors.push('Event ID must be hex, or at least the first four characters of one.')
    } else {
      request.ids = [id]
    }
  }

  const tagName = form.tagName.trim()
  const tagValue = form.tagValue.trim()
  if (tagName !== '' || tagValue !== '') {
    if (tagName === '' || tagValue === '') {
      errors.push('A tag filter needs both a name and a value.')
    } else if (tagName.length !== 1) {
      errors.push('Tag name must be a single letter, as NIP-01 filters only index single-letter tags.')
    } else {
      request.tags = { [tagName]: [tagValue] }
    }
  }

  const since = parseLocalDateTime(form.since)
  if (form.since !== '' && since === undefined) {
    errors.push('From is not a valid date and time.')
  } else if (since !== undefined) {
    request.since = since
  }

  const formUntil = parseLocalDateTime(form.until)
  if (form.until !== '' && formUntil === undefined) {
    errors.push('To is not a valid date and time.')
  } else if (formUntil !== undefined) {
    request.until = formUntil
  }

  if (since !== undefined && formUntil !== undefined && since > formUntil) {
    errors.push('From is after To, so no event can match.')
  }

  const content = form.content.trim()
  if (content !== '') {
    if (content.length < MIN_CONTENT_SEARCH_LENGTH) {
      errors.push(`Content search needs at least ${MIN_CONTENT_SEARCH_LENGTH} characters.`)
    } else {
      request.content_contains = content
    }
  }

  // The cursor wins: it is the previous page's oldest event, always at or
  // below the form's own upper bound.
  if (until !== undefined) {
    request.until = until
  }

  return errors.length > 0 ? { errors } : { request, errors }
}

/** Unix seconds from a datetime-local value, or undefined when unusable. */
function parseLocalDateTime(value: string): number | undefined {
  if (value.trim() === '') {
    return undefined
  }
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? undefined : Math.floor(parsed / 1000)
}

/**
 * Appends a page, dropping events already held.
 *
 * The relay's cursor is a timestamp, so events sharing the boundary second
 * arrive on both pages — a documented consequence of not paging by offset.
 * Without this the table would show them twice.
 */
export function mergeEventPage(existing: StoredEvent[], incoming: StoredEvent[]): StoredEvent[] {
  const seen = new Set(existing.map(event => event.id))
  return [...existing, ...incoming.filter(event => !seen.has(event.id))]
}

/**
 * The kinds this relay documents supporting, named. Anything else keeps its
 * number rather than being guessed at.
 */
const KIND_LABELS: Record<number, string> = {
  0: 'Metadata',
  1: 'Note',
  2: 'Relay recommendation',
  3: 'Contacts',
  5: 'Deletion',
  6: 'Repost',
  7: 'Reaction',
  13: 'Seal',
  14: 'Chat message',
  21: 'Video',
  22: 'Short video',
  40: 'Channel',
  41: 'Channel metadata',
  42: 'Channel message',
  1059: 'Gift wrap',
  1111: 'Comment',
  22242: 'Auth'
}

export function kindLabel(kind: number): string {
  const label = KIND_LABELS[kind]
  return label ? `${label} (${kind})` : `Kind ${kind}`
}

/** Truncated with the full value kept accessible, per the brand rule. */
export function shortHex(value: string, lead = 8): string {
  return value.length <= lead + 6 ? value : `${value.slice(0, lead)}…${value.slice(-6)}`
}

/**
 * A one-line preview. Newlines become spaces so a multi-line note cannot
 * stretch a table row, and the cut is marked rather than silent.
 */
export function contentPreview(content: string, max = 90): string {
  const flattened = content.replace(/\s+/g, ' ').trim()
  if (flattened === '') {
    return '—'
  }
  return flattened.length <= max ? flattened : `${flattened.slice(0, max)}…`
}

/** Absolute local time: an operator correlating with relay logs needs it exact. */
export function formatEventTime(createdAt: number): string {
  return new Date(createdAt * 1000).toLocaleString()
}

/**
 * What the results area is doing, so it can say so.
 *
 * The page used to track only "has a query ever succeeded", which left the
 * table blank and silent in three different situations — before the first
 * query, while one was running, and after one failed — all of which read as
 * "this relay has no events" (nostrfi/workspace#49). An operator cannot act
 * on that: "the relay answered nothing" and "the page never asked" need
 * different fixes.
 */
export type QueryPhase = 'idle' | 'running' | 'ready' | 'failed'

export interface ResultsSummary {
  /** Short status for the results header. */
  label: string
  /** What to say when there is no row to show; empty when there are rows. */
  emptyMessage: string
}

export function describeResults(phase: QueryPhase, count: number): ResultsSummary {
  if (phase === 'running') {
    return { label: 'Running…', emptyMessage: 'Asking the relay…' }
  }
  if (phase === 'failed') {
    return {
      label: 'Query failed',
      emptyMessage: 'The last query failed, so nothing here is up to date. The reason is above.'
    }
  }
  if (phase === 'idle') {
    return { label: 'Not run yet', emptyMessage: 'No query has run yet.' }
  }
  if (count === 0) {
    return {
      label: '0 events',
      emptyMessage: 'The relay answered, and no stored event matches this filter. '
        + 'Expired events and events banned through moderation are never returned.'
    }
  }
  return { label: count === 1 ? '1 event' : `${count} events`, emptyMessage: '' }
}
