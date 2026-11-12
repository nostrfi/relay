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

/**
 * The tag names the relay lets the operator filter by (nostrfi/relay#45),
 * mirroring SupportedFilterTags in backend/internal/domain/event/tags.go. The
 * relay refuses any other name, so offering one here would only spend a
 * signature on a 400.
 */
export const SUPPORTED_FILTER_TAGS: ReadonlyArray<{ name: string, description: string, nips: string }> = [
  { name: 'a', description: 'References an addressable or replaceable event', nips: 'NIP-01' },
  { name: 'alt', description: 'Human-readable summary for custom event kinds', nips: 'NIP-31' },
  { name: 'd', description: 'Unique identifier for addressable events', nips: 'NIP-01' },
  { name: 'e', description: 'References another event', nips: 'NIP-01' },
  { name: 'g', description: 'Geographic location as a geohash', nips: 'NIP-52' },
  { name: 'h', description: 'Group in the relay-based groups system', nips: 'NIP-29' },
  { name: 'i', description: 'External identities and content identifiers', nips: 'NIP-39, NIP-35, NIP-73' },
  { name: 'p', description: 'References a user\'s public key', nips: 'NIP-01' },
  { name: 'q', description: 'References an event in a quote repost', nips: 'NIP-18' },
  { name: 'rank', description: 'Ranking score (0-100) for trusted assertions', nips: 'NIP-85' },
  { name: 'r', description: 'References a URL or relay address', nips: 'NIP-24, NIP-65' },
  { name: 't', description: 'Hashtag', nips: 'NIP-24' },
  { name: '-', description: 'Protected event, publishable only by its author', nips: 'NIP-70' },
  { name: 'client', description: 'Client application that published the event', nips: 'NIP-89' },
  { name: 'emoji', description: 'Custom emoji used in the content', nips: 'NIP-30' },
  { name: 'imeta', description: 'Metadata about media URLs in the content', nips: 'NIP-92' },
  { name: 'proxy', description: 'Source of the event on another protocol', nips: 'NIP-48' },
  { name: 'zap', description: 'Recipients of Lightning payments (zaps)', nips: 'NIP-57' }
]

const SUPPORTED_FILTER_TAG_NAMES = new Set(SUPPORTED_FILTER_TAGS.map(tag => tag.name))

/** One row of the tag filter: a supported tag name and an optional value. */
export interface TagFilterRow {
  name: string
  /** Blank means "the event carries this tag", whatever its value. */
  value: string
}

export const emptyTagFilterRow = (): TagFilterRow => ({ name: '', value: '' })

export interface EventQueryForm {
  /** Comma-separated kind numbers, e.g. "1, 7". */
  kinds: string
  /** Hex pubkey or prefix. */
  author: string
  /** Hex event id or prefix. */
  id: string
  /**
   * Tag filter rows. Different names must all match; rows sharing a name
   * are alternatives, as in NIP-01.
   */
  tags: TagFilterRow[]
  /** datetime-local values, in the browser's own timezone. */
  since: string
  until: string
  content: string
}

export const emptyEventQueryForm = (): EventQueryForm => ({
  kinds: '',
  author: '',
  id: '',
  tags: [emptyTagFilterRow()],
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

  const tags = buildTagFilter(form.tags, errors)
  if (tags !== undefined) {
    request.tags = tags
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

/**
 * Groups the tag rows into the relay's `tags` map, or undefined when no row
 * filters anything. Problems are appended to errors.
 *
 * A blank value asks only that the tag be there, so for that name it
 * outweighs any value rows: "has a t tag, or has t = nostr" is just "has a t
 * tag". The relay reads an empty list as exactly that.
 */
function buildTagFilter(rows: TagFilterRow[], errors: string[]): Record<string, string[]> | undefined {
  const values = new Map<string, Set<string>>()
  const presenceOnly = new Set<string>()
  let missingName = false

  for (const row of rows) {
    const name = row.name.trim()
    const value = row.value.trim()
    if (name === '') {
      // A wholly blank row is just an unused one; a value with no tag is a
      // mistake worth saying so, not a filter to drop silently.
      missingName ||= value !== ''
      continue
    }
    if (!SUPPORTED_FILTER_TAG_NAMES.has(name)) {
      errors.push(`"${name}" is not a tag the relay can filter by.`)
      continue
    }
    if (value === '') {
      presenceOnly.add(name)
    }
    const forName = values.get(name) ?? new Set<string>()
    if (value !== '') {
      forName.add(value)
    }
    values.set(name, forName)
  }

  if (missingName) {
    errors.push('Choose a tag for each tag value.')
  }
  if (values.size === 0) {
    return undefined
  }
  return Object.fromEntries([...values].map(([name, forName]) =>
    [name, presenceOnly.has(name) ? [] : [...forName]]))
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
