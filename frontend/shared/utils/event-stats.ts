import type { KindCount, StatsBucket, StatsPeriod } from '~~/shared/types/event-stats'
// Relative, not aliased: this is a runtime import, and the unit tests run
// vitest directly rather than through Nuxt's alias resolution.
import { kindLabel } from './event-query'

/**
 * Turning the relay's counts into something a chart can draw.
 *
 * The relay returns only periods that contain events, because it is
 * answering a question about its database, not about an axis. A chart drawn
 * straight from that is a lie: three bars side by side read as three
 * consecutive hours whether or not two silent days sit between them. Filling
 * the gaps is this module's main job, and it is why this is pure and tested
 * rather than inlined into the page.
 */

/** The ranges the overview offers, as a span in seconds. */
export const RANGE_PRESETS = [
  { label: '24 hours', seconds: 24 * 60 * 60, bucket: 'hour' as StatsBucket },
  { label: '7 days', seconds: 7 * 24 * 60 * 60, bucket: 'day' as StatsBucket },
  { label: '30 days', seconds: 30 * 24 * 60 * 60, bucket: 'day' as StatsBucket },
  { label: '12 months', seconds: 365 * 24 * 60 * 60, bucket: 'month' as StatsBucket }
]

/** How long each granularity is, for stepping an axis. Months vary; see below. */
const BUCKET_SECONDS: Record<StatsBucket, number> = {
  hour: 3600,
  day: 86400,
  week: 7 * 86400,
  month: 30 * 86400
}

export interface ChartPoint {
  /** Unix seconds at which the period starts. */
  start: number
  count: number
}

/**
 * Fills the silent periods between the relay's answers.
 *
 * Steps from one returned period to the next by the granularity's own
 * length, so a quiet stretch becomes zero-height bars rather than
 * disappearing. Months are stepped with real calendar arithmetic — adding
 * 30 days four times does not land on the first of the month.
 */
export function fillPeriods(periods: StatsPeriod[], bucket: StatsBucket, since: number, until: number): ChartPoint[] {
  const counts = new Map(periods.map(period => [period.start, period.count]))
  const first = periods.length > 0 ? Math.min(...periods.map(p => p.start)) : alignDown(since, bucket)
  const points: ChartPoint[] = []

  let cursor = first
  // Guarded: a corrupt or absurd range must not spin here, and 5,000 is far
  // past what the relay will return after its own coarsening.
  for (let steps = 0; cursor <= until && steps < 5000; steps++) {
    points.push({ start: cursor, count: counts.get(cursor) ?? 0 })
    cursor = nextPeriod(cursor, bucket)
  }
  return points
}

/** The start of the period containing `at`, in UTC. */
function alignDown(at: number, bucket: StatsBucket): number {
  const date = new Date(at * 1000)
  if (bucket === 'month') {
    return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1) / 1000
  }
  if (bucket === 'week') {
    const day = (date.getUTCDay() + 6) % 7 // Monday, matching the relay's date_trunc
    const monday = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate() - day)
    return monday / 1000
  }
  const size = BUCKET_SECONDS[bucket]
  return Math.floor(at / size) * size
}

function nextPeriod(start: number, bucket: StatsBucket): number {
  if (bucket !== 'month') {
    return start + BUCKET_SECONDS[bucket]
  }
  const date = new Date(start * 1000)
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1) / 1000
}

/**
 * The axis label for a period, at the granularity being drawn: an hourly
 * chart needs the hour, a monthly one needs the month, and neither needs the
 * other's precision.
 */
export function periodLabel(start: number, bucket: StatsBucket): string {
  const date = new Date(start * 1000)
  switch (bucket) {
    case 'hour':
      return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    case 'month':
      return date.toLocaleDateString(undefined, { month: 'short', year: 'numeric' })
    default:
      return date.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
  }
}

/** The full instant, for a tooltip, where precision beats brevity. */
export function periodTooltipLabel(start: number, bucket: StatsBucket): string {
  const date = new Date(start * 1000)
  if (bucket === 'hour') {
    return date.toLocaleString()
  }
  return date.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' })
}

export interface RankedKind {
  kind: number
  label: string
  count: number
  /** 0–1 of the largest count, which is the bar's length. */
  fraction: number
  /** Share of the total, for the figure beside the bar. */
  share: number
}

/**
 * The kind breakdown as a ranked list.
 *
 * A ranked bar rather than a pie: relay traffic is long-tailed — kind 1
 * dominates and the tail is the interesting part — and a pie renders exactly
 * that tail as unreadable slivers. Bar length is relative to the largest
 * kind, so the tail stays legible, while the share figure keeps the
 * part-to-whole reading a pie would have given.
 */
export function rankKinds(kinds: KindCount[], limit = 8): { ranked: RankedKind[], remainder: number } {
  const total = kinds.reduce((sum, kind) => sum + kind.count, 0)
  const largest = kinds.reduce((max, kind) => Math.max(max, kind.count), 0)
  const shown = kinds.slice(0, limit)

  return {
    ranked: shown.map(kind => ({
      kind: kind.kind,
      label: kindLabel(kind.kind),
      count: kind.count,
      fraction: largest > 0 ? kind.count / largest : 0,
      share: total > 0 ? kind.count / total : 0
    })),
    remainder: kinds.slice(limit).reduce((sum, kind) => sum + kind.count, 0)
  }
}

/** Thousands separated, so counts stay comparable down a column. */
export function formatCount(count: number): string {
  return count.toLocaleString()
}
