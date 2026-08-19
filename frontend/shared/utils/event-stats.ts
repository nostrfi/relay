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

/**
 * The ranges the overview offers.
 *
 * `since` is computed rather than a fixed span, because a rolling 365 days
 * crosses thirteen month boundaries whenever it does not start on the first
 * of a month — a control labelled "12 months" would draw thirteen bars. The
 * monthly preset therefore starts at a month boundary in the operator's own
 * clock.
 */
export interface RangePreset {
  label: string
  bucket: StatsBucket
  /** The range start for this preset, given "now" and the operator's offset. */
  since: (until: number, offsetSeconds: number) => number
}

export const RANGE_PRESETS: RangePreset[] = [
  { label: '24 hours', bucket: 'hour', since: until => until - 24 * 60 * 60 },
  { label: '7 days', bucket: 'day', since: until => until - 7 * 24 * 60 * 60 },
  { label: '30 days', bucket: 'day', since: until => until - 30 * 24 * 60 * 60 },
  {
    label: '12 months',
    bucket: 'month',
    since: (until, offsetSeconds) => {
      // The first instant of the month eleven months back, so the range
      // covers exactly twelve monthly buckets including the current one.
      const shifted = new Date((until + offsetSeconds) * 1000)
      const start = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth() - 11, 1) / 1000
      return start - offsetSeconds
    }
  }
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
 * Two things this has to get right, both of which produce a chart that looks
 * fine and is wrong.
 *
 * It steps in the *same clock the relay bucketed in*. The relay's period
 * starts are shifted by the operator's offset, so stepping a month in UTC
 * lands on keys that do not exist and every real count reads as zero — the
 * silences would swallow the data (nostrfi/relay#29 review).
 *
 * And it starts at the range boundary, not at the first event. A seven-day
 * range whose activity is all today is a one-day chart otherwise, quietly
 * dropping the six quiet days that are the interesting part of the answer.
 */
export function fillPeriods(
  periods: StatsPeriod[],
  bucket: StatsBucket,
  since: number,
  until: number,
  offsetSeconds = 0
): ChartPoint[] {
  const counts = new Map(periods.map(period => [period.start, period.count]))
  const points: ChartPoint[] = []

  let cursor = alignDown(since, bucket, offsetSeconds)
  // Guarded: a corrupt or absurd range must not spin here, and 5,000 is far
  // past what the relay will return after its own coarsening.
  for (let steps = 0; cursor <= until && steps < 5000; steps++) {
    points.push({ start: cursor, count: counts.get(cursor) ?? 0 })
    cursor = nextPeriod(cursor, bucket, offsetSeconds)
  }
  return points
}

/** The start of the period containing `at`, in the operator's shifted clock. */
function alignDown(at: number, bucket: StatsBucket, offsetSeconds: number): number {
  const shifted = new Date((at + offsetSeconds) * 1000)
  if (bucket === 'month') {
    return Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), 1) / 1000 - offsetSeconds
  }
  if (bucket === 'week') {
    const day = (shifted.getUTCDay() + 6) % 7 // Monday, matching the relay's date_trunc
    const monday = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate() - day)
    return monday / 1000 - offsetSeconds
  }
  const size = BUCKET_SECONDS[bucket]
  return Math.floor((at + offsetSeconds) / size) * size - offsetSeconds
}

function nextPeriod(start: number, bucket: StatsBucket, offsetSeconds: number): number {
  if (bucket !== 'month') {
    return start + BUCKET_SECONDS[bucket]
  }
  const shifted = new Date((start + offsetSeconds) * 1000)
  return Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth() + 1, 1) / 1000 - offsetSeconds
}

/**
 * The axis label for a period, at the granularity being drawn: an hourly
 * chart needs the hour, a monthly one needs the month, and neither needs the
 * other's precision.
 *
 * Rendered in the *fixed offset the relay bucketed with*, not the browser's
 * local calendar. Those differ whenever the range crosses a daylight-saving
 * transition, and formatting a January boundary with August's offset labels
 * it as the 31st of December — a bar named for the wrong month
 * (nostrfi/relay#29 review). The page states the offset alongside, so a
 * label is never ambiguous about which clock it is in.
 */
export function periodLabel(start: number, bucket: StatsBucket, offsetSeconds = 0): string {
  const shifted = new Date((start + offsetSeconds) * 1000)
  switch (bucket) {
    case 'hour':
      return `${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}`
    case 'month':
      return `${MONTHS[shifted.getUTCMonth()]} ${shifted.getUTCFullYear()}`
    default:
      return `${shifted.getUTCDate()} ${MONTHS[shifted.getUTCMonth()]}`
  }
}

/** The full instant, for a tooltip, where precision beats brevity. */
export function periodTooltipLabel(start: number, bucket: StatsBucket, offsetSeconds = 0): string {
  const shifted = new Date((start + offsetSeconds) * 1000)
  const date = `${WEEKDAYS[shifted.getUTCDay()]} ${shifted.getUTCDate()} ${MONTHS[shifted.getUTCMonth()]} ${shifted.getUTCFullYear()}`
  return bucket === 'hour' ? `${date}, ${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}` : date
}

/** How to name the clock the labels are in, for the caption beside a chart. */
export function offsetLabel(offsetSeconds: number): string {
  if (offsetSeconds === 0) {
    return 'UTC'
  }
  const sign = offsetSeconds > 0 ? '+' : '−'
  const minutes = Math.abs(Math.round(offsetSeconds / 60))
  return `UTC${sign}${pad(Math.floor(minutes / 60))}:${pad(minutes % 60)}`
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

const pad = (value: number) => String(value).padStart(2, '0')

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
