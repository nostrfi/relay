import type { LatencyHistogram, MetricsSnapshot } from '~~/shared/types/metrics'

/**
 * Turning cumulative counters into rates, without a time-series store.
 *
 * Prometheus counters only ever go up, so "messages per second" is a
 * difference between two samples this page took. Two things make that
 * arithmetic wrong in ways that look plausible on screen:
 *
 * A relay restart sets every counter back to zero. Subtracting then yields a
 * large negative rate — or, taken as an absolute value, a spike that never
 * happened. A reset is a lost interval, not a data point, and is reported as
 * such so the page can mark the gap.
 *
 * And the elapsed time has to come from the samples themselves. A polling
 * page that says "every five seconds" does not poll while its tab is hidden
 * or its request is slow, and dividing by the interval it intended rather
 * than the one it got overstates every rate after a stall.
 */

export interface CounterSample {
  value: number
  /** Unix milliseconds when the sample was taken. */
  at: number
  /**
   * The relay process's start time, when known. Two samples from different
   * processes cannot be subtracted, however the numbers happen to compare.
   */
  processStartedAt?: number | null
}

export interface Rate {
  /** Events per second, or null when no rate can honestly be computed. */
  perSecond: number | null
  /** True when the counter went backwards — a restart, not a rate. */
  reset: boolean
}

export function rateBetween(previous: CounterSample | undefined, current: CounterSample): Rate {
  if (!previous) {
    // The first sample has nothing to compare against; a rate of zero would
    // be a claim, not a measurement.
    return { perSecond: null, reset: false }
  }
  const restarted = previous.processStartedAt != null
    && current.processStartedAt != null
    && previous.processStartedAt !== current.processStartedAt

  if (restarted || current.value < previous.value) {
    // A counter going backwards catches most restarts, but not one where the
    // new process passed the old value before the next sample — a busy relay
    // restarting between five-second polls would otherwise report the new
    // process's whole count as an interval's traffic.
    return { perSecond: null, reset: true }
  }
  const seconds = (current.at - previous.at) / 1000
  if (seconds <= 0) {
    return { perSecond: null, reset: false }
  }
  return { perSecond: (current.value - previous.value) / seconds, reset: false }
}

/** Every labelled series in a pair of snapshots, as rates, ranked by size. */
export function labelledRates(
  previous: MetricsSnapshot | undefined,
  current: MetricsSnapshot,
  field: 'messages' | 'rejections'
): { label: string, total: number, rate: Rate }[] {
  return Object.entries(current[field])
    .map(([label, total]) => ({
      label,
      total,
      rate: rateBetween(
        previous
          ? { value: previous[field][label] ?? 0, at: previous.at, processStartedAt: previous.processStartedAt }
          : undefined,
        { value: total, at: current.at, processStartedAt: current.processStartedAt }
      )
    }))
    .sort((a, b) => b.total - a.total)
}

/**
 * A quantile estimated from cumulative histogram buckets, the way
 * `histogram_quantile` does it: find the bucket the rank falls in and
 * interpolate linearly within it.
 *
 * An estimate, and labelled as one wherever it is shown. The relay's twelve
 * buckets are coarse, and interpolation assumes observations are spread
 * evenly inside a bucket, which they are not.
 */
export function quantileFromBuckets(histogram: LatencyHistogram, quantile: number): number | null {
  if (histogram.count <= 0 || histogram.buckets.length === 0) {
    return null
  }

  const rank = quantile * histogram.count
  let previousBound = 0
  let previousCount = 0

  for (const bucket of histogram.buckets) {
    if (bucket.count >= rank) {
      if (!Number.isFinite(bucket.le)) {
        // Everything above the last finite bound; the histogram cannot say
        // more than "at least this".
        return previousBound
      }
      const withinBucket = bucket.count - previousCount
      if (withinBucket <= 0) {
        return bucket.le
      }
      const position = (rank - previousCount) / withinBucket
      return previousBound + (bucket.le - previousBound) * position
    }
    previousBound = Number.isFinite(bucket.le) ? bucket.le : previousBound
    previousCount = bucket.count
  }

  return previousBound
}

/** The mean observation, which needs no interpolation to be honest. */
export function meanSeconds(histogram: LatencyHistogram): number | null {
  return histogram.count > 0 ? histogram.sum / histogram.count : null
}

/** Milliseconds, at a precision that does not imply more than was measured. */
export function formatDuration(seconds: number | null): string {
  if (seconds === null) {
    return '—'
  }
  const ms = seconds * 1000
  if (ms < 1) {
    return `${ms.toFixed(2)} ms`
  }
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`
}

/** A rate, or a word saying why there is not one. */
export function formatRate(rate: Rate, unit = '/s'): string {
  if (rate.reset) {
    return 'restarted'
  }
  if (rate.perSecond === null) {
    return '—'
  }
  if (rate.perSecond === 0) {
    return `0${unit}`
  }
  if (rate.perSecond < 0.01) {
    // Rounding this to two places prints 0.00/s, which says "nothing
    // happened" about traffic that did. One event after a long pause is
    // exactly the case worth not erasing.
    return `<0.01${unit}`
  }
  return rate.perSecond < 1 ? `${rate.perSecond.toFixed(2)}${unit}` : `${rate.perSecond.toFixed(1)}${unit}`
}

/** How long ago a sample was taken, for a page that must not look fresher than it is. */
export function sampleAge(at: number, now = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - at) / 1000))
  if (seconds < 60) {
    return `${seconds}s ago`
  }
  const minutes = Math.floor(seconds / 60)
  return minutes < 60 ? `${minutes}m ago` : `${Math.floor(minutes / 60)}h ago`
}
