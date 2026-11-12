import type { MetricsSnapshot } from '~~/shared/types/metrics'

/**
 * The Overview's traffic light, reduced to one of four words.
 *
 * Green, amber and red are the three lamps; "unknown" lights none of them.
 * It is kept apart from "error" on purpose: a relay this page cannot reach is
 * not the same claim as a relay that answered and said it is not ready, and a
 * lamp left lit from the last good poll would be the page asserting something
 * it can no longer check.
 */
export type RelayStatus = 'ok' | 'paused' | 'error' | 'unknown'

export function relayStatus(ready: boolean | null, failing: boolean, paused: boolean): RelayStatus {
  if (failing) {
    return 'unknown'
  }
  // Paused is this page not watching — the tab is in the background — rather
  // than anything the relay reported. The relay has no paused state of its own.
  if (paused) {
    return 'paused'
  }
  if (ready === null) {
    return 'unknown'
  }
  return ready ? 'ok' : 'error'
}

/**
 * How long the relay process has been running, coarse enough to read at a
 * glance: two units at most, the larger first.
 *
 * `startedAt` is unix seconds (the Go process collector's start time) and
 * `now` unix milliseconds, matching where each comes from.
 */
export function formatUptime(startedAt: number | null, now: number): string {
  if (startedAt === null) {
    return '—'
  }
  const seconds = Math.max(0, Math.floor(now / 1000 - startedAt))
  if (seconds < 60) {
    return `${seconds}s`
  }
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) {
    return `${minutes}m`
  }
  const hours = Math.floor(minutes / 60)
  if (hours < 24) {
    return `${hours}h ${minutes % 60}m`
  }
  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

/**
 * One gauge across the samples this page has taken, for a sparkline.
 *
 * A gauge needs no differencing, but a line drawn across a restart joins two
 * different processes as if they were one, so the first sample of a new
 * process starts a fresh segment.
 */
export function gaugeSeries(
  samples: MetricsSnapshot[],
  field: 'connectionsActive' | 'subscriptionsActive'
): (number | null)[] {
  const series: (number | null)[] = []
  samples.forEach((sample, index) => {
    const previous = samples[index - 1]
    const restarted = previous !== undefined
      && previous.processStartedAt != null
      && sample.processStartedAt != null
      && previous.processStartedAt !== sample.processStartedAt
    if (restarted) {
      series.push(null)
    }
    series.push(sample[field])
  })
  return series
}
