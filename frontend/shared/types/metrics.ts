/**
 * The relay's Prometheus metrics, shaped for the dashboard.
 *
 * Mirrors what `backend/pkg/metrics` registers — two gauges, two counters,
 * two counters with a bounded label, and one histogram — rather than being a
 * general model of Prometheus. A shape that admitted anything would move the
 * work of knowing what exists into the page.
 */

export interface LatencyHistogram {
  /** The `query` label: `req` or `negentropy`. */
  query: string
  /** Cumulative buckets, ascending by upper bound; `+Inf` last as Infinity. */
  buckets: { le: number, count: number }[]
  /** Total observed seconds, for the mean. */
  sum: number
  /** Total observations. */
  count: number
}

export interface MetricsSnapshot {
  /** When this sample was taken, in unix milliseconds, by the server that took it. */
  at: number

  /**
   * The relay process's start time, in unix seconds, from the Go process
   * collector. Carried so a restart can be detected outright: a counter that
   * merely goes backwards catches most restarts, but not one where the new
   * process passes the old value before the next sample.
   */
  processStartedAt: number | null

  connectionsActive: number
  subscriptionsActive: number
  eventsStored: number
  saveFailures: number

  /** Cumulative message counts by protocol message type. */
  messages: Record<string, number>
  /** Cumulative rejection counts by NIP-01 rejection prefix. */
  rejections: Record<string, number>

  latency: LatencyHistogram[]
}

export interface MetricsResponse {
  snapshot: MetricsSnapshot
  /**
   * What `/readyz` said at the same moment. `docs/observability.md` treats
   * readiness as the primary "is the relay up" signal, ahead of anything
   * derived from traffic, so it travels with the metrics rather than being a
   * second poll the page has to correlate.
   */
  ready: boolean
}
