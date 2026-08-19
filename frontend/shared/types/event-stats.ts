/**
 * The operator statistics API, mirroring eventStatsRequest and
 * eventStatsResponse in backend/internal/interfaces/ws/events_stats_api.go.
 */

export type StatsBucket = 'hour' | 'day' | 'week' | 'month'

export interface EventStatsRequest {
  /** Unix seconds, inclusive. */
  since?: number
  until?: number
  bucket?: StatsBucket
  /** Shifts period boundaries onto the operator's clock; absent means UTC. */
  utc_offset_minutes?: number
}

export interface StatsPeriod {
  /** Unix seconds at which the period starts. */
  start: number
  count: number
}

export interface KindCount {
  kind: number
  count: number
}

export interface EventStatsResponse {
  /** Periods with events. Empty ones are absent — the caller fills the axis. */
  periods: StatsPeriod[]
  /** Ordered by count, descending. */
  kinds: KindCount[]
  /** Events in the range: the sum of the periods. */
  total: number
  /** Every event on disk, so an empty range can say which kind of empty it is. */
  stored_total: number
  /** What the relay actually applied, which may be coarser than asked. */
  bucket: StatsBucket
  since: number
  until: number
  utc_offset_minutes: number
}
