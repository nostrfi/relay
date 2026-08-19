import { describe, expect, it } from 'vitest'
import { looksLikeRelayMetrics, parsePrometheusText, toSnapshot } from '../shared/utils/prometheus'

/**
 * A real capture from a running relay after publishing five events and
 * opening one subscription, trimmed to the relay's own series. Written out
 * rather than generated so a change in what the relay emits shows up here as
 * a failing test rather than as a quietly empty dashboard.
 */
const CAPTURE = `# HELP relay_connections_active Current number of open WebSocket connections.
# TYPE relay_connections_active gauge
relay_connections_active 0
# HELP relay_events_stored_total Total events successfully persisted.
# TYPE relay_events_stored_total counter
relay_events_stored_total 5
# HELP relay_messages_total Total messages received, by protocol message type.
# TYPE relay_messages_total counter
relay_messages_total{type="CLOSE"} 1
relay_messages_total{type="EVENT"} 5
relay_messages_total{type="REQ"} 1
# HELP relay_query_duration_seconds Repository query duration in seconds, by query type.
# TYPE relay_query_duration_seconds histogram
relay_query_duration_seconds_bucket{query="req",le="0.005"} 1
relay_query_duration_seconds_bucket{query="req",le="0.01"} 1
relay_query_duration_seconds_bucket{query="req",le="0.1"} 1
relay_query_duration_seconds_bucket{query="req",le="+Inf"} 1
relay_query_duration_seconds_sum{query="req"} 0.00126374
relay_query_duration_seconds_count{query="req"} 1
# HELP relay_rejections_total Total rejected messages or events, by rejection reason.
# TYPE relay_rejections_total counter
relay_rejections_total{reason="invalid"} 2
relay_save_failures_total 0
relay_subscriptions_active 0
process_start_time_seconds 1.78715442719e+09
`

describe('parsePrometheusText', () => {
  it('skips comments and blank lines', () => {
    expect(parsePrometheusText(CAPTURE).every(line => !line.name.startsWith('#'))).toBe(true)
  })

  it('reads a bare series and a labelled one', () => {
    const lines = parsePrometheusText(CAPTURE)
    expect(lines.find(l => l.name === 'relay_events_stored_total')?.value).toBe(5)
    const event = lines.find(l => l.name === 'relay_messages_total' && l.labels.type === 'EVENT')
    expect(event?.value).toBe(5)
  })

  it('survives input that is not a metric line', () => {
    expect(parsePrometheusText('garbage\n\n# comment only\nname_without_value')).toEqual([])
  })
})

describe('looksLikeRelayMetrics', () => {
  // A misconfigured proxy answering 200 with an HTML page parses to nothing,
  // and every gauge would then read zero: a scrape failure rendered as a
  // relay sitting perfectly idle (nostrfi/relay#30 review).
  it('rejects a body that carries none of the relay\'s own series', () => {
    expect(looksLikeRelayMetrics(parsePrometheusText('<!doctype html><html></html>'))).toBe(false)
    expect(looksLikeRelayMetrics(parsePrometheusText('go_goroutines 10'))).toBe(false)
  })

  it('accepts the relay\'s own metrics', () => {
    expect(looksLikeRelayMetrics(parsePrometheusText(CAPTURE))).toBe(true)
  })
})

describe('toSnapshot', () => {
  const snapshot = toSnapshot(parsePrometheusText(CAPTURE), 1_700_000_000_000)

  it('picks out the gauges and counters the dashboard shows', () => {
    expect(snapshot.connectionsActive).toBe(0)
    expect(snapshot.eventsStored).toBe(5)
    expect(snapshot.saveFailures).toBe(0)
    expect(snapshot.subscriptionsActive).toBe(0)
  })

  it('keeps the labelled counters by label', () => {
    expect(snapshot.messages).toEqual({ CLOSE: 1, EVENT: 5, REQ: 1 })
    expect(snapshot.rejections).toEqual({ invalid: 2 })
  })

  it('gathers a histogram back into one series, +Inf last', () => {
    expect(snapshot.latency).toHaveLength(1)
    const histogram = snapshot.latency[0]!
    expect(histogram.query).toBe('req')
    expect(histogram.count).toBe(1)
    expect(histogram.sum).toBeCloseTo(0.00126374, 8)
    expect(histogram.buckets.at(-1)!.le).toBe(Number.POSITIVE_INFINITY)
    expect(histogram.buckets.map(b => b.le).slice(0, 3)).toEqual([0.005, 0.01, 0.1])
  })

  it('keeps the process start time, which is how a restart is detected', () => {
    expect(snapshot.processStartedAt).toBeCloseTo(1787154427.19, 2)
  })

  it('ignores everything that is not the relay\'s own instrumentation', () => {
    const withRuntime = `${CAPTURE}go_goroutines 14\nprocess_cpu_seconds_total 0.4\n`
    const parsed = toSnapshot(parsePrometheusText(withRuntime), 0)
    expect(parsed.messages).toEqual({ CLOSE: 1, EVENT: 5, REQ: 1 })
    expect(parsed.eventsStored).toBe(5)
  })
})
