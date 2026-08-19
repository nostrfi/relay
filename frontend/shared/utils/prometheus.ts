import type { LatencyHistogram, MetricsSnapshot } from '~~/shared/types/metrics'

/**
 * Reading the Prometheus text exposition format.
 *
 * Only as much of it as this relay emits, and no more: comments, then lines
 * of `name{label="value",...} number`. Histograms arrive as separate
 * `_bucket`, `_sum` and `_count` series that have to be gathered back into
 * one thing.
 *
 * Kept pure and tested against a real capture, because a parser that quietly
 * mis-reads a line does not fail — it reports a plausible wrong number, and a
 * dashboard is exactly where nobody would notice.
 */

export interface MetricLine {
  name: string
  labels: Record<string, string>
  value: number
}

/** One `name{labels} value` line; comments and blanks are skipped. */
export function parsePrometheusText(body: string): MetricLine[] {
  const lines: MetricLine[] = []

  for (const raw of body.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) {
      continue
    }

    const open = line.indexOf('{')
    let name: string
    let labels: Record<string, string> = {}
    let rest: string

    if (open === -1) {
      const space = line.indexOf(' ')
      if (space === -1) {
        continue
      }
      name = line.slice(0, space)
      rest = line.slice(space + 1)
    } else {
      const close = line.indexOf('}', open)
      if (close === -1) {
        continue
      }
      name = line.slice(0, open)
      labels = parseLabels(line.slice(open + 1, close))
      rest = line.slice(close + 1)
    }

    const value = Number(rest.trim().split(/\s+/)[0])
    if (!Number.isFinite(value) && rest.trim().split(/\s+/)[0] !== '+Inf') {
      continue
    }
    lines.push({ name, labels, value })
  }

  return lines
}

function parseLabels(source: string): Record<string, string> {
  const labels: Record<string, string> = {}
  // Values are quoted and, for this relay, never contain commas or escapes:
  // every label value is a known message type, rejection prefix or query name.
  for (const pair of source.split(',')) {
    const equals = pair.indexOf('=')
    if (equals === -1) {
      continue
    }
    const key = pair.slice(0, equals).trim()
    const value = pair.slice(equals + 1).trim().replace(/^"|"$/g, '')
    if (key !== '') {
      labels[key] = value
    }
  }
  return labels
}

/**
 * Gathers the parsed lines into the shape the dashboard reads, discarding
 * everything the Go runtime and the process collector add — this page is
 * about the relay, not about its garbage collector.
 */
export function toSnapshot(lines: MetricLine[], at: number): MetricsSnapshot {
  const snapshot: MetricsSnapshot = {
    at,
    connectionsActive: 0,
    subscriptionsActive: 0,
    eventsStored: 0,
    saveFailures: 0,
    messages: {},
    rejections: {},
    latency: []
  }

  const histograms = new Map<string, LatencyHistogram>()

  for (const line of lines) {
    switch (line.name) {
      case 'relay_connections_active':
        snapshot.connectionsActive = line.value
        break
      case 'relay_subscriptions_active':
        snapshot.subscriptionsActive = line.value
        break
      case 'relay_events_stored_total':
        snapshot.eventsStored = line.value
        break
      case 'relay_save_failures_total':
        snapshot.saveFailures = line.value
        break
      case 'relay_messages_total':
        if (line.labels.type) {
          snapshot.messages[line.labels.type] = line.value
        }
        break
      case 'relay_rejections_total':
        if (line.labels.reason) {
          snapshot.rejections[line.labels.reason] = line.value
        }
        break
      case 'relay_query_duration_seconds_bucket':
      case 'relay_query_duration_seconds_sum':
      case 'relay_query_duration_seconds_count': {
        const query = line.labels.query ?? 'unknown'
        const histogram = histograms.get(query) ?? { query, buckets: [], sum: 0, count: 0 }
        if (line.name.endsWith('_bucket')) {
          const le = line.labels.le === '+Inf' ? Number.POSITIVE_INFINITY : Number(line.labels.le)
          histogram.buckets.push({ le, count: line.value })
        } else if (line.name.endsWith('_sum')) {
          histogram.sum = line.value
        } else {
          histogram.count = line.value
        }
        histograms.set(query, histogram)
        break
      }
    }
  }

  snapshot.latency = [...histograms.values()]
    .map(histogram => ({ ...histogram, buckets: histogram.buckets.sort((a, b) => a.le - b.le) }))
    .sort((a, b) => a.query.localeCompare(b.query))

  return snapshot
}
