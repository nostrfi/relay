import { looksLikeRelayMetrics, parsePrometheusText, toSnapshot } from '~~/shared/utils/prometheus'
import type { MetricsResponse } from '~~/shared/types/metrics'

/**
 * Reads the relay's Prometheus metrics for the dashboard.
 *
 * Unlike every other relay call here, this carries no NIP-98 signature — and
 * that is what makes a live view possible at all. The relay serves /metrics
 * to anyone, this server reaches it over the internal network, and the
 * operator is already authenticated by session. A signed endpoint would cost
 * one signer prompt per poll (nostrfi/workspace#39).
 *
 * The text is parsed here rather than in the browser: the page then receives
 * the handful of numbers it draws instead of a few kilobytes of exposition
 * format including the Go runtime's own metrics.
 */
const RELAY_METRICS_TIMEOUT_MS = 5_000

export default defineEventHandler(async (event): Promise<MetricsResponse> => {
  await requireAdminSession(event)

  const { relayApiBase } = useRuntimeConfig(event)
  const base = relayApiBase.replace(/\/$/, '')

  let text: string
  let sampledAt: number
  try {
    const response = await fetch(`${base}/metrics`, { signal: AbortSignal.timeout(RELAY_METRICS_TIMEOUT_MS) })
    if (!response.ok) {
      throw createError({
        statusCode: 502,
        statusMessage: `The relay's metrics endpoint answered ${response.status}`
      })
    }
    text = await response.text()
    // The moment the counters were read. Anything that happens after this —
    // the readiness check below, for one — must not push the timestamp
    // later: rates divide counter deltas by these times, so a slow /readyz
    // would shrink an interval that had already elapsed.
    sampledAt = Date.now()
  } catch (cause) {
    if ((cause as { statusCode?: number })?.statusCode) {
      throw cause
    }
    const timedOut = (cause as Error)?.name === 'TimeoutError'
    throw createError({
      statusCode: 504,
      statusMessage: timedOut
        ? `The relay did not answer within ${RELAY_METRICS_TIMEOUT_MS / 1000} seconds`
        : `The relay could not be reached: ${(cause as Error)?.message ?? 'unknown error'}`
    })
  }

  const lines = parsePrometheusText(text)
  if (!looksLikeRelayMetrics(lines)) {
    // A proxy answering 200 with an HTML page parses to nothing, and every
    // gauge would then read zero — a scrape failure shown as an idle relay.
    throw createError({
      statusCode: 502,
      statusMessage: 'The relay\'s metrics endpoint answered with something that is not Prometheus metrics'
    })
  }

  // Readiness travels with the sample rather than as a second poll the page
  // would have to correlate. docs/observability.md treats it as the primary
  // "is the relay up" signal, ahead of anything derived from traffic — and a
  // failure to answer is itself the answer, so it never throws.
  let ready: boolean
  try {
    const readyz = await fetch(`${base}/readyz`, { signal: AbortSignal.timeout(RELAY_METRICS_TIMEOUT_MS) })
    ready = readyz.ok
  } catch {
    ready = false
  }

  // The relay's address is logged, not returned: it is the internal Docker
  // hostname in a Compose deployment, and AGENTS.md keeps that off the
  // client. The server log is where a surprising number gets traced to a
  // host, and it already carries it.
  console.info(`metrics read: relay=${base}/metrics ready=${ready} series=${lines.length}`)

  return {
    snapshot: toSnapshot(lines, sampledAt),
    ready
  }
})
