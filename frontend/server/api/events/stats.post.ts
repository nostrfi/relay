/**
 * Forwards a signed statistics request to the relay.
 *
 * Identical in shape to the browse proxy next door: the browser signs, this
 * route forwards the bytes unread, and the relay authorizes. The counts are
 * as privileged as the events they count.
 */

/**
 * How long the relay gets to answer before the page is told it did not.
 *
 * Bounded: a relay that accepts the connection and then stops responding
 * would otherwise leave this request pending until the platform's own
 * network timeout, with the overview stuck busy and its range controls
 * disabled the whole time. Counting is a small read; ten seconds is
 * generous for it (AGENTS.md, "Frontend Conventions").
 */
const RELAY_STATS_TIMEOUT_MS = 10_000

export default defineEventHandler(async (event) => {
  const { pubkey } = await requireAdminSession(event)
  return forwardSignedRequest(event, pubkey, {
    relayPath: '/api/events/stats',
    contentType: 'application/json',
    timeoutMs: RELAY_STATS_TIMEOUT_MS
  })
})
