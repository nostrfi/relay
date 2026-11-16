/**
 * Forwards a signed event-browse query to the relay.
 *
 * The filter is passed through unread. Nothing here decides what an operator
 * may query — the relay authorizes the request against the signer's role,
 * and a check here would only be a second, weaker opinion.
 */
export default defineEventHandler(async (event) => {
  const { pubkey } = await requireAdminSession(event)
  return forwardSignedRequest(event, pubkey, {
    relayPath: '/api/events/query',
    contentType: 'application/json'
  })
})
