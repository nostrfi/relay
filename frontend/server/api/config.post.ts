/**
 * Forwards a signed configuration read to the relay.
 *
 * Owner only, here as on the relay (D3, nostrfi/relay#55). The relay is the
 * authority and refuses an administrator itself; checking here as well
 * answers with a clear 403 before a signature is spent on a request that
 * cannot succeed.
 */
export default defineEventHandler(async (event) => {
  const { pubkey } = await requireAdminSession(event, { minimum: 'owner' })
  return forwardSignedRequest(event, pubkey, {
    relayPath: '/api/config',
    contentType: 'application/json'
  })
})
