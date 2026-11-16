/**
 * Forwards a NIP-86 management call to the relay.
 *
 * The browser signs it; this route only proxies, through
 * server/utils/relay-forward.ts, which keeps the body byte-for-byte intact.
 *
 * The relay separates two failure kinds by status: a method-level problem
 * ("pubkey must be 64 hex characters") is a 200 carrying an error envelope,
 * while a failed operator check is a 401 (or a 403 for a known key whose
 * role is too low). Both reach the caller as the relay sent them.
 */
export default defineEventHandler(async (event) => {
  const { pubkey } = await requireAdminSession(event)
  return forwardSignedRequest(event, pubkey, {
    relayPath: '/',
    contentType: 'application/nostr+json+rpc'
  })
})
