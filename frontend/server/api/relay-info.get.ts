import type { RelayInfo } from '~~/shared/types/relay-info'

/**
 * Public, deliberately: this proxies the relay's NIP-11 document, which the
 * relay serves to any anonymous caller that asks with
 * `Accept: application/nostr+json`. Requiring a session here would protect
 * nothing while making the dashboard's public face a login wall
 * (nostrfi/workspace#46).
 *
 * Every route that returns operational state or proxies an action still
 * calls requireAdminSession.
 */
export default defineEventHandler(async (event): Promise<RelayInfo> => {
  const { relayApiBase } = useRuntimeConfig(event)

  return await $fetch<RelayInfo>(relayApiBase, {
    headers: { Accept: 'application/nostr+json' }
  })
})
