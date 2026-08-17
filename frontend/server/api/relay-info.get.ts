import type { RelayInfo } from '~~/shared/types/relay-info'

export default defineEventHandler(async (event): Promise<RelayInfo> => {
  // The dashboard is an administrative surface: route middleware only
  // redirects the browser, so every data route enforces the session itself.
  await requireAdminSession(event)

  const { relayApiBase } = useRuntimeConfig(event)

  return await $fetch<RelayInfo>(relayApiBase, {
    headers: { Accept: 'application/nostr+json' }
  })
})
