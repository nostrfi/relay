import type { RelayInfo } from '~~/shared/types/relay-info'

export default defineEventHandler(async (): Promise<RelayInfo> => {
  const { relayApiBase } = useRuntimeConfig()

  return await $fetch<RelayInfo>(relayApiBase, {
    headers: { Accept: 'application/nostr+json' }
  })
})
