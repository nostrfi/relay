<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'

// Private by default — see app/middleware/auth.global.ts. No definePageMeta
// opt-out here, and none on any future feature page.
const { state } = useAdminSession()
const { data: relay } = await useFetch('/api/relay-info')

useSeoMeta({ title: 'Dashboard' })

const npub = computed(() => {
  const pubkey = state.value?.pubkey
  return pubkey ? npubEncode(pubkey) : null
})

/**
 * Entry points for the administrative areas. Each becomes a real link as its
 * ticket lands; until then the operator can see what is coming rather than
 * facing an empty page.
 */
const areas = [
  { name: 'Event browser', issue: 36, description: 'Search and inspect stored events.' },
  { name: 'Moderation', issue: 37, description: 'Ban pubkeys, events, and IP ranges via NIP-86.' },
  { name: 'Configuration', issue: 38, description: 'Review the relay\'s effective settings.' },
  { name: 'Metrics', issue: 39, description: 'Connection, storage, and throughput observability.' }
]
</script>

<template>
  <div class="mx-auto max-w-3xl">
    <header class="mb-8">
      <h1 class="font-display text-3xl font-semibold tracking-tight">
        Dashboard
      </h1>
      <p
        v-if="npub"
        class="mt-2 text-(--ui-text-muted)"
      >
        Signed in as <span class="font-mono text-sm">{{ npub }}</span>
      </p>
    </header>

    <RelayInfoCards :relay="relay" />

    <UCard class="mt-6">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Admin areas</span>
      </template>

      <ul class="flex flex-col gap-4">
        <li
          v-for="area in areas"
          :key="area.issue"
          class="flex items-start justify-between gap-4"
        >
          <div>
            <p class="font-medium">
              {{ area.name }}
            </p>
            <p class="text-sm text-(--ui-text-muted)">
              {{ area.description }}
            </p>
          </div>
          <UBadge
            variant="subtle"
            color="neutral"
          >
            #{{ area.issue }}
          </UBadge>
        </li>
      </ul>

      <template #footer>
        <p class="text-sm text-(--ui-text-dimmed)">
          Each area opens here as its ticket lands.
        </p>
      </template>
    </UCard>
  </div>
</template>
