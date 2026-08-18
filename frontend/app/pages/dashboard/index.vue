<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'

// Private by default — see app/middleware/auth.global.ts. The only meta here
// is the shell it renders in; no page under /dashboard opts out of the guard.
definePageMeta({ layout: 'dashboard' })

const { state } = useAdminSession()
const { data: relay } = await useFetch('/api/relay-info')

// Matches the sidebar entry and the navbar heading; the tab reads
// "Overview — Relay Admin".
useSeoMeta({ title: 'Overview' })

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
  { name: 'Event browser', issue: 36, description: 'Search and inspect stored events.', to: '/dashboard/events' },
  { name: 'Moderation', issue: 37, description: 'Ban pubkeys, events, and IP ranges via NIP-86.', to: '/dashboard/moderation' },
  { name: 'Configuration', issue: 38, description: 'Review the relay\'s effective settings.', to: '/dashboard/configuration' },
  { name: 'Metrics', issue: 39, description: 'Connection, storage, and throughput observability.', to: null }
]
</script>

<template>
  <UDashboardPanel
    id="overview"
    :ui="{ body: 'max-w-3xl' }"
  >
    <template #header>
      <!-- The title lives in the navbar, which also carries the sidebar
           toggle on a narrow viewport. -->
      <UDashboardNavbar title="Overview" />
    </template>

    <template #body>
      <p
        v-if="npub"
        class="mb-6 text-(--ui-text-muted)"
      >
        Signed in as <span class="font-mono text-sm">{{ npub }}</span>
      </p>

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
            <UButton
              v-if="area.to"
              :to="area.to"
              size="xs"
              variant="subtle"
            >
              Open
            </UButton>
            <UBadge
              v-else
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
    </template>
  </UDashboardPanel>
</template>
