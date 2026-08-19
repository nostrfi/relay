<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'
import type { EventStatsResponse, StatsBucket } from '~~/shared/types/event-stats'
import type { QueryPhase } from '~~/shared/utils/event-query'
import {
  RANGE_PRESETS,
  fillPeriods,
  formatCount,
  rankKinds
} from '~~/shared/utils/event-stats'

// Matches the sidebar entry and the navbar heading; the tab reads
// "Overview — Relay Admin".
useSeoMeta({ title: 'Overview' })

// Private by default — see app/middleware/auth.global.ts. The only meta here
// is the shell it renders in; no page under /dashboard opts out of the guard.
definePageMeta({ layout: 'dashboard' })

const { state } = useAdminSession()
const { data: relay } = await useFetch('/api/relay-info')
const { fetchStats } = useEventStats()

const npub = computed(() => {
  const pubkey = state.value?.pubkey
  return pubkey ? npubEncode(pubkey) : null
})

const stats = ref<EventStatsResponse | null>(null)
const phase = ref<QueryPhase>('idle')
const error = ref('')
const refusalCauses = ref<string[]>([])
const refusalLogHint = ref('')

/** Which preset the operator is looking at; the default is a week. */
const rangeIndex = ref(1)
const range = computed(() => RANGE_PRESETS[rangeIndex.value] ?? RANGE_PRESETS[1]!)

async function load() {
  phase.value = 'running'
  error.value = ''
  refusalCauses.value = []
  refusalLogHint.value = ''

  const until = Math.floor(Date.now() / 1000)
  try {
    stats.value = await fetchStats({
      since: until - range.value.seconds,
      until,
      bucket: range.value.bucket,
      // The operator's clock, so "today" means their today rather than the
      // server's. The relay reports back which offset it applied.
      utc_offset_minutes: -new Date().getTimezoneOffset()
    })
    phase.value = 'ready'
  } catch (cause) {
    const refused = cause as { refusal?: { headline: string, causes: string[] }, logHint?: string }
    error.value = refused.refusal?.headline || (cause as Error)?.message || 'The event statistics could not be read.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
    phase.value = 'failed'
  }
}

onMounted(load)
watch(rangeIndex, load)

/**
 * The relay returns only periods that hold events, so the silences are
 * filled here — three bars in a row must not read as three consecutive days
 * when two quiet ones sit between them.
 */
const points = computed(() => {
  const current = stats.value
  if (!current) {
    return []
  }
  return fillPeriods(current.periods, current.bucket, current.since, current.until)
})

const kinds = computed(() => rankKinds(stats.value?.kinds ?? []))

const busy = computed(() => phase.value === 'running')

/**
 * What the charts say when they have nothing to draw. An empty range against
 * a relay holding a million events means something different from the same
 * range against an empty relay, and the difference is the whole reason
 * stored_total is in the response (nostrfi/workspace#49).
 */
const emptyMessage = computed(() => {
  if (phase.value === 'idle') {
    return 'No statistics have been read yet.'
  }
  if (phase.value === 'running') {
    return 'Asking the relay…'
  }
  if (phase.value === 'failed') {
    return 'The last request failed, so there is nothing current to show. The reason is above.'
  }
  const current = stats.value
  if (!current || current.total > 0) {
    return ''
  }
  return current.stored_total > 0
    ? `No events in this range. The relay holds ${formatCount(current.stored_total)} in total — try a longer range.`
    : 'This relay has no stored events at all.'
})

/** The granularity the relay applied, which it may have coarsened. */
const appliedBucket = computed<StatsBucket | null>(() => stats.value?.bucket ?? null)
const coarsened = computed(() => appliedBucket.value !== null && appliedBucket.value !== range.value.bucket)
</script>

<template>
  <UDashboardPanel id="overview">
    <template #header>
      <UDashboardNavbar title="Overview">
        <template #right>
          <UButton
            icon="i-lucide-refresh-cw"
            size="xs"
            variant="ghost"
            color="neutral"
            :loading="busy"
            @click="load"
          >
            Refresh
          </UButton>
        </template>
      </UDashboardNavbar>
    </template>

    <template #body>
      <!--
        Identity as one line rather than a card of NIP-11 fields: the
        configuration page shows them in full, and repeating them here was
        most of what made this page worth replacing (nostrfi/workspace#50).
      -->
      <p class="mb-6 text-sm text-(--ui-text-muted)">
        <span class="font-medium text-(--ui-text)">{{ relay?.name || 'Nostrfi Relay' }}</span>
        <span v-if="relay?.version"> · <span class="nf-tabular">{{ relay.version }}</span></span>
        <span v-if="npub"> · signed in as <span class="font-mono">{{ npub.slice(0, 12) }}…</span></span>
      </p>

      <div
        v-if="error"
        class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
        role="alert"
      >
        <p>{{ error }}</p>

        <ul
          v-if="refusalCauses.length > 0"
          class="mt-3 flex list-disc flex-col gap-2 pl-5"
        >
          <li
            v-for="cause in refusalCauses"
            :key="cause"
          >
            {{ cause }}
          </li>
        </ul>

        <p
          v-if="refusalLogHint"
          class="mt-3"
        >
          {{ refusalLogHint }}
        </p>

        <UButton
          class="mt-4"
          size="xs"
          variant="subtle"
          :loading="busy"
          @click="load"
        >
          Try again
        </UButton>
      </div>

      <UCard class="mb-6">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 class="font-display text-lg font-semibold">
                Events received
              </h2>
              <p class="text-sm text-(--ui-text-muted)">
                <template v-if="phase === 'ready' && stats">
                  <span class="nf-tabular">{{ formatCount(stats.total) }}</span> in this range,
                  by {{ appliedBucket }}<template v-if="coarsened">
                    — coarsened from {{ range.bucket }} to keep the chart readable
                  </template>.
                </template>
                <template v-else>
                  Stored events over time, as the relay counts them.
                </template>
              </p>
            </div>

            <UFieldGroup size="xs">
              <UButton
                v-for="(preset, index) in RANGE_PRESETS"
                :key="preset.label"
                :variant="index === rangeIndex ? 'solid' : 'outline'"
                :color="index === rangeIndex ? 'primary' : 'neutral'"
                :disabled="busy"
                @click="rangeIndex = index"
              >
                {{ preset.label }}
              </UButton>
            </UFieldGroup>
          </div>
        </template>

        <ChartsEventsOverTime
          v-if="phase === 'ready' && stats && stats.total > 0"
          :points="points"
          :bucket="stats.bucket"
        />
        <p
          v-else
          class="py-8 text-sm text-(--ui-text-muted)"
        >
          {{ emptyMessage }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <div>
            <h2 class="font-display text-lg font-semibold">
              Event kinds
            </h2>
            <p class="text-sm text-(--ui-text-muted)">
              What those events are, ranked by how many of each the relay stored.
            </p>
          </div>
        </template>

        <ChartsKindBreakdown
          v-if="phase === 'ready' && kinds.ranked.length > 0"
          :kinds="kinds.ranked"
          :remainder="kinds.remainder"
        />
        <p
          v-else
          class="py-8 text-sm text-(--ui-text-muted)"
        >
          {{ emptyMessage }}
        </p>
      </UCard>
    </template>
  </UDashboardPanel>
</template>
