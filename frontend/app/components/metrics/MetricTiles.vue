<script setup lang="ts">
import type { MetricsSnapshot } from '~~/shared/types/metrics'
import { formatCount } from '~~/shared/utils/event-stats'
import { sampleAge } from '~~/shared/utils/metric-rates'

/**
 * What the relay is doing right now, as figures rather than charts.
 *
 * A single current value is a stat tile, not a chart — a one-bar bar chart
 * says less and takes more room. The age of the sample sits alongside,
 * because a poller that has stopped looks exactly like a quiet relay
 * otherwise.
 */
const props = defineProps<{
  snapshot: MetricsSnapshot | null
  ready: boolean | null
  paused: boolean
  /** True when the last poll failed, so these figures are stale. */
  failing: boolean
}>()

const now = ref(Date.now())
let ticker: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  ticker = setInterval(() => {
    now.value = Date.now()
  }, 1000)
})
onBeforeUnmount(() => {
  if (ticker !== null) {
    clearInterval(ticker)
  }
})

const tiles = computed(() => {
  const snapshot = props.snapshot
  return [
    { label: 'Connections', value: snapshot ? formatCount(snapshot.connectionsActive) : '—' },
    { label: 'Subscriptions', value: snapshot ? formatCount(snapshot.subscriptionsActive) : '—' },
    { label: 'Events stored', value: snapshot ? formatCount(snapshot.eventsStored) : '—' },
    { label: 'Save failures', value: snapshot ? formatCount(snapshot.saveFailures) : '—' }
  ]
})

const age = computed(() => (props.snapshot ? sampleAge(props.snapshot.at, now.value) : null))
</script>

<template>
  <UCard class="mb-6">
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2">
          <h2 class="font-display text-lg font-semibold">
            Right now
          </h2>
          <!--
            Unknown is its own state. A green badge left over from the last
            successful poll, standing beside an error, is the page asserting
            something it can no longer check.
          -->
          <UBadge
            v-if="failing || ready === null"
            color="neutral"
            variant="subtle"
            icon="i-lucide-help-circle"
          >
            Not reading
          </UBadge>
          <UBadge
            v-else
            :color="ready ? 'success' : 'error'"
            variant="subtle"
            :icon="ready ? 'i-lucide-check' : 'i-lucide-triangle-alert'"
          >
            {{ ready ? 'Ready' : 'Not ready' }}
          </UBadge>
        </div>

        <p class="text-sm text-(--ui-text-dimmed)">
          <template v-if="failing">
            The last read failed — these figures are stale.
          </template>
          <template v-else-if="paused">
            Paused while this tab is in the background.
          </template>
          <template v-else-if="age">
            Sampled {{ age }}
          </template>
        </p>
      </div>
    </template>

    <dl class="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <div
        v-for="tile in tiles"
        :key="tile.label"
      >
        <dt class="text-sm text-(--ui-text-muted)">
          {{ tile.label }}
        </dt>
        <dd class="nf-tabular font-display text-2xl font-semibold">
          {{ tile.value }}
        </dd>
      </div>
    </dl>

    <template #footer>
      <p class="text-sm text-(--ui-text-dimmed)">
        Live from the relay's <code class="font-mono">/metrics</code>, refreshed every 5 seconds.
        Counters reset when the relay restarts.
      </p>
    </template>
  </UCard>
</template>
