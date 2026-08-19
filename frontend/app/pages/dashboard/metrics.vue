<script setup lang="ts">
import { formatCount } from '~~/shared/utils/event-stats'
import {
  formatDuration,
  formatRate,
  labelledRates,
  meanSeconds,
  quantileFromBuckets,
  rateBetween
} from '~~/shared/utils/metric-rates'

useSeoMeta({ title: 'Metrics' })

// Private by default — see app/middleware/auth.global.ts.
definePageMeta({ layout: 'dashboard' })

const { samples, latest, previous, ready, error, paused, refresh } = useRelayMetrics()

/**
 * Rates are ranked tables with one sparkline each rather than a multi-series
 * chart. Message types and rejection reasons both need more series than the
 * brand has validated categorical hues, and the tail — which reason is
 * rising — is the part worth reading (nostrfi/workspace#39).
 */
const messageRates = computed(() =>
  latest.value ? labelledRates(previous.value, latest.value, 'messages') : []
)
const rejectionRates = computed(() =>
  latest.value ? labelledRates(previous.value, latest.value, 'rejections') : []
)

/** The rate history for one label, oldest first, with gaps preserved. */
function historyFor(field: 'messages' | 'rejections', label: string): (number | null)[] {
  const series: (number | null)[] = []
  for (let i = 1; i < samples.value.length; i++) {
    const before = samples.value[i - 1]!
    const after = samples.value[i]!
    const rate = rateBetween(
      { value: before[field][label] ?? 0, at: before.at },
      { value: after[field][label] ?? 0, at: after.at }
    )
    series.push(rate.perSecond)
  }
  return series
}

const storedRate = computed(() => {
  if (!latest.value) {
    return { perSecond: null, reset: false }
  }
  return rateBetween(
    previous.value ? { value: previous.value.eventsStored, at: previous.value.at } : undefined,
    { value: latest.value.eventsStored, at: latest.value.at }
  )
})

const storedHistory = computed(() => {
  const series: (number | null)[] = []
  for (let i = 1; i < samples.value.length; i++) {
    const before = samples.value[i - 1]!
    const after = samples.value[i]!
    series.push(rateBetween({ value: before.eventsStored, at: before.at }, { value: after.eventsStored, at: after.at }).perSecond)
  }
  return series
})

const latency = computed(() => (latest.value?.latency ?? []).map(histogram => ({
  query: histogram.query,
  observations: histogram.count,
  mean: formatDuration(meanSeconds(histogram)),
  p50: formatDuration(quantileFromBuckets(histogram, 0.5)),
  p95: formatDuration(quantileFromBuckets(histogram, 0.95))
})))

/** How long this page has been sampling, which is the whole of its history. */
const windowLabel = computed(() => {
  if (samples.value.length < 2) {
    return 'since this page opened'
  }
  const seconds = Math.round((samples.value.at(-1)!.at - samples.value[0]!.at) / 1000)
  return seconds < 90 ? `over the last ${seconds}s` : `over the last ${Math.round(seconds / 60)}m`
})
</script>

<template>
  <UDashboardPanel id="metrics">
    <template #header>
      <UDashboardNavbar title="Metrics">
        <template #right>
          <UButton
            icon="i-lucide-refresh-cw"
            size="xs"
            variant="ghost"
            color="neutral"
            @click="refresh"
          >
            Sample now
          </UButton>
        </template>
      </UDashboardNavbar>
    </template>

    <template #body>
      <p class="mb-6 max-w-3xl text-(--ui-text-muted)">
        Live from the relay's Prometheus endpoint, sampled every 5 seconds while this tab is
        visible. There is no metrics store behind this: rates are differences between the samples
        this page has taken, so the window starts when the page opens and is gone when it closes.
        For real history, point Prometheus at the same endpoint.
      </p>

      <div
        v-if="error"
        class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
        role="alert"
      >
        <p>{{ error }}</p>
        <UButton
          class="mt-3"
          size="xs"
          variant="subtle"
          @click="refresh"
        >
          Try again
        </UButton>
      </div>

      <MetricsMetricTiles
        :snapshot="latest"
        :ready="ready"
        :paused="paused"
        :failing="error !== ''"
      />

      <UCard class="mb-6">
        <template #header>
          <div class="flex flex-wrap items-baseline justify-between gap-2">
            <h2 class="font-display text-lg font-semibold">
              Messages
            </h2>
            <p class="text-sm text-(--ui-text-muted)">
              By protocol message type, {{ windowLabel }}
            </p>
          </div>
        </template>

        <table
          v-if="messageRates.length > 0"
          class="w-full text-left text-sm"
        >
          <thead class="text-(--ui-text-muted)">
            <tr>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Type
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Rate
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Total
              </th>
              <th
                scope="col"
                class="pb-2 font-medium"
              >
                <span class="sr-only">Trend</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in messageRates"
              :key="row.label"
              class="border-t border-(--ui-border)"
            >
              <td class="py-2 pr-4 font-mono">
                {{ row.label }}
              </td>
              <td class="nf-tabular py-2 pr-4">
                {{ formatRate(row.rate) }}
              </td>
              <td class="nf-tabular py-2 pr-4 text-(--ui-text-muted)">
                {{ formatCount(row.total) }}
              </td>
              <td class="py-2">
                <MetricsSparkline :values="historyFor('messages', row.label)" />
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else
          class="py-4 text-sm text-(--ui-text-muted)"
        >
          No messages have reached this relay since it started.
        </p>
      </UCard>

      <UCard class="mb-6">
        <template #header>
          <div class="flex flex-wrap items-baseline justify-between gap-2">
            <h2 class="font-display text-lg font-semibold">
              Rejections
            </h2>
            <p class="text-sm text-(--ui-text-muted)">
              By reason, {{ windowLabel }}
            </p>
          </div>
        </template>

        <table
          v-if="rejectionRates.length > 0"
          class="w-full text-left text-sm"
        >
          <thead class="text-(--ui-text-muted)">
            <tr>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Reason
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Rate
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Total
              </th>
              <th
                scope="col"
                class="pb-2 font-medium"
              >
                <span class="sr-only">Trend</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in rejectionRates"
              :key="row.label"
              class="border-t border-(--ui-border)"
            >
              <td class="py-2 pr-4 font-mono">
                {{ row.label }}
              </td>
              <td class="nf-tabular py-2 pr-4">
                {{ formatRate(row.rate) }}
              </td>
              <td class="nf-tabular py-2 pr-4 text-(--ui-text-muted)">
                {{ formatCount(row.total) }}
              </td>
              <td class="py-2">
                <MetricsSparkline :values="historyFor('rejections', row.label)" />
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else
          class="py-4 text-sm text-(--ui-text-muted)"
        >
          Nothing has been rejected since this relay started.
        </p>
      </UCard>

      <UCard class="mb-6">
        <template #header>
          <div class="flex flex-wrap items-baseline justify-between gap-2">
            <h2 class="font-display text-lg font-semibold">
              Storage
            </h2>
            <p class="text-sm text-(--ui-text-muted)">
              Events persisted, {{ windowLabel }}
            </p>
          </div>
        </template>

        <div class="flex flex-wrap items-center gap-6">
          <div>
            <p class="text-sm text-(--ui-text-muted)">
              Rate
            </p>
            <p class="nf-tabular font-display text-2xl font-semibold">
              {{ formatRate(storedRate) }}
            </p>
          </div>
          <div>
            <p class="text-sm text-(--ui-text-muted)">
              Stored since start
            </p>
            <p class="nf-tabular font-display text-2xl font-semibold">
              {{ latest ? formatCount(latest.eventsStored) : '—' }}
            </p>
          </div>
          <div>
            <p class="text-sm text-(--ui-text-muted)">
              Save failures
            </p>
            <p class="nf-tabular font-display text-2xl font-semibold">
              {{ latest ? formatCount(latest.saveFailures) : '—' }}
            </p>
          </div>
          <MetricsSparkline
            class="ml-auto"
            :values="storedHistory"
          />
        </div>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-baseline justify-between gap-2">
            <h2 class="font-display text-lg font-semibold">
              Query latency
            </h2>
            <p class="text-sm text-(--ui-text-muted)">
              Since the relay started, not just this window
            </p>
          </div>
        </template>

        <table
          v-if="latency.length > 0"
          class="w-full text-left text-sm"
        >
          <thead class="text-(--ui-text-muted)">
            <tr>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Query
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                Mean
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                p50
              </th>
              <th
                scope="col"
                class="pb-2 pr-4 font-medium"
              >
                p95
              </th>
              <th
                scope="col"
                class="pb-2 font-medium"
              >
                Observations
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in latency"
              :key="row.query"
              class="border-t border-(--ui-border)"
            >
              <td class="py-2 pr-4 font-mono">
                {{ row.query }}
              </td>
              <td class="nf-tabular py-2 pr-4">
                {{ row.mean }}
              </td>
              <td class="nf-tabular py-2 pr-4">
                {{ row.p50 }}
              </td>
              <td class="nf-tabular py-2 pr-4">
                {{ row.p95 }}
              </td>
              <td class="nf-tabular py-2 text-(--ui-text-muted)">
                {{ formatCount(row.observations) }}
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else
          class="py-4 text-sm text-(--ui-text-muted)"
        >
          No queries have run since this relay started.
        </p>

        <template #footer>
          <p class="text-sm text-(--ui-text-dimmed)">
            p50 and p95 are estimated from the relay's twelve histogram buckets by interpolation, the
            same way <code class="font-mono">histogram_quantile</code> does. The mean is exact.
          </p>
        </template>
      </UCard>
    </template>
  </UDashboardPanel>
</template>
