<script setup lang="ts">
import type { MetricsSnapshot } from '~~/shared/types/metrics'
import { formatCount } from '~~/shared/utils/event-stats'
import { sampleAge } from '~~/shared/utils/metric-rates'
import { formatUptime, gaugeSeries, relayStatus } from '~~/shared/utils/relay-status'
import type { RelayStatus, StatusFigure } from '~~/shared/utils/relay-status'

/**
 * The relay's status band and the figures beneath it, shared by the Overview
 * and Metrics pages so both always say the same thing about the same relay.
 *
 * The band is a traffic light and one word. How fresh the figures are is
 * carried by the refresh icon instead of a line of text: it turns while a
 * sample is being read, so a poller that has stopped is visible as an icon
 * that has stopped — still the thing a quiet relay must not be mistaken for.
 * The exact sample age stays one hover or focus away.
 *
 * Only the figures differ between pages. The Metrics page explains stored
 * events in its own Storage section, so it shows live gauges here instead of
 * repeating them (nostrfi/relay#49).
 */
const props = withDefaults(defineProps<{
  snapshot: MetricsSnapshot | null
  /** Oldest first, for the sparklines. */
  samples: MetricsSnapshot[]
  ready: boolean | null
  paused: boolean
  /** True when the last poll failed, so these figures are stale. */
  failing: boolean
  /** True while a sample is in flight. */
  polling: boolean
  /** Which figures to show beneath the band, in order. */
  figures?: StatusFigure[]
}>(), {
  figures: () => ['uptime', 'connections', 'eventsStored']
})

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
  if (settle !== null) {
    clearTimeout(settle)
  }
})

const status = computed(() => relayStatus(props.ready, props.failing, props.paused))

const STATUS: Record<RelayStatus, { word: string, lamp: 'red' | 'amber' | 'green' | null, tone: string }> = {
  ok: { word: 'OK', lamp: 'green', tone: 'var(--ui-success)' },
  paused: { word: 'Paused', lamp: 'amber', tone: 'var(--ui-warning)' },
  error: { word: 'Error', lamp: 'red', tone: 'var(--ui-error)' },
  unknown: { word: 'Unknown', lamp: null, tone: 'var(--ui-text-dimmed)' }
}
const current = computed(() => STATUS[status.value])

const LAMPS = [
  { key: 'red', tone: 'var(--ui-error)' },
  { key: 'amber', tone: 'var(--ui-warning)' },
  { key: 'green', tone: 'var(--ui-success)' }
] as const

/*
 * A local read takes a few milliseconds — far too short to see. Each poll
 * spins the icon for at least this long so it registers, without claiming
 * a request is still running once it plainly is not.
 */
const MIN_SPIN_MS = 700
const spinning = ref(false)
let spinStartedAt = 0
let settle: ReturnType<typeof setTimeout> | null = null
watch(() => props.polling, (busy) => {
  if (settle !== null) {
    clearTimeout(settle)
    settle = null
  }
  if (busy) {
    spinStartedAt = Date.now()
    spinning.value = true
    return
  }
  const remaining = MIN_SPIN_MS - (Date.now() - spinStartedAt)
  if (remaining <= 0) {
    spinning.value = false
  } else {
    settle = setTimeout(() => {
      spinning.value = false
      settle = null
    }, remaining)
  }
}, { immediate: true })

const syncLabel = computed(() => {
  if (spinning.value) {
    return 'Reading the relay…'
  }
  const age = props.snapshot ? sampleAge(props.snapshot.at, now.value) : null
  if (props.failing) {
    return age ? `The last read failed. Last good sample ${age}.` : 'The last read failed.'
  }
  if (props.paused) {
    return age ? `Paused while this tab is in the background. Last sample ${age}.` : 'Paused while this tab is in the background.'
  }
  return age ? `Sampled ${age}` : 'Waiting for the first sample'
})

/*
 * Uptime counts on from the relay's own start time while the page can see
 * the relay. Once a read fails it stops at the last sample: a relay this page
 * cannot reach may not be running at all, and a clock still ticking would say
 * it is.
 */
const startedAt = computed(() => props.snapshot?.processStartedAt ?? null)
const uptime = computed(() => {
  if (!props.snapshot) {
    return '—'
  }
  return formatUptime(startedAt.value, props.failing ? props.snapshot.at : now.value)
})
const startedLabel = computed(() => {
  if (!props.snapshot) {
    return ''
  }
  if (startedAt.value === null) {
    return 'The relay does not report its start time.'
  }
  const when = new Date(startedAt.value * 1000).toLocaleString(undefined, {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit'
  })
  return `Running since ${when}`
})

const connections = computed(() => gaugeSeries(props.samples, 'connectionsActive'))
const subscriptions = computed(() => gaugeSeries(props.samples, 'subscriptionsActive'))

/* Written out in full so Tailwind can find each class in the source. */
const COLUMNS: Record<number, string> = {
  2: 'sm:grid-cols-2',
  3: 'sm:grid-cols-3',
  4: 'sm:grid-cols-2 lg:grid-cols-4'
}
</script>

<template>
  <UCard
    class="mb-6"
    :ui="{ header: 'p-0 sm:px-0', body: 'p-4 sm:p-6' }"
  >
    <template #header>
      <div
        class="status-band flex items-center gap-3 px-4 py-3 sm:px-6"
        :style="{ '--tone': current.tone }"
      >
        <h2 class="sr-only">
          Relay status
        </h2>
        <span
          class="lamps"
          aria-hidden="true"
        >
          <span
            v-for="lamp in LAMPS"
            :key="lamp.key"
            class="lamp"
            :style="current.lamp === lamp.key ? { background: lamp.tone } : undefined"
          />
        </span>
        <p
          class="font-display text-lg font-semibold text-(--tone)"
          role="status"
        >
          {{ current.word }}
        </p>

        <UTooltip :text="syncLabel">
          <span
            class="sync ms-auto"
            :class="{ 'sync-stopped': paused, 'text-(--ui-error)': failing, 'text-(--ui-primary)': spinning && !failing }"
            role="img"
            tabindex="0"
            :aria-label="syncLabel"
          >
            <UIcon
              name="i-lucide-refresh-cw"
              class="size-4"
              :class="{ 'sync-spin': spinning }"
            />
          </span>
        </UTooltip>
      </div>
    </template>

    <dl
      class="grid grid-cols-1 gap-4"
      :class="COLUMNS[figures.length]"
    >
      <div
        v-for="figure in figures"
        :key="figure"
        class="tile"
      >
        <template v-if="figure === 'uptime'">
          <dt class="text-sm text-(--ui-text-muted)">
            Uptime
          </dt>
          <dd class="nf-tabular font-display text-3xl font-semibold">
            {{ uptime }}
          </dd>
          <dd class="nf-tabular mt-1 text-sm text-(--ui-text-dimmed)">
            {{ startedLabel }}
          </dd>
        </template>

        <template v-else-if="figure === 'connections'">
          <dt class="text-sm text-(--ui-text-muted)">
            Connections
          </dt>
          <dd class="flex items-end justify-between gap-3">
            <span class="nf-tabular font-display text-3xl font-semibold">
              {{ snapshot ? formatCount(snapshot.connectionsActive) : '—' }}
            </span>
            <MetricsSparkline :values="connections" />
          </dd>
          <dd class="mt-1 text-sm text-(--ui-text-dimmed)">
            Since this page opened
          </dd>
        </template>

        <template v-else-if="figure === 'subscriptions'">
          <dt class="text-sm text-(--ui-text-muted)">
            Subscriptions
          </dt>
          <dd class="flex items-end justify-between gap-3">
            <span class="nf-tabular font-display text-3xl font-semibold">
              {{ snapshot ? formatCount(snapshot.subscriptionsActive) : '—' }}
            </span>
            <MetricsSparkline :values="subscriptions" />
          </dd>
          <dd class="mt-1 text-sm text-(--ui-text-dimmed)">
            Open across all connections
          </dd>
        </template>

        <template v-else-if="figure === 'eventsStored'">
          <dt class="text-sm text-(--ui-text-muted)">
            Events stored
          </dt>
          <dd class="nf-tabular font-display text-3xl font-semibold">
            {{ snapshot ? formatCount(snapshot.eventsStored) : '—' }}
          </dd>
          <dd
            class="mt-1 text-sm"
            :class="snapshot && snapshot.saveFailures > 0 ? 'text-(--ui-error)' : 'text-(--ui-text-dimmed)'"
          >
            <span class="nf-tabular font-semibold">{{ snapshot ? formatCount(snapshot.saveFailures) : '—' }}</span>
            save failures
          </dd>
        </template>
      </div>
    </dl>
  </UCard>
</template>

<style scoped>
.status-band {
  /* Tonal shift, not a shadow: the band takes a wash of the status colour. */
  background: color-mix(in oklab, var(--tone) 12%, var(--ui-bg-elevated));
  border-bottom: 1px solid color-mix(in oklab, var(--tone) 35%, var(--ui-border));
}

.lamps {
  display: inline-flex;
  gap: var(--nf-space-1);
  padding: var(--nf-space-1);
  border: 1px solid var(--ui-border);
  border-radius: var(--nf-radius-pill);
  background: var(--ui-bg);
}

.lamp {
  width: 14px;
  height: 14px;
  border-radius: var(--nf-radius-pill);
  background: var(--ui-bg-accented);
}

.tile {
  min-width: 0;
  padding: var(--nf-space-4);
  border: 1px solid var(--ui-border);
  border-radius: var(--nf-radius-compact);
  background: var(--ui-bg-muted);
}

.sync {
  display: inline-grid;
  place-items: center;
  width: 30px;
  height: 30px;
  border: 1px solid var(--ui-border);
  border-radius: var(--nf-radius-pill);
  color: var(--ui-text-dimmed);
}

.sync-stopped {
  opacity: 0.5;
  border-style: dashed;
}

.sync-spin {
  animation: sync-spin 0.8s linear infinite;
}

@keyframes sync-spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes sync-pulse {
  50% {
    opacity: 0.35;
  }
}

/* The turn is a signal, not decoration, so reduced motion keeps it as a pulse. */
@media (prefers-reduced-motion: reduce) {
  .sync-spin {
    animation: sync-pulse 1s ease-in-out infinite;
  }
}
</style>
