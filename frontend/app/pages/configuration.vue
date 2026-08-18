<script setup lang="ts">
import type { RelayConfig } from '~~/shared/types/relay-config'

useSeoMeta({ title: 'Configuration' })

const { state } = useAdminSession()
const { fetchConfig } = useRelayConfig()
const { data: relay } = await useFetch('/api/relay-info')

/** One label/value line. `mono` for protocol data, `tabular` for figures. */
interface Row {
  label: string
  value: string
  mono?: boolean
  tabular?: boolean
}

const config = ref<RelayConfig | null>(null)
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  try {
    config.value = await fetchConfig()
  } catch (cause) {
    error.value = (cause as Error)?.message || 'The configuration could not be read.'
  } finally {
    loading.value = false
  }
})

function seconds(value: number | undefined): string {
  return value === undefined ? '—' : `${value}s`
}

function text(value: string | undefined): string {
  return value === undefined || value === '' ? '—' : value
}

/**
 * Resource limits are disabled at zero, not set to zero: newLimiter returns
 * no limiter below 1, and the connection cap is skipped unless positive. A
 * bare "0" would read as "nothing allowed" when it means the opposite, so
 * say what the relay actually does.
 */
function limit(value: number | undefined, unit: string): string {
  if (value === undefined) {
    return '—'
  }
  return value > 0 ? `${value} ${unit}` : 'Unlimited'
}

/**
 * The relay's operator key against the one signed into the dashboard. These
 * are configured separately — the relay's `moderation.admin_pubkey` and the
 * dashboard's `NUXT_ADMIN_PUBKEY` — and nothing showed you when they had
 * drifted apart.
 */
const operatorMatch = computed(() => {
  const relayAdmin = config.value?.moderation.admin_pubkey
  const signedIn = state.value?.pubkey
  if (!relayAdmin || !signedIn) {
    return null
  }
  return relayAdmin === signedIn
})

/** True when every resource limit is off, which an omitted section causes. */
const noResourceLimits = computed(() => {
  const limits = config.value?.resource_limits
  return !!limits && limits.max_connections <= 0 && limits.messages_per_second <= 0 && limits.events_per_second <= 0
})

const identity = computed<Row[]>(() => [
  { label: 'Name', value: text(relay.value?.name) },
  { label: 'Description', value: text(relay.value?.description) },
  { label: 'Contact', value: text(relay.value?.contact) },
  { label: 'Software', value: text(relay.value?.software) },
  { label: 'Version', value: text(relay.value?.version), tabular: true },
  { label: 'Operator pubkey', value: text(relay.value?.pubkey), mono: true }
])

const sections = computed<{ title: string, rows: Row[] }[]>(() => {
  const c = config.value
  if (!c) {
    return []
  }
  return [
    {
      title: 'Resource limits',
      rows: [
        { label: 'Max connections', value: limit(c.resource_limits.max_connections, 'connections'), tabular: true },
        { label: 'Messages per second', value: limit(c.resource_limits.messages_per_second, 'per second'), tabular: true },
        { label: 'Events per second', value: limit(c.resource_limits.events_per_second, 'per second'), tabular: true }
      ]
    },
    {
      title: 'Authentication (NIP-42)',
      rows: [
        { label: 'Relay URL binding', value: text(c.auth.relay_url), mono: true },
        { label: 'Max event age', value: seconds(c.auth.max_event_age_seconds), tabular: true }
      ]
    },
    {
      title: 'Moderation (NIP-86)',
      rows: [
        { label: 'Admin pubkey', value: text(c.moderation.admin_pubkey), mono: true },
        { label: 'Max event age', value: seconds(c.moderation.max_event_age_seconds), tabular: true }
      ]
    },
    {
      title: 'WebSocket origins',
      rows: [
        { label: 'Mode', value: text(c.websocket.mode) },
        {
          label: 'Allowed origins',
          value: c.websocket.allowed_origins.length > 0 ? c.websocket.allowed_origins.join(', ') : '—',
          mono: true
        }
      ]
    },
    {
      title: 'Retention',
      rows: [{ label: 'Purge interval', value: seconds(c.retention.purge_interval_seconds), tabular: true }]
    },
    {
      title: 'Listener',
      rows: [
        { label: 'Listen address', value: text(c.server.listen_addr), mono: true },
        { label: 'Shutdown timeout', value: seconds(c.server.shutdown_timeout_seconds), tabular: true }
      ]
    },
    {
      title: 'Storage',
      rows: [{ label: 'Database path', value: text(c.storage.db_path), mono: true }]
    }
  ]
})
</script>

<template>
  <div class="mx-auto max-w-3xl">
    <header class="mb-8">
      <h1 class="font-display text-3xl font-semibold tracking-tight">
        Configuration
      </h1>
      <p class="mt-2 text-(--ui-text-muted)">
        The configuration this relay process is running, after code defaults are applied — not a
        copy of <code class="font-mono">config.yaml</code>. Changes to the file take effect when the
        relay restarts, and cannot be made from here.
      </p>
    </header>

    <p
      v-if="error"
      class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
      role="alert"
    >
      {{ error }}
    </p>

    <UCard class="mb-6">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Identity (NIP-11)</span>
      </template>

      <dl class="flex flex-col gap-3">
        <div
          v-for="row in identity"
          :key="row.label"
          class="grid grid-cols-1 gap-1 sm:grid-cols-[14rem_1fr]"
        >
          <dt class="text-sm text-(--ui-text-muted)">
            {{ row.label }}
          </dt>
          <dd
            class="break-all text-sm"
            :class="[row.mono && 'font-mono', row.tabular && 'nf-tabular']"
          >
            {{ row.value }}
          </dd>
        </div>
      </dl>
    </UCard>

    <p
      v-if="loading"
      class="text-sm text-(--ui-text-muted)"
    >
      Reading the relay's configuration…
    </p>

    <template v-else-if="config">
      <p
        v-if="operatorMatch === false"
        class="mb-6 rounded-(--ui-radius) border border-(--ui-warning) px-4 py-3 text-sm text-(--ui-warning)"
        role="status"
      >
        The relay's admin pubkey is not the key you signed in with. The dashboard's
        <code class="font-mono">NUXT_ADMIN_PUBKEY</code> and the relay's
        <code class="font-mono">moderation.admin_pubkey</code> should name the same operator —
        privileged relay calls will be refused until they do.
      </p>

      <UCard
        v-for="section in sections"
        :key="section.title"
        class="mb-6"
      >
        <template #header>
          <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">{{ section.title }}</span>
        </template>

        <dl class="flex flex-col gap-3">
          <div
            v-for="row in section.rows"
            :key="row.label"
            class="grid grid-cols-1 gap-1 sm:grid-cols-[14rem_1fr]"
          >
            <dt class="text-sm text-(--ui-text-muted)">
              {{ row.label }}
            </dt>
            <dd
              class="break-all text-sm"
              :class="[row.mono && 'font-mono', row.tabular && 'nf-tabular']"
            >
              {{ row.value }}
            </dd>
          </div>
        </dl>

        <template
          v-if="section.title === 'WebSocket origins' && config.websocket.mode !== 'production'"
          #footer
        >
          <p class="text-sm text-(--ui-text-muted)">
            Development mode accepts a WebSocket connection from any Origin. Production mode requires
            a non-empty allow-list and refuses to start without one.
          </p>
        </template>

        <template
          v-else-if="section.title === 'Resource limits' && noResourceLimits"
          #footer
        >
          <p class="text-sm text-(--ui-warning)">
            This relay is enforcing no connection cap and no rate limiting. Omitting
            <code class="font-mono">resource_limits</code> from
            <code class="font-mono">config.yaml</code> disables them rather than applying a default.
          </p>
        </template>
      </UCard>
    </template>
  </div>
</template>
