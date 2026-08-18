<script setup lang="ts">
import type { RelayConfig } from '~~/shared/types/relay-config'
import type { ConfigRow } from '~~/shared/utils/config-view'
import {
  configSections,
  formatText,
  hasNoResourceLimits,
  operatorKeysMatch
} from '~~/shared/utils/config-view'

useSeoMeta({ title: 'Configuration' })

const { state } = useAdminSession()
const { fetchConfig } = useRelayConfig()
const { data: relay } = await useFetch('/api/relay-info')

const config = ref<RelayConfig | null>(null)
const loading = ref(true)
const error = ref('')
const refusedByRelay = ref(false)

onMounted(async () => {
  try {
    config.value = await fetchConfig()
  } catch (cause) {
    // A 401 here has one likely cause worth naming: the relay authorizes
    // this read against its own moderation.admin_pubkey, which is set
    // separately from the dashboard's NUXT_ADMIN_PUBKEY. When they name
    // different keys the operator can sign in and still be refused, and
    // this is the only place that says why.
    refusedByRelay.value = (cause as { statusCode?: number })?.statusCode === 401
    error.value = (cause as Error)?.message || 'The configuration could not be read.'
  } finally {
    loading.value = false
  }
})

const identity = computed<ConfigRow[]>(() => [
  { label: 'Name', value: formatText(relay.value?.name) },
  { label: 'Description', value: formatText(relay.value?.description) },
  { label: 'Contact', value: formatText(relay.value?.contact) },
  { label: 'Software', value: formatText(relay.value?.software) },
  { label: 'Version', value: formatText(relay.value?.version), tabular: true },
  { label: 'Operator pubkey', value: formatText(relay.value?.pubkey), mono: true }
])

const sections = computed(() => (config.value ? configSections(config.value) : []))

const noResourceLimits = computed(() => hasNoResourceLimits(config.value))

/**
 * The relay's operator key against the one signed into the dashboard. These
 * are configured separately — the relay's `moderation.admin_pubkey` and the
 * dashboard's `NUXT_ADMIN_PUBKEY` — and nothing showed you when they had
 * drifted apart.
 */
const operatorMatch = computed(() => operatorKeysMatch(config.value?.moderation.admin_pubkey, state.value?.pubkey))

const signedInPubkey = computed(() => formatText(state.value?.pubkey))
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

    <div
      v-if="error"
      class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
      role="alert"
    >
      <p>{{ refusedByRelay ? 'The relay refused this request.' : error }}</p>
      <p
        v-if="refusedByRelay"
        class="mt-2"
      >
        The relay authorizes this read against its own
        <code class="font-mono">moderation.admin_pubkey</code>, which is configured separately from
        the dashboard's <code class="font-mono">NUXT_ADMIN_PUBKEY</code>. You signed in as
        <span class="font-mono">{{ signedInPubkey }}</span>; if that is not the relay's admin key,
        every privileged relay call will be refused until the two agree.
      </p>
    </div>

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
