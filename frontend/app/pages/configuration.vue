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
const refusalCauses = ref<string[]>([])
const refusalLogHint = ref('')

async function load() {
  loading.value = true
  error.value = ''
  refusalCauses.value = []
  refusalLogHint.value = ''

  try {
    config.value = await fetchConfig()
  } catch (cause) {
    // useRelayConfig turns a relay refusal into a headline plus the causes
    // that could produce it. It deliberately does not assert one: the relay
    // answers every failed check with a bare "unauthorized", so a stale
    // signature, a wrong key and a rewritten path are indistinguishable
    // here. Only the relay's own log knows.
    const refused = cause as { refusal?: { headline: string, causes: string[] }, logHint?: string }
    error.value = refused.refusal?.headline || (cause as Error)?.message || 'The configuration could not be read.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
  } finally {
    loading.value = false
  }
}

onMounted(load)

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
        :loading="loading"
        @click="load"
      >
        Try again
      </UButton>
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
