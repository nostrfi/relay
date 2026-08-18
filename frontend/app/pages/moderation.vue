<script setup lang="ts">
import type { ModerationCategory } from '~~/shared/types/moderation'
import { validateHexId, validateIpOrCidr, validateReason } from '~~/shared/utils/moderation-validation'

useSeoMeta({ title: 'Moderation' })

const moderation = useModeration()

interface Entry { value: string, reason?: string }

interface Section {
  key: ModerationCategory
  title: string
  /** Column heading for the value, matching the relay's own field name. */
  valueLabel: string
  placeholder: string
  addLabel: string
  removeLabel: string
  entries: Ref<Entry[]>
  /** False until a list request has actually succeeded. */
  loaded: Ref<boolean>
  input: Ref<string>
  reason: Ref<string>
  validate: (value: string) => string | null
  load: () => Promise<void>
  add: () => Promise<void>
  remove: (value: string) => Promise<void>
}

const loading = ref(true)
const busy = ref(false)
const error = ref('')
const notice = ref('')

// A relay refusal is not a method error: the relay will not say which check
// failed, so the page lists what could have caused it rather than picking
// one. See shared/utils/relay-refusal.ts.
const refusalCauses = ref<string[]>([])
const refusalLogHint = ref('')

/** The entry a confirmation prompt is currently about. */
const pendingRemoval = ref<{ section: Section, value: string } | null>(null)
const confirmOpen = ref(false)

const pubkeys = ref<Entry[]>([])
const events = ref<Entry[]>([])
const ips = ref<Entry[]>([])

// Tracked separately from the arrays: an empty array after a failed request
// is not an empty list, and saying "nothing banned yet" when nothing was
// fetched would misreport the relay's state.
const pubkeysLoaded = ref(false)
const eventsLoaded = ref(false)
const ipsLoaded = ref(false)

const pubkeyInput = ref('')
const eventInput = ref('')
const ipInput = ref('')
const pubkeyReason = ref('')
const eventReason = ref('')
const ipReason = ref('')

/** Surfaces the relay's own wording; it is the only account of why a call failed. */
function report(response: { error?: string }, success: string): boolean {
  if (response.error) {
    error.value = response.error
    return false
  }
  notice.value = success
  return true
}

const sections: Section[] = [
  {
    key: 'pubkeys',
    title: 'Banned pubkeys',
    valueLabel: 'Pubkey',
    placeholder: '64 hex characters',
    addLabel: 'Ban pubkey',
    removeLabel: 'Unban',
    entries: pubkeys,
    loaded: pubkeysLoaded,
    input: pubkeyInput,
    reason: pubkeyReason,
    validate: value => validateHexId(value, 'Pubkey'),
    load: async () => {
      const res = await moderation.listBannedPubkeys()
      if (res.error) {
        error.value = res.error
        pubkeysLoaded.value = false
        return
      }
      pubkeys.value = (res.result ?? []).map(e => ({ value: e.pubkey, reason: e.reason }))
      pubkeysLoaded.value = true
    },
    add: async () => {
      const res = await moderation.banPubkey(pubkeyInput.value.trim(), pubkeyReason.value.trim())
      if (report(res, 'Pubkey banned.')) {
        pubkeyInput.value = ''
        pubkeyReason.value = ''
      }
    },
    remove: async (value) => {
      report(await moderation.unbanPubkey(value), 'Pubkey unbanned.')
    }
  },
  {
    key: 'events',
    title: 'Banned events',
    valueLabel: 'Event ID',
    placeholder: '64 hex characters',
    addLabel: 'Ban event',
    removeLabel: 'Allow',
    entries: events,
    loaded: eventsLoaded,
    input: eventInput,
    reason: eventReason,
    validate: value => validateHexId(value, 'Event ID'),
    load: async () => {
      const res = await moderation.listBannedEvents()
      if (res.error) {
        error.value = res.error
        eventsLoaded.value = false
        return
      }
      events.value = (res.result ?? []).map(e => ({ value: e.id, reason: e.reason }))
      eventsLoaded.value = true
    },
    add: async () => {
      const res = await moderation.banEvent(eventInput.value.trim(), eventReason.value.trim())
      if (report(res, 'Event banned.')) {
        eventInput.value = ''
        eventReason.value = ''
      }
    },
    remove: async (value) => {
      report(await moderation.allowEvent(value), 'Event allowed again.')
    }
  },
  {
    key: 'ips',
    title: 'Blocked IPs',
    valueLabel: 'IP or CIDR',
    placeholder: '203.0.113.4 or 203.0.113.0/24',
    addLabel: 'Block IP',
    removeLabel: 'Unblock',
    entries: ips,
    loaded: ipsLoaded,
    input: ipInput,
    reason: ipReason,
    validate: validateIpOrCidr,
    load: async () => {
      const res = await moderation.listBlockedIPs()
      if (res.error) {
        error.value = res.error
        ipsLoaded.value = false
        return
      }
      ips.value = (res.result ?? []).map(e => ({ value: e.ip, reason: e.reason }))
      ipsLoaded.value = true
    },
    add: async () => {
      const res = await moderation.blockIP(ipInput.value.trim(), ipReason.value.trim())
      if (report(res, 'IP blocked.')) {
        ipInput.value = ''
        ipReason.value = ''
      }
    },
    remove: async (value) => {
      report(await moderation.unblockIP(value), 'IP unblocked.')
    }
  }
]

function problemFor(section: Section): string | null {
  const value = section.input.value.trim()
  if (value === '') {
    return null
  }
  return section.validate(value) ?? validateReason(section.reason.value)
}

async function withBusy(work: () => Promise<void>) {
  busy.value = true
  error.value = ''
  notice.value = ''
  refusalCauses.value = []
  refusalLogHint.value = ''
  try {
    await work()
  } catch (cause) {
    const refused = cause as { refusal?: { headline: string, causes: string[] }, logHint?: string }
    error.value = refused.refusal?.headline || (cause as Error)?.message || 'The request failed.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
  } finally {
    busy.value = false
  }
}

/** Retries whatever failed by reloading every list. */
async function retry() {
  await withBusy(loadAll)
}

async function loadAll() {
  // Each list is a separately signed request. They are issued together, but
  // the signing itself is serialized by the signer queue (useSigner.ts):
  // an extension asked to approve a second signature while the first is
  // still on screen answers "Another approval request is already pending".
  //
  // allSettled, not all: a rejection from one must not hand the page back —
  // and with it the retry button — while the others are still waiting their
  // turn at the signer. Clicking retry then would stack three more.
  const results = await Promise.allSettled(sections.map(s => s.load()))
  const failure = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
  if (failure) {
    throw failure.reason
  }
}

async function submit(section: Section) {
  if (problemFor(section)) {
    return
  }
  await withBusy(async () => {
    await section.add()
    await section.load()
  })
}

function askRemove(section: Section, value: string) {
  pendingRemoval.value = { section, value }
  confirmOpen.value = true
}

async function confirmRemove() {
  const pending = pendingRemoval.value
  confirmOpen.value = false
  pendingRemoval.value = null
  if (!pending) {
    return
  }
  await withBusy(async () => {
    await pending.section.remove(pending.value)
    await pending.section.load()
  })
}

onMounted(async () => {
  await withBusy(loadAll)
  loading.value = false
})
</script>

<template>
  <div class="mx-auto max-w-3xl">
    <header class="mb-8">
      <h1 class="font-display text-3xl font-semibold tracking-tight">
        Moderation
      </h1>
      <p class="mt-2 text-(--ui-text-muted)">
        Bans and blocks are applied through the relay's NIP-86 management API. They are not
        retroactive: banning a pubkey stops future publishes but leaves its existing events
        readable, and banning an event hides that one event.
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
        v-if="refusalCauses.length > 0 || refusalLogHint || error.includes('signature')"
        class="mt-4"
        size="xs"
        variant="subtle"
        :loading="busy"
        @click="retry"
      >
        Try again
      </UButton>
    </div>
    <p
      v-else-if="notice"
      class="mb-6 rounded-(--ui-radius) border border-(--ui-success) px-4 py-3 text-sm text-(--ui-success)"
      role="status"
    >
      {{ notice }}
    </p>

    <UCard
      v-for="section in sections"
      :key="section.key"
      class="mb-6"
    >
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">{{ section.title }}</span>
      </template>

      <p
        v-if="loading"
        class="text-sm text-(--ui-text-muted)"
      >
        Loading…
      </p>
      <p
        v-else-if="!section.loaded.value"
        class="text-sm text-(--ui-text-muted)"
      >
        This list could not be loaded, so it is not shown. It is not necessarily empty.
      </p>
      <p
        v-else-if="section.entries.value.length === 0"
        class="text-sm text-(--ui-text-muted)"
      >
        Nothing {{ section.key === 'ips' ? 'blocked' : 'banned' }} yet.
      </p>

      <ul
        v-else
        class="mb-6 flex flex-col gap-3"
      >
        <li
          v-for="entry in section.entries.value"
          :key="entry.value"
          class="flex items-start justify-between gap-4 border-b border-(--ui-border-muted) pb-3 last:border-0 last:pb-0"
        >
          <div class="min-w-0">
            <p class="break-all font-mono text-sm">
              {{ entry.value }}
            </p>
            <p
              v-if="entry.reason"
              class="text-sm text-(--ui-text-muted)"
            >
              {{ entry.reason }}
            </p>
          </div>
          <UButton
            size="xs"
            variant="ghost"
            :disabled="busy"
            @click="askRemove(section, entry.value)"
          >
            {{ section.removeLabel }}
          </UButton>
        </li>
      </ul>

      <form
        class="flex flex-col gap-3"
        @submit.prevent="submit(section)"
      >
        <div class="flex flex-col gap-3 sm:flex-row">
          <UInput
            v-model="section.input.value"
            class="flex-1"
            :placeholder="section.placeholder"
            :aria-label="section.valueLabel"
            autocomplete="off"
            spellcheck="false"
          />
          <UInput
            v-model="section.reason.value"
            class="flex-1"
            placeholder="Reason (optional)"
            aria-label="Reason"
            autocomplete="off"
          />
          <UButton
            type="submit"
            :loading="busy"
            :disabled="busy || section.input.value.trim() === '' || problemFor(section) !== null"
          >
            {{ section.addLabel }}
          </UButton>
        </div>
        <p
          v-if="problemFor(section)"
          class="text-sm text-(--ui-error)"
        >
          {{ problemFor(section) }}
        </p>
      </form>
    </UCard>

    <UModal
      v-model:open="confirmOpen"
      title="Confirm"
      :description="pendingRemoval ? `${pendingRemoval.section.removeLabel} this entry? It takes effect immediately.` : ''"
    >
      <template #body>
        <p class="break-all font-mono text-sm">
          {{ pendingRemoval?.value }}
        </p>
      </template>
      <template #footer>
        <div class="flex justify-end gap-3">
          <UButton
            variant="ghost"
            @click="confirmOpen = false"
          >
            Cancel
          </UButton>
          <UButton
            color="error"
            @click="confirmRemove"
          >
            {{ pendingRemoval?.section.removeLabel }}
          </UButton>
        </div>
      </template>
    </UModal>
  </div>
</template>
