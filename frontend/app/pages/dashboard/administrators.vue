<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'
import type { RoleAssignment } from '~~/shared/types/administrators'
import { parseAdministratorKey, validateAdministratorLabel } from '~~/shared/utils/administrator-input'

useSeoMeta({ title: 'Administrators' })

// Private by default — see app/middleware/auth.global.ts.
// Owner only (D2, nostrfi/relay#57): if administrators could manage
// administrators, one compromised admin key would be a full takeover. The
// relay refuses the role methods to them with a 403; the middleware sends
// them back to the overview before they get that far.
definePageMeta({ layout: 'dashboard', ownerOnly: true })

const administrators = useAdministrators()
const { state } = useAdminSession()

const loading = ref(true)
const busy = ref(false)
const error = ref('')
const notice = ref('')
const refusalCauses = ref<string[]>([])
const refusalLogHint = ref('')

const owner = ref<RoleAssignment | null>(null)
const admins = ref<RoleAssignment[]>([])
// An empty list after a failed request is not "no administrators".
const loaded = ref(false)

const keyInput = ref('')
const labelInput = ref('')

const pendingRemoval = ref<RoleAssignment | null>(null)
const confirmOpen = ref(false)

/** The owner's key: the relay's word first, the session's until it loads. */
const ownerPubkey = computed(() => owner.value?.pubkey ?? state.value?.pubkey)

const parsedKey = computed(() => keyInput.value.trim() === '' ? null : parseAdministratorKey(keyInput.value, ownerPubkey.value))
const labelProblem = computed(() => validateAdministratorLabel(labelInput.value))
const problem = computed(() => parsedKey.value?.error ?? labelProblem.value)

/** Re-granting replaces the label, so say so before the owner signs. */
const existing = computed(() => {
  const pubkey = parsedKey.value?.pubkey
  return pubkey ? admins.value.find(a => a.pubkey === pubkey) ?? null : null
})

function npubOf(pubkey: string): { full: string, short: string } {
  try {
    const full = npubEncode(pubkey)
    return { full, short: `${full.slice(0, 10)}…${full.slice(-6)}` }
  } catch {
    return { full: pubkey, short: pubkey }
  }
}

function grantedBy(entry: RoleAssignment): string {
  if (!entry.granted_by) {
    return 'Unknown'
  }
  if (entry.granted_by === ownerPubkey.value) {
    return 'Owner'
  }
  // A grant made by a previous owner key; see README §Administrators.
  return `${npubOf(entry.granted_by).short} (previous owner)`
}

function grantedAt(entry: RoleAssignment): string {
  return entry.granted_at ? new Date(entry.granted_at * 1000).toLocaleString() : 'Unknown'
}

function nameOf(entry: RoleAssignment): string {
  return entry.label || npubOf(entry.pubkey).short
}

async function copy(value: string) {
  try {
    await navigator.clipboard.writeText(value)
    notice.value = 'Copied.'
  } catch {
    error.value = 'Could not copy to the clipboard.'
  }
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
    const refused = cause as {
      refusal?: { headline: string, causes: string[] }
      logHint?: string
      data?: { statusMessage?: string }
      statusCode?: number
    }
    // A 403 is a key the relay knows whose role is too low: this session
    // was opened as the owner, but the relay no longer counts the key as
    // one (moderation.admin_pubkey changed and the relay restarted).
    const forbidden = refused.statusCode === 403
      ? 'The relay says this key is not the owner, so it cannot manage administrators. Sign out and sign in again to refresh your role.'
      : ''
    error.value = forbidden
      || refused.refusal?.headline
      || refused.data?.statusMessage
      || (cause as Error)?.message
      || 'The request failed.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
  } finally {
    busy.value = false
  }
}

async function load() {
  const res = await administrators.listRoleAssignments()
  if (res.error) {
    error.value = res.error
    loaded.value = false
    return
  }
  const rows = res.result ?? []
  owner.value = rows.find(r => r.role === 'owner') ?? null
  admins.value = rows.filter(r => r.role === 'admin')
  loaded.value = true
}

async function submit() {
  const pubkey = parsedKey.value?.pubkey
  if (!pubkey || problem.value) {
    return
  }
  const label = labelInput.value.trim()
  const updating = existing.value !== null
  await withBusy(async () => {
    const res = await administrators.assignAdmin(pubkey, label)
    if (res.error) {
      error.value = res.error
      return
    }
    keyInput.value = ''
    labelInput.value = ''
    await load()
    notice.value = updating ? 'Administrator updated.' : 'Administrator added.'
  })
}

function askRemove(entry: RoleAssignment) {
  pendingRemoval.value = entry
  confirmOpen.value = true
}

async function confirmRemove() {
  const entry = pendingRemoval.value
  confirmOpen.value = false
  pendingRemoval.value = null
  if (!entry) {
    return
  }
  await withBusy(async () => {
    const res = await administrators.unassignAdmin(entry.pubkey)
    if (res.error) {
      error.value = res.error
      return
    }
    await load()
    notice.value = 'Administrator removed.'
  })
}

async function retry() {
  await withBusy(load)
}

onMounted(async () => {
  await withBusy(load)
  loading.value = false
})
</script>

<template>
  <UDashboardPanel
    id="administrators"
    :ui="{ body: 'max-w-3xl' }"
  >
    <template #header>
      <UDashboardNavbar title="Administrators" />
    </template>

    <template #body>
      <p class="mb-6 text-(--ui-text-muted)">
        Administrators sign in with their own key and can use events, statistics, metrics and
        moderation. Only you, the owner, can see this page or change who is an administrator.
        Removing one takes effect on their key's very next request.
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
          v-if="!loaded || refusalCauses.length > 0 || refusalLogHint"
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

      <UCard class="mb-6">
        <template #header>
          <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Operators</span>
        </template>

        <p
          v-if="loading"
          class="text-sm text-(--ui-text-muted)"
        >
          Loading…
        </p>
        <p
          v-else-if="!loaded"
          class="text-sm text-(--ui-text-muted)"
        >
          The list could not be loaded, so it is not shown. It is not necessarily empty.
        </p>

        <ul
          v-else
          class="flex flex-col gap-3"
        >
          <li
            v-if="owner"
            class="flex items-start justify-between gap-4 border-b border-(--ui-border-muted) pb-3 last:border-0 last:pb-0"
          >
            <div class="min-w-0">
              <p class="text-sm font-medium">
                Owner (configuration)
              </p>
              <button
                type="button"
                class="font-mono text-sm text-(--ui-text-muted) hover:underline"
                :title="npubOf(owner.pubkey).full"
                :aria-label="`Copy ${npubOf(owner.pubkey).full}`"
                @click="copy(npubOf(owner.pubkey).full)"
              >
                {{ npubOf(owner.pubkey).short }}
              </button>
              <p class="text-sm text-(--ui-text-muted)">
                Set by <code class="font-mono">moderation.admin_pubkey</code>. It cannot be removed here.
              </p>
            </div>
            <UBadge
              label="Owner"
              variant="subtle"
            />
          </li>

          <li
            v-if="admins.length === 0"
            class="text-sm text-(--ui-text-muted)"
          >
            No administrators yet.
          </li>

          <li
            v-for="entry in admins"
            :key="entry.pubkey"
            class="flex items-start justify-between gap-4 border-b border-(--ui-border-muted) pb-3 last:border-0 last:pb-0"
          >
            <div class="min-w-0">
              <p
                v-if="entry.label"
                class="text-sm font-medium"
              >
                {{ entry.label }}
              </p>
              <button
                type="button"
                class="font-mono text-sm text-(--ui-text-muted) hover:underline"
                :title="npubOf(entry.pubkey).full"
                :aria-label="`Copy ${npubOf(entry.pubkey).full}`"
                @click="copy(npubOf(entry.pubkey).full)"
              >
                {{ npubOf(entry.pubkey).short }}
              </button>
              <p class="text-sm text-(--ui-text-muted)">
                Granted by {{ grantedBy(entry) }} · {{ grantedAt(entry) }}
              </p>
            </div>
            <UButton
              size="xs"
              variant="ghost"
              :disabled="busy"
              @click="askRemove(entry)"
            >
              Remove
            </UButton>
          </li>
        </ul>
      </UCard>

      <UCard>
        <template #header>
          <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Add administrator</span>
        </template>

        <form
          class="flex flex-col gap-3"
          @submit.prevent="submit"
        >
          <div class="flex flex-col gap-3 sm:flex-row">
            <UInput
              v-model="keyInput"
              class="flex-1"
              placeholder="npub1… or 64 hex characters"
              aria-label="Administrator public key"
              autocomplete="off"
              spellcheck="false"
            />
            <UInput
              v-model="labelInput"
              class="flex-1"
              placeholder="Label (optional)"
              aria-label="Label"
              autocomplete="off"
            />
            <UButton
              type="submit"
              :loading="busy"
              :disabled="busy || !loaded || !parsedKey?.pubkey || problem !== null"
            >
              {{ existing ? 'Update' : 'Add' }}
            </UButton>
          </div>
          <p
            v-if="problem"
            class="text-sm text-(--ui-error)"
          >
            {{ problem }}
          </p>
          <p
            v-else-if="existing"
            class="text-sm text-(--ui-text-muted)"
          >
            This key is already an administrator. Saving replaces its label.
          </p>
        </form>
      </UCard>

      <UModal
        v-model:open="confirmOpen"
        title="Remove administrator"
        :description="pendingRemoval ? `Remove ${nameOf(pendingRemoval)}? The relay refuses their next request, and that ends their dashboard session.` : ''"
      >
        <template #body>
          <p class="break-all font-mono text-sm">
            {{ pendingRemoval ? npubOf(pendingRemoval.pubkey).full : '' }}
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
              Remove
            </UButton>
          </div>
        </template>
      </UModal>
    </template>
  </UDashboardPanel>
</template>
