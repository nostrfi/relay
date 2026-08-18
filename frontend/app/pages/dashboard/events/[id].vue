<script setup lang="ts">
import { verifyEvent } from 'nostr-tools/pure'
import type { Event as NostrEvent } from 'nostr-tools/pure'
import type { StoredEvent } from '~~/shared/types/events'
import { formatEventTime, kindLabel } from '~~/shared/utils/event-query'

useSeoMeta({ title: 'Event' })

// Private by default — see app/middleware/auth.global.ts.
definePageMeta({ layout: 'dashboard' })

const route = useRoute()
const { query } = useEvents()

const id = computed(() => String(route.params.id ?? ''))

const event = ref<StoredEvent | null>(null)
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
    // The same browse endpoint, filtered to one id: a second endpoint that
    // fetched an event by id would be a second way to read the same rows.
    const page = await query({ ids: [id.value], limit: 1 })
    event.value = page.events[0] ?? null
  } catch (cause) {
    const refused = cause as { refusal?: { headline: string, causes: string[] }, logHint?: string }
    error.value = refused.refusal?.headline || (cause as Error)?.message || 'The event could not be read.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
  } finally {
    loading.value = false
  }
}

onMounted(load)

/**
 * Verified here, in the browser, over the event exactly as the relay
 * returned it.
 *
 * The relay checks every signature before storing, so this should always
 * pass — which is the point: it states what was checked rather than asking
 * the operator to take storage on trust, and a failure would mean the bytes
 * changed after they were stored.
 */
const signatureValid = computed(() => {
  if (!event.value) {
    return null
  }
  try {
    return verifyEvent(event.value as NostrEvent)
  } catch {
    return false
  }
})

const json = computed(() => (event.value ? JSON.stringify(event.value, null, 2) : ''))
</script>

<template>
  <UDashboardPanel id="event-detail">
    <template #header>
      <UDashboardNavbar title="Event">
        <template #right>
          <UButton
            to="/dashboard/events"
            size="xs"
            variant="ghost"
            color="neutral"
            icon="i-lucide-arrow-left"
          >
            Back to events
          </UButton>
        </template>
      </UDashboardNavbar>
    </template>

    <template #body>
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

      <p
        v-else-if="loading"
        class="text-(--ui-text-muted)"
      >
        Reading the event…
      </p>

      <p
        v-else-if="!event"
        class="text-(--ui-text-muted)"
      >
        No stored event has this ID. It may have expired, or been banned through moderation.
      </p>

      <template v-else>
        <UCard class="mb-6">
          <template #header>
            <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Event</span>
          </template>

          <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div class="sm:col-span-2">
              <dt class="text-sm text-(--ui-text-muted)">
                ID
              </dt>
              <dd class="break-all font-mono text-sm">
                {{ event.id }}
              </dd>
            </div>
            <div class="sm:col-span-2">
              <dt class="text-sm text-(--ui-text-muted)">
                Author
              </dt>
              <dd class="break-all font-mono text-sm">
                {{ event.pubkey }}
              </dd>
            </div>
            <div>
              <dt class="text-sm text-(--ui-text-muted)">
                Kind
              </dt>
              <dd>{{ kindLabel(event.kind) }}</dd>
            </div>
            <div>
              <dt class="text-sm text-(--ui-text-muted)">
                Created
              </dt>
              <dd class="nf-tabular">
                {{ formatEventTime(event.created_at) }}
              </dd>
            </div>
            <div class="sm:col-span-2">
              <dt class="text-sm text-(--ui-text-muted)">
                Signature
              </dt>
              <dd class="flex items-center gap-2">
                <UBadge
                  :color="signatureValid ? 'success' : 'error'"
                  variant="subtle"
                  :icon="signatureValid ? 'i-lucide-check' : 'i-lucide-triangle-alert'"
                >
                  {{ signatureValid ? 'Valid' : 'Invalid' }}
                </UBadge>
                <span class="text-sm text-(--ui-text-dimmed)">
                  Checked in this browser, over the event as stored.
                </span>
              </dd>
            </div>
          </dl>
        </UCard>

        <UCard class="mb-6">
          <template #header>
            <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Tags</span>
          </template>

          <div
            v-if="event.tags.length > 0"
            class="overflow-x-auto"
          >
            <table class="w-full text-left text-sm">
              <thead class="text-(--ui-text-muted)">
                <tr>
                  <th class="pb-2 pr-4 font-medium">
                    Name
                  </th>
                  <th class="pb-2 font-medium">
                    Values
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(tag, index) in event.tags"
                  :key="index"
                  class="border-t border-(--ui-border)"
                >
                  <td class="py-2 pr-4 align-top font-mono">
                    {{ tag[0] }}
                  </td>
                  <td class="break-all py-2 align-top font-mono">
                    {{ tag.slice(1).join(' · ') }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <p
            v-else
            class="text-sm text-(--ui-text-muted)"
          >
            This event has no tags.
          </p>
        </UCard>

        <UCard>
          <template #header>
            <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Raw event</span>
          </template>

          <pre class="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs">{{ json }}</pre>
        </UCard>
      </template>
    </template>
  </UDashboardPanel>
</template>
