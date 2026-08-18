<script setup lang="ts">
import type { StoredEvent } from '~~/shared/types/events'
import {
  EVENT_PAGE_SIZE,
  buildEventQuery,
  contentPreview,
  emptyEventQueryForm,
  formatEventTime,
  kindLabel,
  mergeEventPage,
  shortHex
} from '~~/shared/utils/event-query'

useSeoMeta({ title: 'Events' })

// Private by default — see app/middleware/auth.global.ts.
definePageMeta({ layout: 'dashboard' })

const { query } = useEvents()

const form = ref(emptyEventQueryForm())
const events = ref<StoredEvent[]>([])
const problems = ref<string[]>([])
const error = ref('')
const refusalCauses = ref<string[]>([])
const refusalLogHint = ref('')
const busy = ref(false)

/** False until a query has actually come back, so "no events" is honest. */
const ran = ref(false)

/** The relay's cursor for the next page; null when this is the last. */
const nextUntil = ref<number | null>(null)

/** What the relay applied, which can be lower than the page size asked for. */
const appliedLimit = ref(EVENT_PAGE_SIZE)

async function run(append: boolean) {
  const built = buildEventQuery(form.value, append && nextUntil.value !== null ? nextUntil.value : undefined)
  problems.value = built.errors
  if (!built.request) {
    return
  }

  busy.value = true
  error.value = ''
  refusalCauses.value = []
  refusalLogHint.value = ''

  try {
    const page = await query(built.request)
    // Merged rather than concatenated: the cursor is a timestamp, so events
    // sharing the boundary second arrive on both pages.
    events.value = append ? mergeEventPage(events.value, page.events) : page.events
    nextUntil.value = page.next_until ?? null
    appliedLimit.value = page.limit
    ran.value = true
  } catch (cause) {
    // useEvents turns a relay refusal into a headline plus the causes that
    // could produce it, rather than asserting one. See relay-refusal.ts.
    const refused = cause as { refusal?: { headline: string, causes: string[] }, logHint?: string }
    error.value = refused.refusal?.headline || (cause as Error)?.message || 'The events could not be read.'
    refusalCauses.value = refused.refusal?.causes ?? []
    refusalLogHint.value = refused.logHint ?? ''
  } finally {
    busy.value = false
  }
}

function reset() {
  form.value = emptyEventQueryForm()
  problems.value = []
}

onMounted(() => run(false))
</script>

<template>
  <UDashboardPanel id="events">
    <template #header>
      <UDashboardNavbar title="Events" />
    </template>

    <template #body>
      <p class="mb-6 max-w-3xl text-(--ui-text-muted)">
        The events this relay has stored, newest first. Each query is signed with your key and
        answered by the relay itself, so it shows what the relay would serve: expired events and
        events banned through moderation are not here.
      </p>

      <UCard class="mb-6">
        <form
          class="grid grid-cols-1 gap-4 sm:grid-cols-2"
          @submit.prevent="run(false)"
        >
          <UFormField
            label="Kinds"
            hint="Comma-separated"
          >
            <UInput
              v-model="form.kinds"
              placeholder="1, 7"
              class="w-full"
            />
          </UFormField>

          <UFormField
            label="Author"
            hint="Hex pubkey or prefix"
          >
            <UInput
              v-model="form.author"
              placeholder="3bf0c63f…"
              class="w-full font-mono"
            />
          </UFormField>

          <UFormField
            label="Event ID"
            hint="Hex id or prefix"
          >
            <UInput
              v-model="form.id"
              placeholder="a1b2c3d4…"
              class="w-full font-mono"
            />
          </UFormField>

          <UFormField
            label="Content contains"
            hint="At least 3 characters"
          >
            <UInput
              v-model="form.content"
              placeholder="substring"
              class="w-full"
            />
          </UFormField>

          <UFormField
            label="Tag"
            hint="Single letter, e.g. e or p"
          >
            <div class="flex gap-2">
              <UInput
                v-model="form.tagName"
                placeholder="e"
                class="w-16 font-mono"
              />
              <UInput
                v-model="form.tagValue"
                placeholder="value"
                class="w-full font-mono"
              />
            </div>
          </UFormField>

          <div class="grid grid-cols-2 gap-2">
            <UFormField label="From">
              <UInput
                v-model="form.since"
                type="datetime-local"
                class="w-full"
              />
            </UFormField>
            <UFormField label="To">
              <UInput
                v-model="form.until"
                type="datetime-local"
                class="w-full"
              />
            </UFormField>
          </div>

          <div class="flex items-end gap-2 sm:col-span-2">
            <UButton
              type="submit"
              :loading="busy"
              icon="i-lucide-search"
            >
              Run query
            </UButton>
            <UButton
              variant="ghost"
              color="neutral"
              :disabled="busy"
              @click="reset"
            >
              Clear filters
            </UButton>
            <p class="ml-auto text-sm text-(--ui-text-dimmed)">
              Each query is signed once, and returns up to {{ appliedLimit }} events.
            </p>
          </div>
        </form>

        <ul
          v-if="problems.length > 0"
          class="mt-4 flex list-disc flex-col gap-1 pl-5 text-sm text-(--ui-error)"
        >
          <li
            v-for="problem in problems"
            :key="problem"
          >
            {{ problem }}
          </li>
        </ul>
      </UCard>

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
          @click="run(false)"
        >
          Try again
        </UButton>
      </div>

      <UCard>
        <template #header>
          <div class="flex items-center justify-between gap-4">
            <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Results</span>
            <span
              v-if="ran"
              class="nf-tabular text-sm text-(--ui-text-dimmed)"
            >{{ events.length }} shown</span>
          </div>
        </template>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="text-(--ui-text-muted)">
              <tr>
                <th class="pb-2 pr-4 font-medium">
                  Time
                </th>
                <th class="pb-2 pr-4 font-medium">
                  Kind
                </th>
                <th class="pb-2 pr-4 font-medium">
                  Author
                </th>
                <th class="pb-2 pr-4 font-medium">
                  Content
                </th>
                <th class="pb-2 font-medium">
                  <span class="sr-only">Open</span>
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="event in events"
                :key="event.id"
                class="border-t border-(--ui-border)"
              >
                <td class="nf-tabular whitespace-nowrap py-2 pr-4 align-top">
                  {{ formatEventTime(event.created_at) }}
                </td>
                <td class="whitespace-nowrap py-2 pr-4 align-top">
                  {{ kindLabel(event.kind) }}
                </td>
                <td
                  class="py-2 pr-4 align-top font-mono"
                  :title="event.pubkey"
                >
                  {{ shortHex(event.pubkey) }}
                </td>
                <td class="py-2 pr-4 align-top">
                  {{ contentPreview(event.content) }}
                </td>
                <td class="py-2 align-top">
                  <UButton
                    :to="`/dashboard/events/${event.id}`"
                    size="xs"
                    variant="subtle"
                  >
                    Open
                  </UButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <p
          v-if="ran && events.length === 0 && !error"
          class="py-4 text-sm text-(--ui-text-muted)"
        >
          No stored event matches this filter.
        </p>

        <template
          v-if="nextUntil !== null"
          #footer
        >
          <UButton
            variant="subtle"
            size="xs"
            :loading="busy"
            @click="run(true)"
          >
            Load more
          </UButton>
          <p class="mt-2 text-sm text-(--ui-text-dimmed)">
            Paging continues from the oldest event shown, and costs one more signature.
          </p>
        </template>
      </UCard>
    </template>
  </UDashboardPanel>
</template>
