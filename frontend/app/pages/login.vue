<script setup lang="ts">
const { login } = useAdminSession()

useSeoMeta({ title: 'Sign in' })

const bunkerInput = ref('')
type Pending = 'nip07' | 'nip46' | 'nip46-restore'

const pending = ref<Pending | null>(null)
const error = ref('')

const extensionAvailable = ref(false)
const storedBunker = ref(false)
onMounted(() => {
  extensionAvailable.value = hasNip07()
  // A previous bunker pairing can be reconnected instead of re-pairing from
  // the URL, which is the point of persisting it.
  storedBunker.value = hasStoredBunker()
})

async function reconnectBunker(): Promise<Signer> {
  const signer = await restoreBunkerSigner()
  if (!signer) {
    storedBunker.value = false
    throw new Error('The saved remote signer could not be reconnected. Enter its bunker URL again.')
  }
  return signer
}

async function signIn(create: () => Promise<Signer>, kind: Pending) {
  error.value = ''
  pending.value = kind

  let signer: Signer | null = null
  try {
    signer = await create()
    await login(signer)
    await navigateTo('/')
  } catch (cause) {
    error.value = messageFor(cause)
  } finally {
    // A NIP-46 connection is a live relay subscription; drop it once the
    // session cookie is set. Later actions reconnect from stored pairing.
    await signer?.close()
    pending.value = null
  }
}

function messageFor(cause: unknown): string {
  const status = (cause as { statusCode?: number })?.statusCode
  if (status === 401) {
    return 'That key is not this relay\'s configured operator.'
  }
  if (status === 429) {
    return 'Too many attempts. Wait a minute and try again.'
  }
  return (cause as Error)?.message || 'Sign-in failed.'
}
</script>

<template>
  <div class="mx-auto max-w-md">
    <h1 class="font-display mb-2 text-2xl font-semibold tracking-tight">
      Sign in
    </h1>
    <p class="mb-8 text-(--ui-text-muted)">
      Prove ownership of the relay operator key to reach the dashboard.
    </p>

    <p
      v-if="error"
      class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
      role="alert"
    >
      {{ error }}
    </p>

    <UCard class="mb-6">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Browser extension</span>
      </template>

      <p class="mb-4 text-sm text-(--ui-text-muted)">
        Sign with a NIP-07 extension such as Alby or nos2x.
      </p>

      <UButton
        :loading="pending === 'nip07'"
        :disabled="pending !== null || !extensionAvailable"
        @click="signIn(async () => nip07Signer(), 'nip07')"
      >
        Sign in with extension
      </UButton>

      <p
        v-if="!extensionAvailable"
        class="mt-3 text-sm text-(--ui-text-dimmed)"
      >
        No signing extension detected in this browser.
      </p>
    </UCard>

    <UCard>
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Remote signer</span>
      </template>

      <div
        v-if="storedBunker"
        class="mb-6"
      >
        <p class="mb-3 text-sm text-(--ui-text-muted)">
          This browser is already paired with a remote signer.
        </p>
        <UButton
          :loading="pending === 'nip46-restore'"
          :disabled="pending !== null"
          @click="signIn(reconnectBunker, 'nip46-restore')"
        >
          Reconnect saved signer
        </UButton>
      </div>

      <p class="mb-4 text-sm text-(--ui-text-muted)">
        {{ storedBunker ? 'Or pair a different signer' : 'Connect a NIP-46 bunker' }} with its
        <code class="font-mono">bunker://</code> URL, or a
        <code class="font-mono">name@domain</code> identifier.
      </p>

      <form
        class="flex flex-col gap-3 sm:flex-row"
        @submit.prevent="signIn(() => bunkerSigner(bunkerInput), 'nip46')"
      >
        <UInput
          v-model="bunkerInput"
          class="flex-1"
          placeholder="bunker://…"
          autocomplete="off"
          spellcheck="false"
          aria-label="Bunker URL or NIP-05 identifier"
        />
        <UButton
          type="submit"
          :loading="pending === 'nip46'"
          :disabled="pending !== null || bunkerInput.trim() === ''"
        >
          Connect
        </UButton>
      </form>
    </UCard>
  </div>
</template>
