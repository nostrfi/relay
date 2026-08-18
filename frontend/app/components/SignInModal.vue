<script setup lang="ts">
/**
 * The dashboard's only sign-in surface. Triggered from the header, so a
 * visitor reading the public relay page can sign in without leaving it.
 */
const open = defineModel<boolean>('open', { default: false })

const { login } = useAdminSession()

type Pending = 'nip07' | 'nip46' | 'nip46-restore'

const bunkerInput = ref('')
const pending = ref<Pending | null>(null)
const error = ref('')

const extensionAvailable = ref(false)
const storedBunker = ref(false)

// window.nostr and localStorage are client-only, and the modal can be opened
// long after mount, so both are re-read each time it opens.
watch(open, (isOpen) => {
  if (!isOpen) {
    return
  }
  error.value = ''
  extensionAvailable.value = hasNip07()
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
    // Privileged relay calls need a signature long after login; remember
    // which signer to reach for rather than guessing later.
    rememberSignerKind(signer.kind)
    open.value = false
    await navigateTo('/dashboard')
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
  <UModal
    v-model:open="open"
    title="Sign in"
    description="Prove ownership of the relay operator key to reach the dashboard."
  >
    <slot />

    <template #body>
      <p
        v-if="error"
        class="mb-6 rounded-(--ui-radius) border border-(--ui-error) px-4 py-3 text-sm text-(--ui-error)"
        role="alert"
      >
        {{ error }}
      </p>

      <section class="mb-8">
        <h3 class="mb-2 text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">
          Browser extension
        </h3>
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
      </section>

      <section>
        <h3 class="mb-2 text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">
          Remote signer
        </h3>

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
      </section>
    </template>
  </UModal>
</template>
