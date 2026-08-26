<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'

const { state, logout } = useAdminSession()

// Truncated with the full value kept accessible, per the brand rule for
// protocol identifiers.
const npub = computed(() => {
  const pubkey = state.value?.pubkey
  if (!pubkey) {
    return null
  }
  const encoded = npubEncode(pubkey)
  return { full: encoded, short: `${encoded.slice(0, 10)}…${encoded.slice(-6)}` }
})

async function signOut() {
  await logout()
  await navigateTo('/')
}

/**
 * Opened by the header button, or by ?signin=1 — which is where the auth
 * middleware sends someone who reached a private page signed out.
 */
const route = useRoute()
const signInOpen = ref(route.query.signin !== undefined)

watch(() => route.query.signin, (value) => {
  if (value !== undefined) {
    signInOpen.value = true
  }
})
</script>

<template>
  <div
    data-nf-mode="signal"
    class="nf-shell"
  >
    <header class="nf-header">
      <div class="nf-header__inner">
        <AppLogo :size="32" />
        <span class="nf-wordmark font-display">Relay Admin</span>

        <div class="nf-identity">
          <!--
            Leftmost in the identity cluster so it sits in the same place
            signed in and signed out. Binary light/dark: the dark palette
            already exists in main.css, this is the only thing that was
            missing (nostrfi/relay#31).
          -->
          <UColorModeButton size="xs" />

          <template v-if="npub">
            <NuxtLink
              to="/dashboard"
              class="nf-header__link"
            >
              Dashboard
            </NuxtLink>
            <span
              class="nf-npub font-mono"
              :title="npub.full"
            >{{ npub.short }}</span>
            <UButton
              size="xs"
              variant="ghost"
              @click="signOut"
            >
              Sign out
            </UButton>
          </template>

          <SignInModal
            v-else
            v-model:open="signInOpen"
          >
            <UButton size="xs">
              Sign in
            </UButton>
          </SignInModal>
        </div>
      </div>
    </header>

    <main class="nf-main">
      <slot />
    </main>
  </div>
</template>

<style scoped>
/*
 * The shell root carries data-nf-mode="signal": the dashboard is a
 * configuration and moderation surface, so it never takes the Sovereign hero
 * treatment. See 60-marketing/brand/brand-system.md, "Transition rule".
 */
.nf-shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  background: var(--ui-bg);
  color: var(--ui-text);
}

/*
 * Product UI separates with borders and tonal shift before shadows —
 * the marketing shadow token is deliberately not used here.
 */
.nf-header {
  background: var(--ui-bg-elevated);
  border-bottom: 1px solid var(--ui-border);
}

.nf-header__inner {
  display: flex;
  align-items: center;
  gap: var(--nf-space-3);
  max-width: var(--ui-container);
  margin: 0 auto;
  padding: var(--nf-space-3) var(--nf-space-4);
}

.nf-wordmark {
  font-size: 18px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text-highlighted);
}

.nf-identity {
  display: flex;
  align-items: center;
  gap: var(--nf-space-2);
  margin-left: auto;
}

.nf-npub {
  font-size: 13px;
  color: var(--ui-text-muted);
}

.nf-header__link {
  font-size: 14px;
  color: var(--ui-text-muted);
}

.nf-header__link:hover {
  color: var(--ui-text);
}

.nf-main {
  flex: 1;
  width: 100%;
  max-width: var(--ui-container);
  margin: 0 auto;
  padding: var(--nf-space-8) var(--nf-space-4) var(--nf-space-16);
}
</style>
