<script setup lang="ts">
import { npubEncode } from 'nostr-tools/nip19'

/**
 * The shell every private page renders inside.
 *
 * The public landing page keeps `default.vue`: it is a single page, and a
 * sidebar of operator areas would offer a signed-out visitor a menu of
 * things they cannot open.
 *
 * Only pages that exist appear here. The areas still to be built (event
 * browser #36, metrics #39) are listed on the overview page with their
 * issue numbers, where they read as a roadmap rather than as navigation
 * that goes nowhere.
 *
 * The root carries `data-nf-mode="signal"`, like the public shell: the
 * dashboard is a configuration, moderation and trust surface, so it never
 * takes the Sovereign hero treatment. See CODINGSTANDARDS.md, "Styling and
 * brand".
 */
const links = [
  { label: 'Overview', icon: 'i-lucide-layout-dashboard', to: '/dashboard' },
  { label: 'Moderation', icon: 'i-lucide-shield-ban', to: '/dashboard/moderation' },
  { label: 'Configuration', icon: 'i-lucide-settings', to: '/dashboard/configuration' }
]

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
</script>

<template>
  <UDashboardGroup
    data-nf-mode="signal"
    class="nf-dashboard"
  >
    <UDashboardSidebar
      collapsible
      resizable
      :ui="{ header: 'gap-2', footer: 'border-t border-(--ui-border)' }"
    >
      <template #header="{ collapsed }">
        <AppLogo :size="28" />
        <span
          v-if="!collapsed"
          class="nf-wordmark font-display"
        >Relay Admin</span>
        <UDashboardSidebarCollapse class="ms-auto" />
      </template>

      <template #default="{ collapsed }">
        <UNavigationMenu
          :items="links"
          :collapsed="collapsed"
          orientation="vertical"
        />
      </template>

      <template #footer="{ collapsed }">
        <!--
          The signed-in identity, and the only way out of the session.
          Signing *in* stays on the public shell's modal — one sign-in
          surface, per CODINGSTANDARDS.md, "Authentication and sessions".
        -->
        <span
          v-if="npub && !collapsed"
          class="nf-npub font-mono truncate"
          :title="npub.full"
        >{{ npub.short }}</span>
        <UButton
          icon="i-lucide-log-out"
          size="xs"
          variant="ghost"
          color="neutral"
          :label="collapsed ? undefined : 'Sign out'"
          :square="collapsed"
          class="ms-auto"
          @click="signOut"
        />
      </template>
    </UDashboardSidebar>

    <slot />
  </UDashboardGroup>
</template>

<style scoped>
.nf-dashboard {
  min-height: 100vh;
  background: var(--ui-bg);
  color: var(--ui-text);
}

.nf-wordmark {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text-highlighted);
}

.nf-npub {
  font-size: 13px;
  color: var(--ui-text-muted);
}
</style>
