<script setup lang="ts">
withDefaults(defineProps<{
  size?: number
  alt?: string
}>(), {
  size: 32,
  alt: 'Nostrfi'
})

// The dashboard is served under app.baseURL ('/admin'), and Vue does not
// rewrite absolute asset URLs in templates, so public assets must be joined
// to the base by hand or they 404 behind Caddy.
const base = useRuntimeConfig().app.baseURL.replace(/\/$/, '')
const lightLogo = `${base}/brand/light/nostrfi.png`
const darkLogo = `${base}/brand/dark/nostrfi.png`
</script>

<template>
  <div
    class="app-logo-wrapper"
    :style="{ width: `${size}px`, height: `${size}px` }"
  >
    <img
      :src="lightLogo"
      :width="size"
      :height="size"
      :alt="alt"
      loading="eager"
      decoding="async"
      class="app-logo light-logo"
    >
    <img
      :src="darkLogo"
      :width="size"
      :height="size"
      :alt="alt"
      loading="eager"
      decoding="async"
      class="app-logo dark-logo"
    >
  </div>
</template>

<style scoped>
.app-logo-wrapper {
  display: block;
  position: relative;
}

.app-logo {
  display: block;
  aspect-ratio: 1 / 1;
  object-fit: contain;
}

.dark-logo {
  display: none;
}

.light-logo {
  display: block;
}

/*
 * Swap logos in dark mode (.dark on <html>, set by Nuxt UI color mode before
 * first paint). :global() must wrap the entire selector — a global ancestor
 * combined with a scoped descendant gets miscompiled.
 */
:global(.dark .light-logo) {
  display: none;
}

:global(.dark .dark-logo) {
  display: block;
}
</style>
