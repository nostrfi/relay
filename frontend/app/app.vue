<script setup lang="ts">
useHead({
  htmlAttrs: {
    lang: 'en'
  }
})

useSeoMeta({
  titleTemplate: '%s — Relay Admin',
  description: 'Administration dashboard for the Nostrfi relay.'
})
</script>

<template>
  <UApp>
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
  </UApp>
</template>
