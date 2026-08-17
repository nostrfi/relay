<script setup lang="ts">
// Public assets sit under app.baseURL ('/admin'), so favicon hrefs are joined
// to the base rather than written as bare absolute paths.
const base = useRuntimeConfig().app.baseURL.replace(/\/$/, '')

useHead({
  htmlAttrs: {
    lang: 'en'
  },
  link: [
    { rel: 'icon', type: 'image/png', sizes: '96x96', href: `${base}/favicon-96x96.png` },
    { rel: 'icon', type: 'image/x-icon', href: `${base}/favicon.ico` },
    { rel: 'apple-touch-icon', sizes: '180x180', href: `${base}/apple-touch-icon.png` }
  ]
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
