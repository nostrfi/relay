<script setup lang="ts">
// The relay's public face. No session required: the relay serves this same
// NIP-11 document to any anonymous caller, so nothing here is sensitive.
definePageMeta({ public: true })

const { data: relay } = await useFetch('/api/relay-info')
</script>

<template>
  <div class="mx-auto max-w-3xl">
    <header class="mb-8">
      <h1 class="font-display text-3xl font-semibold tracking-tight">
        {{ relay?.name || 'Nostrfi Relay' }}
      </h1>
      <p
        v-if="relay?.description"
        class="mt-2 text-(--ui-text-muted)"
      >
        {{ relay.description }}
      </p>
    </header>

    <RelayInfoCards :relay="relay" />
  </div>
</template>
