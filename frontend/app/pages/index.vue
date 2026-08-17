<script setup lang="ts">
const { data: relay } = await useFetch('/api/relay-info')
</script>

<template>
  <div class="mx-auto max-w-3xl px-4 py-12">
    <header class="mb-8 text-center">
      <h1 class="text-3xl font-bold">
        {{ relay?.name || 'Nostrfi Relay' }}
      </h1>
      <p
        v-if="relay?.description"
        class="mt-2 text-(--ui-text-muted)"
      >
        {{ relay.description }}
      </p>
    </header>

    <UCard class="mb-6">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Relay Information</span>
      </template>

      <dl class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Software
          </dt>
          <dd class="break-all">
            <a
              v-if="relay?.software"
              :href="relay.software"
              target="_blank"
              rel="noopener"
              class="text-primary hover:underline"
            >{{ relay.name }}</a>
          </dd>
        </div>
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Version
          </dt>
          <dd>{{ relay?.version }}</dd>
        </div>
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Contact
          </dt>
          <dd>{{ relay?.contact }}</dd>
        </div>
      </dl>

      <div class="mt-4">
        <dt class="text-sm text-(--ui-text-muted)">
          Operator
        </dt>
        <dd class="break-all font-mono text-sm">
          {{ relay?.pubkey }}
        </dd>
      </div>
    </UCard>

    <UCard class="mb-6">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Supported NIPs</span>
      </template>

      <div class="flex flex-wrap gap-2">
        <UBadge
          v-for="nip in relay?.supported_nips"
          :key="nip"
          variant="subtle"
          color="primary"
        >
          NIP-{{ nip }}
        </UBadge>
      </div>
    </UCard>

    <UCard v-if="relay?.limitation">
      <template #header>
        <span class="text-sm font-semibold uppercase tracking-wide text-(--ui-text-muted)">Limitations</span>
      </template>

      <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Max Message Length
          </dt>
          <dd>{{ relay.limitation.max_message_length }}</dd>
        </div>
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Max Subscriptions
          </dt>
          <dd>{{ relay.limitation.max_subscriptions }}</dd>
        </div>
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Auth Required
          </dt>
          <dd>{{ relay.limitation.auth_required }}</dd>
        </div>
        <div>
          <dt class="text-sm text-(--ui-text-muted)">
            Payment Required
          </dt>
          <dd>{{ relay.limitation.payment_required }}</dd>
        </div>
      </dl>
    </UCard>
  </div>
</template>
