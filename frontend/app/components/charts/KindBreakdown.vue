<script setup lang="ts">
import type { RankedKind } from '~~/shared/utils/event-stats'
import { formatCount } from '~~/shared/utils/event-stats'

/**
 * The kind breakdown, ranked.
 *
 * A ranked bar rather than a pie, decided in nostrfi/workspace#50: relay
 * traffic is long-tailed — one kind dominates and the tail is the
 * interesting part — and a pie renders exactly that tail as unreadable
 * slivers. Length compares against the largest kind; the share figure keeps
 * the part-to-whole reading a pie would have offered.
 *
 * Rendered as a labelled list rather than an SVG chart, which is what makes
 * it its own table view: every value is text, in the DOM, in reading order.
 */
defineProps<{
  kinds: RankedKind[]
  remainder: number
}>()
</script>

<template>
  <div>
    <ol class="flex flex-col gap-3">
      <li
        v-for="kind in kinds"
        :key="kind.kind"
        class="grid grid-cols-[minmax(7rem,auto)_1fr_auto] items-center gap-3"
      >
        <span class="truncate text-sm">{{ kind.label }}</span>

        <span
          class="nf-kind-track"
          role="presentation"
        >
          <span
            class="nf-kind-bar"
            :style="{ width: `${Math.max(kind.fraction * 100, 1)}%` }"
          />
        </span>

        <span class="nf-tabular whitespace-nowrap text-sm text-(--ui-text-muted)">
          {{ formatCount(kind.count) }}
          <span class="text-(--ui-text-dimmed)">·&nbsp;{{ Math.round(kind.share * 100) }}%</span>
        </span>
      </li>
    </ol>

    <p
      v-if="remainder > 0"
      class="mt-3 text-sm text-(--ui-text-dimmed)"
    >
      {{ formatCount(remainder) }} more events in kinds outside the top {{ kinds.length }}.
    </p>
  </div>
</template>

<style scoped>
.nf-kind-track {
  display: block;
  height: 8px;
  border-radius: var(--nf-radius-pill);
  background: var(--ui-bg-accented);
}

.nf-kind-bar {
  display: block;
  height: 100%;
  border-radius: var(--nf-radius-pill);
  background: var(--nf-chart-series);
}
</style>
