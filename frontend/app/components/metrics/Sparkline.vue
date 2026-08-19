<script setup lang="ts">
/**
 * A rate over the samples this page has taken.
 *
 * Hand-drawn SVG rather than a chart component: it carries no axes, no
 * legend and no tooltip, it is one of many in a table, and a charting
 * library instance per row would cost more than the line is worth. The
 * numbers beside it in the table are the accessible reading; this is
 * decoration, and marked as such.
 */
const props = defineProps<{
  /** Oldest first. Nulls are gaps — a restart, or an interval with no rate. */
  values: (number | null)[]
}>()

const WIDTH = 96
const HEIGHT = 24

const path = computed(() => {
  const values = props.values
  if (values.length < 2) {
    return ''
  }
  const highest = Math.max(1, ...values.filter((v): v is number => v !== null))
  const step = WIDTH / (values.length - 1)

  // Gaps break the line rather than being drawn through: a restart is not a
  // measurement, and a line across it would invent one.
  let commands = ''
  let penDown = false
  values.forEach((value, index) => {
    if (value === null) {
      penDown = false
      return
    }
    const x = index * step
    const y = HEIGHT - (value / highest) * (HEIGHT - 2) - 1
    commands += `${penDown ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)} `
    penDown = true
  })
  return commands.trim()
})
</script>

<template>
  <svg
    :width="WIDTH"
    :height="HEIGHT"
    :viewBox="`0 0 ${WIDTH} ${HEIGHT}`"
    aria-hidden="true"
    focusable="false"
    class="overflow-visible"
  >
    <path
      v-if="path"
      :d="path"
      fill="none"
      stroke="var(--nf-chart-series)"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
    />
  </svg>
</template>
