<script setup lang="ts">
import { VisAxis, VisStackedBar, VisTooltip, VisXYContainer } from '@unovis/vue'
import { StackedBar } from '@unovis/ts'
import type { StatsBucket } from '~~/shared/types/event-stats'
import type { ChartPoint } from '~~/shared/utils/event-stats'
import { formatCount, periodLabel, periodTooltipLabel } from '~~/shared/utils/event-stats'

/**
 * Events received per period.
 *
 * One series, so one hue and no legend — the heading names what the bars
 * are. Colour comes from the validated chart token rather than a literal;
 * see the note beside --nf-chart-series in main.css.
 */
const props = defineProps<{
  points: ChartPoint[]
  bucket: StatsBucket
  /** The fixed offset the relay bucketed with, so labels match the bars. */
  offsetSeconds: number
  /** Names the clock, for the caption and the table. */
  clockLabel: string
}>()

const x = (point: ChartPoint, index: number) => index
const y = (point: ChartPoint) => point.count

/** Enough ticks to orient, never one per bar — labels would collide. */
const tickValues = computed(() => {
  const count = props.points.length
  if (count <= 1) {
    return [0]
  }
  const step = Math.max(1, Math.ceil(count / 6))
  const ticks: number[] = []
  for (let i = 0; i < count; i += step) {
    ticks.push(i)
  }
  return ticks
})

const tickFormat = (index: number) => {
  const point = props.points[Math.round(index)]
  return point ? periodLabel(point.start, props.bucket, props.offsetSeconds) : ''
}

/**
 * The same numbers as text.
 *
 * The bars carry the values graphically and the tooltip needs a pointer, so
 * without this the counts are unreachable by keyboard or screen reader — and
 * the page's single total cannot say which periods were busy and which were
 * silent. Collapsed by default so it does not compete with the chart, and
 * present in the DOM either way (nostrfi/relay#29 review).
 */
const tableRows = computed(() => props.points.map(point => ({
  label: periodTooltipLabel(point.start, props.bucket, props.offsetSeconds),
  count: point.count
})))

const triggers = {
  [StackedBar.selectors.bar]: (point: ChartPoint) =>
    `<div class="nf-chart-tooltip">
       <div class="nf-chart-tooltip__label">${periodTooltipLabel(point.start, props.bucket, props.offsetSeconds)}</div>
       <div class="nf-chart-tooltip__value">${formatCount(point.count)} events</div>
     </div>`
}
</script>

<template>
  <div class="nf-chart">
    <!-- Unovis renders to the DOM, so it is client-only; the server sends the
         card and the axis area, not a chart that would then be replaced. -->
    <ClientOnly>
      <VisXYContainer
        :data="points"
        :height="220"
        :margin="{ top: 8, right: 8, bottom: 8, left: 8 }"
      >
        <VisStackedBar
          :x="x"
          :y="y"
          :rounded-corners="4"
          :bar-min-height="1"
          color="var(--nf-chart-series)"
        />
        <VisAxis
          type="x"
          :tick-values="tickValues"
          :tick-format="tickFormat"
          :grid-line="false"
          :tick-line="false"
        />
        <VisAxis
          type="y"
          :tick-format="formatCount"
          :num-ticks="4"
          :tick-line="false"
          :domain-line="false"
        />
        <VisTooltip :triggers="triggers" />
      </VisXYContainer>

      <template #fallback>
        <div
          class="nf-chart__placeholder"
          aria-hidden="true"
        />
      </template>
    </ClientOnly>

    <details class="mt-3">
      <summary class="cursor-pointer text-sm text-(--ui-text-muted)">
        View as a table ({{ clockLabel }})
      </summary>
      <div class="mt-2 max-h-64 overflow-y-auto">
        <table class="w-full text-left text-sm">
          <caption class="sr-only">
            Events per period, in {{ clockLabel }}
          </caption>
          <thead class="text-(--ui-text-muted)">
            <tr>
              <th
                scope="col"
                class="pb-1 pr-4 font-medium"
              >
                Period
              </th>
              <th
                scope="col"
                class="pb-1 font-medium"
              >
                Events
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in tableRows"
              :key="row.label"
              class="border-t border-(--ui-border)"
            >
              <td class="py-1 pr-4">
                {{ row.label }}
              </td>
              <td class="nf-tabular py-1">
                {{ formatCount(row.count) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </details>
  </div>
</template>

<style scoped>
.nf-chart {
  width: 100%;
}

.nf-chart__placeholder {
  height: 220px;
}

/* Recessive chrome: the data is the only thing that carries colour. */
.nf-chart :deep(.vis-axis-tick-label) {
  fill: var(--nf-chart-axis);
  font-size: 12px;
  font-family: var(--nf-font-body);
}

.nf-chart :deep(.vis-axis-grid-line),
.nf-chart :deep(.vis-axis-domain-line) {
  stroke: var(--nf-chart-grid);
}
</style>
