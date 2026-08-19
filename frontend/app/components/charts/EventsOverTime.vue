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
  return point ? periodLabel(point.start, props.bucket) : ''
}

const triggers = {
  [StackedBar.selectors.bar]: (point: ChartPoint) =>
    `<div class="nf-chart-tooltip">
       <div class="nf-chart-tooltip__label">${periodTooltipLabel(point.start, props.bucket)}</div>
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
