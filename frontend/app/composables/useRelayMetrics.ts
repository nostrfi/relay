import type { MetricsResponse, MetricsSnapshot } from '~~/shared/types/metrics'

/** How often to sample while the tab is visible. */
const POLL_INTERVAL_MS = 5_000

/**
 * How many samples to keep. At five seconds apart this is roughly the last
 * five minutes — enough for a sparkline, and deliberately not a history: the
 * window starts when the page opens and is gone when it closes.
 */
const MAX_SAMPLES = 60

/**
 * Polls the relay's metrics while the page is watching.
 *
 * Polling stops when the tab is hidden. A background tab that keeps asking
 * every five seconds is a request the operator did not make, and browsers
 * throttle the timer anyway — which would make the intervals a lie if any
 * rate were computed from the nominal period rather than the timestamps.
 */
export function useRelayMetrics() {
  const samples = ref<MetricsSnapshot[]>([])
  const ready = ref<boolean | null>(null)
  const relay = ref('')
  const error = ref('')
  const polling = ref(false)
  const paused = ref(false)

  let timer: ReturnType<typeof setInterval> | null = null

  async function sample() {
    polling.value = true
    try {
      const response = await $fetch<MetricsResponse>('/api/metrics')
      samples.value = [...samples.value, response.snapshot].slice(-MAX_SAMPLES)
      ready.value = response.ready
      relay.value = response.relay
      error.value = ''
    } catch (cause) {
      // Kept visible rather than swallowed: a poller that fails quietly looks
      // exactly like a relay with nothing happening (nostrfi/workspace#49).
      error.value = (cause as { statusMessage?: string })?.statusMessage
        || (cause as Error)?.message
        || 'The relay metrics could not be read.'
    } finally {
      polling.value = false
    }
  }

  function start() {
    stop()
    timer = setInterval(sample, POLL_INTERVAL_MS)
  }

  function stop() {
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'hidden') {
      paused.value = true
      stop()
      return
    }
    paused.value = false
    sample()
    start()
  }

  onMounted(() => {
    sample()
    start()
    document.addEventListener('visibilitychange', onVisibilityChange)
  })

  onBeforeUnmount(() => {
    stop()
    document.removeEventListener('visibilitychange', onVisibilityChange)
  })

  const latest = computed(() => samples.value.at(-1) ?? null)
  const previous = computed(() => samples.value.at(-2) ?? undefined)

  return { samples, latest, previous, ready, relay, error, polling, paused, refresh: sample }
}
