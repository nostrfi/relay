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
  const error = ref('')
  const polling = ref(false)
  const paused = ref(false)

  let timer: ReturnType<typeof setTimeout> | null = null
  let inFlight = false

  async function sample() {
    // One at a time. With setInterval, a sample slower than the interval
    // overlaps the next, and the responses can land out of order — an older
    // snapshot appended after a newer one reads as a counter going backwards,
    // which this page reports as a relay restart that never happened.
    if (inFlight) {
      return
    }
    inFlight = true
    polling.value = true
    try {
      const response = await $fetch<MetricsResponse>('/api/metrics')
      samples.value = [...samples.value, response.snapshot].slice(-MAX_SAMPLES)
      ready.value = response.ready
      error.value = ''
    } catch (cause) {
      // Kept visible rather than swallowed: a poller that fails quietly looks
      // exactly like a relay with nothing happening (nostrfi/workspace#49).
      error.value = (cause as { statusMessage?: string })?.statusMessage
        || (cause as Error)?.message
        || 'The relay metrics could not be read.'
      // And readiness becomes unknown rather than staying green: the last
      // "ready" is a statement about a relay this page can no longer reach.
      ready.value = null
    } finally {
      inFlight = false
      polling.value = false
    }
  }

  /** Schedules the next sample only once the current one is done. */
  function scheduleNext() {
    stop()
    timer = setTimeout(async () => {
      await sample()
      if (!paused.value) {
        scheduleNext()
      }
    }, POLL_INTERVAL_MS)
  }

  function stop() {
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  async function start() {
    await sample()
    scheduleNext()
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'hidden') {
      paused.value = true
      stop()
      return
    }
    paused.value = false
    start()
  }

  onMounted(() => {
    // A tab restored in the background is already hidden here, and no
    // visibilitychange fires to tell us — polling would run for the whole
    // time it sat there unwatched.
    if (document.visibilityState === 'hidden') {
      paused.value = true
    } else {
      start()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
  })

  onBeforeUnmount(() => {
    stop()
    document.removeEventListener('visibilitychange', onVisibilityChange)
  })

  const latest = computed(() => samples.value.at(-1) ?? null)
  const previous = computed(() => samples.value.at(-2) ?? undefined)

  return { samples, latest, previous, ready, error, polling, paused, refresh: sample }
}
