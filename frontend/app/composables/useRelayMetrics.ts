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
  const { recheck } = useAdminSession()
  const samples = ref<MetricsSnapshot[]>([])
  const ready = ref<boolean | null>(null)
  const error = ref('')
  const polling = ref(false)
  const paused = ref(false)

  let timer: ReturnType<typeof setTimeout> | null = null
  let inFlight = false
  /** Set when a role re-check failed; polling waits for the operator. */
  let recheckBlocked = false

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
      const response = await fetchMetrics()
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
      if (recheckBlocked) {
        error.value = `Metrics need your signer to re-confirm your role: ${error.value}`
        paused.value = true
        stop()
      }
    } finally {
      inFlight = false
      polling.value = false
    }
  }

  /**
   * Reads one snapshot. Metrics are the one view the relay does not
   * authorize itself, so the dashboard asks for a recent role confirmation
   * first (D5, nostrfi/relay#56). When it has lapsed, one signed `whoami`
   * renews it and the read is retried; a revoked key is signed out instead.
   */
  async function fetchMetrics(): Promise<MetricsResponse> {
    try {
      return await $fetch<MetricsResponse>('/api/metrics')
    } catch (cause) {
      const body = (cause as { data?: { data?: { roleRecheckRequired?: unknown } } })?.data
      if (body?.data?.roleRecheckRequired !== true) {
        throw cause
      }
      try {
        await recheck()
      } catch (recheckCause) {
        // Declined or unreachable signer. Polling on would ask again every
        // five seconds, so stop until the operator asks for a sample.
        recheckBlocked = true
        throw recheckCause
      }
      return await $fetch<MetricsResponse>('/api/metrics')
    }
  }

  /** Schedules the next sample only once the current one is done. */
  function scheduleNext() {
    stop()
    timer = setTimeout(async () => {
      await sample()
      if (!paused.value && !recheckBlocked) {
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
    recheckBlocked = false
    await sample()
    if (!recheckBlocked) {
      scheduleNext()
    }
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

  // A manual refresh is the operator asking: it may prompt the signer again,
  // and resumes polling if that succeeds.
  async function refresh() {
    paused.value = false
    await start()
  }

  return { samples, latest, previous, ready, error, polling, paused, refresh }
}
