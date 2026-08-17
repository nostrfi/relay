/**
 * Fixed-window rate limiter for the unauthenticated session endpoints.
 *
 * Login verifies a Schnorr signature before it knows who the caller is, so
 * an open endpoint is a CPU amplifier. This bounds attempts per client
 * address. In-memory and per-process, matching challenge.ts.
 */

interface Window {
  count: number
  resetAt: number
}

const windows = new Map<string, Window>()

/** Caps memory if addresses are spoofed across a wide range. */
const MAX_TRACKED = 1024

export interface RateLimit {
  limit: number
  windowMs: number
}

export function allowRequest(key: string, { limit, windowMs }: RateLimit): boolean {
  const now = Date.now()

  for (const [tracked, window] of windows) {
    if (window.resetAt <= now) {
      windows.delete(tracked)
    }
  }

  if (windows.size >= MAX_TRACKED && !windows.has(key)) {
    return false
  }

  const window = windows.get(key)
  if (!window || window.resetAt <= now) {
    windows.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }

  if (window.count >= limit) {
    return false
  }

  window.count += 1
  return true
}

/** Test seam: drops all tracked windows. */
export function resetRateLimits(): void {
  windows.clear()
}
