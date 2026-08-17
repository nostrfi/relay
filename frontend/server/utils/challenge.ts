import { randomBytes } from 'node:crypto'

/**
 * One-time login challenges.
 *
 * NIP-98's created_at window alone permits replay inside that window: an
 * observed auth event could be sent again by anyone who captured it. Binding
 * each login to a server-issued nonce that is consumed on first use closes
 * that, the same way NIP-42 binds a WebSocket AUTH event to a per-connection
 * challenge.
 *
 * Held in process memory: the dashboard runs as a single Node process (see
 * docs/operations.md). Challenges do not survive a restart — an operator
 * mid-login simply retries — and this would need a shared store before the
 * dashboard could be scaled to more than one replica.
 */

const CHALLENGE_TTL_MS = 5 * 60 * 1000

/**
 * Bounds memory if the unauthenticated challenge endpoint is hammered.
 * Reaching this ceiling evicts the oldest outstanding challenges, which at
 * worst makes a concurrent login retry.
 */
const MAX_OUTSTANDING = 256

const challenges = new Map<string, number>()

function pruneExpired(now: number): void {
  for (const [value, expiresAt] of challenges) {
    if (expiresAt <= now) {
      challenges.delete(value)
    }
  }
}

export function issueChallenge(): string {
  const now = Date.now()
  pruneExpired(now)

  // Map preserves insertion order, so the first keys are the oldest.
  while (challenges.size >= MAX_OUTSTANDING) {
    const oldest = challenges.keys().next()
    if (oldest.done) {
      break
    }
    challenges.delete(oldest.value)
  }

  const value = randomBytes(32).toString('hex')
  challenges.set(value, now + CHALLENGE_TTL_MS)
  return value
}

/** Returns true at most once per issued challenge. */
export function consumeChallenge(value: string): boolean {
  const now = Date.now()
  pruneExpired(now)

  const expiresAt = challenges.get(value)
  if (expiresAt === undefined || expiresAt <= now) {
    return false
  }
  challenges.delete(value)
  return true
}

/** Test seam: drops all outstanding challenges. */
export function resetChallenges(): void {
  challenges.clear()
}
