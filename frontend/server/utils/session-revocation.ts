import { randomUUID } from 'node:crypto'

/**
 * Which sealed session cookies the dashboard still honours.
 *
 * A sealed cookie cannot be withdrawn from the browser. Clearing it only
 * works if no later response sets it again, and any copy of it unseals until
 * it expires. So the server keeps the last word itself, with two checks:
 *
 *   - Each sign-in gets a fresh `sid`. Logging out, signing in over the
 *     session, or the relay revoking the key records that sid here until
 *     the cookie would have expired. A request that was waiting on the relay
 *     when this happened can still set the cookie again on its way out, but
 *     the cookie no longer works.
 *   - Each session also records the `boot` id of the process that issued it.
 *     The revoked sids live in process memory, like the login challenges
 *     (server/utils/challenge.ts), because the dashboard runs as one Node
 *     process. A restart would forget them and bring every logged-out cookie
 *     back. Instead, a restart ends every session, and operators sign in
 *     again.
 *
 * Free of h3 and Nuxt so it can be tested directly.
 */

export interface SessionIdentity {
  sid?: string
  boot?: string
}

export interface SessionRevocations {
  /** The boot id new sessions are stamped with. */
  readonly bootId: string
  /** Stops honouring `sid` until `expiresAtMs`, when its cookie is dead anyway. */
  revoke: (sid: string, expiresAtMs: number, nowMs?: number) => void
  /** True for a session this process issued and has not revoked. */
  isLive: (session: SessionIdentity) => boolean
  /** Revoked sids still remembered; for tests. */
  size: () => number
}

export function createSessionRevocations(bootId: string = randomUUID()): SessionRevocations {
  const revoked = new Map<string, number>()

  function prune(nowMs: number): void {
    for (const [sid, expiresAtMs] of revoked) {
      if (expiresAtMs <= nowMs) {
        revoked.delete(sid)
      }
    }
  }

  return {
    bootId,
    revoke(sid, expiresAtMs, nowMs = Date.now()) {
      prune(nowMs)
      if (expiresAtMs > nowMs) {
        revoked.set(sid, expiresAtMs)
      }
    },
    isLive(session) {
      return session.sid !== undefined && session.boot === bootId && !revoked.has(session.sid)
    },
    size: () => revoked.size
  }
}
