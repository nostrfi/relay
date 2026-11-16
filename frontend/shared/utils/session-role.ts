import type { DashboardRole } from '~~/shared/types/session'

/**
 * The pure half of role-based dashboard sessions (nostrfi/relay#56).
 *
 * The relay decides who is the owner and who is an administrator; the
 * dashboard only records what the relay said and when. Everything here is
 * free of h3 and Nuxt so it can be tested directly.
 */

/**
 * How long a role confirmation lasts before the browser is asked to sign a
 * fresh `whoami`.
 *
 * Every signed relay call the dashboard proxies already confirms the role
 * as a side effect (see server/utils/relay-forward.ts), so this only fires
 * for an operator who has made none for this long — in practice, one
 * watching the Metrics page, which is the one route the relay does not
 * authorize itself. It bounds how long a revoked administrator keeps that
 * view.
 */
export const ROLE_RECHECK_SECONDS = 15 * 60

/** The body the browser signs to ask the relay who it is. */
export const WHOAMI_REQUEST = { method: 'whoami', params: [] as unknown[] }

const ROLE_RANK: Record<DashboardRole, number> = { admin: 1, owner: 2 }

export function isDashboardRole(value: unknown): value is DashboardRole {
  return value === 'owner' || value === 'admin'
}

/** Mirrors the relay's Role.Satisfies: the owner can do anything an admin can. */
export function roleSatisfies(role: DashboardRole | undefined, minimum: DashboardRole): boolean {
  return role !== undefined && ROLE_RANK[role] >= ROLE_RANK[minimum]
}

/** True when a confirmation made at `checkedAt` (unix seconds) has lapsed. */
export function roleRecheckDue(checkedAt: number | undefined, nowSeconds: number = Math.floor(Date.now() / 1000)): boolean {
  return checkedAt === undefined || nowSeconds - checkedAt >= ROLE_RECHECK_SECONDS
}

/**
 * Reads a relay `whoami` envelope, admitting only a role the dashboard
 * knows, held by the key the caller expected.
 *
 * The pubkey comparison binds the relay-bound signature to the one the
 * dashboard verified itself: without it, a `whoami` signed by an
 * administrator could be paired with a login challenge signed by anyone.
 */
export function roleFromWhoami(envelope: unknown, expectedPubkey: string): DashboardRole | null {
  const result = (envelope as { result?: { pubkey?: unknown, role?: unknown } })?.result
  if (!result || typeof result !== 'object') {
    return null
  }
  if (result.pubkey !== expectedPubkey) {
    return null
  }
  return isDashboardRole(result.role) ? result.role : null
}

/**
 * True when `body` is exactly a `whoami` call. The login and re-check
 * routes forward a body to the relay before any session exists, and must
 * not become a way to send it anything else.
 */
export function isWhoamiBody(body: string): boolean {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return false
  }
  const call = parsed as { method?: unknown, params?: unknown }
  return call?.method === 'whoami' && (call.params === undefined || (Array.isArray(call.params) && call.params.length === 0))
}

/**
 * The pubkey that signed a `Nostr <base64>` Authorization header, or null.
 *
 * Unverified on purpose: the relay verifies the signature. This is used only
 * to ask whether a relay answer is about the session's own key — a forged
 * header can at most end its sender's own session.
 */
export function signerPubkeyOf(header: string | undefined): string | null {
  const prefix = 'Nostr '
  if (!header || !header.startsWith(prefix) || header.length > 16 * 1024) {
    return null
  }
  try {
    const json = typeof atob === 'function'
      ? atob(header.slice(prefix.length))
      : Buffer.from(header.slice(prefix.length), 'base64').toString('utf8')
    const pubkey = (JSON.parse(json) as { pubkey?: unknown })?.pubkey
    return typeof pubkey === 'string' && /^[0-9a-f]{64}$/.test(pubkey) ? pubkey : null
  } catch {
    return null
  }
}

/**
 * What a relay answer to a signed request says about the signer's role.
 *
 * - `confirmed`: the relay accepted it, so the key still holds a role.
 * - `revoked`: a 401 with no public reason. The relay explains every
 *   verification failure (stale signature, wrong path) and stays silent only
 *   about identity, so this means the key is neither owner nor admin now.
 * - `unknown`: anything else — a 403 (known key, role too low), a
 *   verification failure, an outage.
 */
export type RoleEvidence = 'confirmed' | 'revoked' | 'unknown'

export function roleEvidenceFrom(status: number, reason: unknown): RoleEvidence {
  if (status >= 200 && status < 300) {
    return 'confirmed'
  }
  if (status === 401 && (typeof reason !== 'string' || reason === '')) {
    return 'revoked'
  }
  return 'unknown'
}
