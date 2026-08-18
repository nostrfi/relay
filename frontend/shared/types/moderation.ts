/**
 * Shapes of the relay's NIP-86 management API, mirrored from
 * backend/internal/interfaces/ws/management.go. The dashboard is a client of
 * that API — it holds no moderation state of its own.
 */

/** Every management call answers with exactly one of these fields. */
export interface Nip86Response<T = unknown> {
  result?: T
  error?: string
}

export interface Nip86Request {
  method: string
  params: unknown[]
}

/**
 * List methods return one object per entry, keyed by the category's own
 * field name, plus an optional reason. `banned_at` is deliberately not part
 * of the response — see the relay's moderationEntriesToList.
 */
export interface BannedPubkey { pubkey: string, reason?: string }
export interface BannedEvent { id: string, reason?: string }
export interface BlockedIP { ip: string, reason?: string }

export type ModerationCategory = 'pubkeys' | 'events' | 'ips'
