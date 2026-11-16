/**
 * The dashboard session is an identity assertion, not a capability: it
 * records which pubkey proved ownership of a key at login, and the role the
 * relay reported for it, and gates the UI. Privileged relay actions still
 * carry their own per-request signature — see CODINGSTANDARDS.md,
 * "Authentication and sessions".
 */

/**
 * The roles that may open a dashboard session, as the relay's NIP-86
 * `whoami` names them. The relay is the only authority on which one a key
 * holds (nostrfi/relay#55, #56).
 */
export type DashboardRole = 'owner' | 'admin'

export interface SessionState {
  authenticated: boolean
  /** Hex pubkey of the signed-in operator; absent when not authenticated. */
  pubkey?: string
  /** The role the relay last confirmed for that pubkey. */
  role?: DashboardRole
  /**
   * True once the role has gone unconfirmed for longer than the re-check
   * interval. The browser then signs one `whoami`, so the route the relay
   * cannot protect itself (metrics) keeps working only for a key that still
   * holds a role. See shared/utils/session-role.ts.
   */
  roleRecheckDue?: boolean
}

export interface ChallengeResponse {
  challenge: string
}
