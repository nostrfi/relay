/**
 * The dashboard session is an identity assertion, not a capability: it
 * records which pubkey proved ownership of a key at login, and gates the UI.
 * Privileged relay actions still carry their own per-request signature — see
 * CODINGSTANDARDS.md, "Authentication and sessions".
 */
export interface SessionState {
  authenticated: boolean
  /** Hex pubkey of the signed-in operator; absent when not authenticated. */
  pubkey?: string
}

export interface ChallengeResponse {
  challenge: string
}
