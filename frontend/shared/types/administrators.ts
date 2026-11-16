/**
 * Shapes of the relay's role methods, mirrored from dispatchRoleMethod in
 * backend/internal/interfaces/ws/management.go (nostrfi/relay#55).
 */

/**
 * One row of `listroleassignments`. The relay lists the owner first, from
 * configuration, with no grant fields; every administrator after it carries
 * who granted it and when.
 */
export interface RoleAssignment {
  pubkey: string
  role: 'owner' | 'admin'
  label?: string
  /** Hex pubkey of the owner who made the grant. */
  granted_by?: string
  /** Unix seconds. */
  granted_at?: number
}
