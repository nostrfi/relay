import type { RoleAssignment } from '~~/shared/types/administrators'

/**
 * The relay's role methods, owner only (D2, nostrfi/relay#57). The relay
 * answers an administrator with a 403, whatever this dashboard shows.
 *
 * `admin` is the only role id the relay grants; see README §Administrators.
 */
export function useAdministrators() {
  const { call } = useNip86()

  return {
    listRoleAssignments: () => call<RoleAssignment[]>('listroleassignments', []),
    assignAdmin: (pubkey: string, label: string) =>
      call<boolean>('assignrole', label ? [pubkey, 'admin', label] : [pubkey, 'admin']),
    unassignAdmin: (pubkey: string) => call<boolean>('unassignrole', [pubkey, 'admin'])
  }
}
