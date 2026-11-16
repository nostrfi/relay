import { randomUUID } from 'node:crypto'
import type { H3Event } from 'h3'
import type { DashboardRole } from '~~/shared/types/session'
import { isDashboardRole, roleRecheckDue, roleSatisfies } from '~~/shared/utils/session-role'

/**
 * Sealed-cookie session for the admin dashboard, via h3's built-in
 * useSession — no session store and no extra dependency. The cookie holds
 * the authenticated pubkey and the role the relay last confirmed for it; it
 * is not a bearer credential for the relay, which continues to demand a
 * signature per privileged action.
 */

const SESSION_NAME = 'nf-admin-session'

/** Sessions last one working day, then the operator signs again. */
const SESSION_MAX_AGE_SECONDS = 8 * 60 * 60

/**
 * iron-webcrypto (which h3 seals cookies with) requires at least 32
 * characters of key material.
 */
const MIN_PASSWORD_LENGTH = 32

export interface AdminSessionData {
  /** Issued fresh at each sign-in; what logout revokes (see session-revocation.ts). */
  sid?: string
  /** The process that issued the session; a restart ends it. */
  boot?: string
  pubkey?: string
  /** What the relay's `whoami` answered at sign-in or at the last re-check. */
  role?: DashboardRole
  loggedInAt?: number
  /** Unix seconds when the relay last confirmed the role. */
  roleCheckedAt?: number
}

/** A session that can be acted on: signed in, with a role the relay named. */
export interface ActiveAdminSession {
  pubkey: string
  role: DashboardRole
  roleCheckedAt?: number
}

/** One per process: see server/utils/session-revocation.ts. */
const revocations = createSessionRevocations()

/** Stops honouring a session's cookie, wherever copies of it went. */
function revokeSession(data: AdminSessionData): void {
  if (data.sid && data.loggedInAt) {
    // outlasts every copy h3 would still unseal.
    revocations.revoke(data.sid, revocationExpiryMs(data.loggedInAt, SESSION_MAX_AGE_SECONDS))
  }
}

function sessionConfig(event: H3Event) {
  const config = useRuntimeConfig(event)
  const password = config.sessionPassword

  // Fail closed. A dashboard that seals sessions with a default secret is
  // worse than one that refuses to start: anyone who knows the default can
  // forge a session cookie.
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    throw createError({
      statusCode: 500,
      statusMessage: `NUXT_SESSION_PASSWORD is unset or shorter than ${MIN_PASSWORD_LENGTH} characters`
    })
  }

  return {
    name: SESSION_NAME,
    password,
    maxAge: SESSION_MAX_AGE_SECONDS,
    cookie: {
      httpOnly: true,
      sameSite: 'lax' as const,
      // The dashboard is only reachable through the TLS-terminating Caddy
      // overlay (see Caddyfile), and browsers treat localhost as a secure
      // context, so this holds for local development too.
      secure: true,
      path: config.app.baseURL
    }
  }
}

export async function getAdminSession(event: H3Event): Promise<AdminSessionData> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  return session.data
}

/**
 * The session as something to act on, or null.
 *
 * A cookie sealed before sessions carried a role (dashboards before
 * nostrfi/relay#56) has a pubkey but no role. It is treated as signed out:
 * the relay never said what that key may do, and one more sign-in costs
 * less than guessing. So is one that was revoked or issued before a
 * restart, or that carries no sid (see session-revocation.ts).
 */
export async function getActiveAdminSession(event: H3Event): Promise<ActiveAdminSession | null> {
  const data = await getAdminSession(event)
  if (!data.pubkey || !isDashboardRole(data.role) || !revocations.isLive(data)) {
    return null
  }
  return { pubkey: data.pubkey, role: data.role, roleCheckedAt: data.roleCheckedAt }
}

export interface RequireAdminSessionOptions {
  /** The least role the route needs; any signed-in role when absent. */
  minimum?: DashboardRole
  /**
   * Refuse once the role confirmation has lapsed. For routes the relay does
   * not authorize itself, where the session is the only check there is.
   */
  freshRole?: boolean
}

/**
 * Guard for every server route that returns relay data or proxies an action.
 * Route middleware in the Nuxt app only redirects the browser; it is not a
 * security boundary, so protected handlers call this themselves.
 */
export async function requireAdminSession(event: H3Event, options: RequireAdminSessionOptions = {}): Promise<ActiveAdminSession> {
  const session = await getActiveAdminSession(event)
  if (!session) {
    throw createError({ statusCode: 401, statusMessage: 'Not authenticated' })
  }
  if (options.minimum && !roleSatisfies(session.role, options.minimum)) {
    throw createError({ statusCode: 403, statusMessage: `${options.minimum === 'owner' ? 'Owner' : 'Administrator'} only` })
  }
  if (options.freshRole && roleRecheckDue(session.roleCheckedAt)) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Role re-check required',
      data: { roleRecheckRequired: true }
    })
  }
  return session
}

export async function startAdminSession(event: H3Event, pubkey: string, role: DashboardRole): Promise<void> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  // Signing in over a session ends it: otherwise a request still in flight
  // for it could set its cookie again over this one.
  revokeSession(session.data)
  const now = Math.floor(Date.now() / 1000)
  await session.update({ sid: randomUUID(), boot: revocations.bootId, pubkey, role, loggedInAt: now, roleCheckedAt: now })
}

/**
 * Records that the relay has just confirmed the session's role.
 *
 * Returns false, writing nothing, when there is no session to confirm — in
 * particular one logged out while the relay was being asked.
 */
export async function confirmAdminRole(event: H3Event, role?: DashboardRole): Promise<boolean> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  if (!session.data.pubkey || !revocations.isLive(session.data)) {
    return false
  }
  await session.update({
    ...(role ? { role } : {}),
    roleCheckedAt: Math.floor(Date.now() / 1000)
  })
  return true
}

export async function endAdminSession(event: H3Event): Promise<void> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  revokeSession(session.data)
  await session.clear()
}
