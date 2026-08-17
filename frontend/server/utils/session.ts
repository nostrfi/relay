import type { H3Event } from 'h3'

/**
 * Sealed-cookie session for the admin dashboard, via h3's built-in
 * useSession — no session store and no extra dependency. The cookie holds
 * only the authenticated pubkey; it is not a bearer credential for the
 * relay, which continues to demand a signature per privileged action.
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
  pubkey?: string
  loggedInAt?: number
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
 * Guard for every server route that returns relay data or proxies an action.
 * Route middleware in the Nuxt app only redirects the browser; it is not a
 * security boundary, so protected handlers call this themselves.
 */
export async function requireAdminSession(event: H3Event): Promise<string> {
  const data = await getAdminSession(event)
  if (!data.pubkey) {
    throw createError({ statusCode: 401, statusMessage: 'Not authenticated' })
  }
  return data.pubkey
}

export async function startAdminSession(event: H3Event, pubkey: string): Promise<void> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  await session.update({ pubkey, loggedInAt: Math.floor(Date.now() / 1000) })
}

export async function endAdminSession(event: H3Event): Promise<void> {
  const session = await useSession<AdminSessionData>(event, sessionConfig(event))
  await session.clear()
}
