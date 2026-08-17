/**
 * Redirects unauthenticated navigation to the login page.
 *
 * This is a user-experience guard, not a security boundary: it runs in the
 * Nuxt app, where anything it decides can be bypassed by calling the API
 * directly. Every server route that returns relay data enforces the session
 * itself via requireAdminSession.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { ensureLoaded } = useAdminSession()
  const session = await ensureLoaded()

  if (to.path === '/login') {
    return session.authenticated ? navigateTo('/') : undefined
  }

  if (!session.authenticated) {
    return navigateTo('/login')
  }
})
