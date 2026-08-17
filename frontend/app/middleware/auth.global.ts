/**
 * Redirects unauthenticated navigation to the login page.
 *
 * This is a user-experience guard, not a security boundary: it runs in the
 * Nuxt app, where anything it decides can be bypassed by calling the API
 * directly. Every server route that returns relay data enforces the session
 * itself via requireAdminSession.
 *
 * The session is re-read on every navigation rather than cached, so an
 * expired or externally cleared cookie sends the operator back to the login
 * page instead of leaving them in a signed-in UI whose requests all fail.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { refresh } = useAdminSession()
  const session = await refresh()

  if (to.path === '/login') {
    return session.authenticated ? navigateTo('/') : undefined
  }

  if (!session.authenticated) {
    return navigateTo('/login')
  }
})
