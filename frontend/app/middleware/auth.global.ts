/**
 * Guards navigation, defaulting to private.
 *
 * A page opts out with `definePageMeta({ public: true })` — only the landing
 * page does. Defaulting the other way would mean every future feature page
 * had to remember a guard, and forgetting one would fail open.
 *
 * This is a user-experience guard, not a security boundary: it runs in the
 * Nuxt app, where anything it decides can be bypassed by calling the API
 * directly. Every server route that returns operational state or proxies an
 * action enforces the session itself via requireAdminSession.
 *
 * The session is re-read on every navigation rather than cached, so an
 * expired or externally cleared cookie is noticed immediately instead of
 * leaving the operator in a signed-in UI whose requests all fail.
 */
export default defineNuxtRouteMiddleware(async (to) => {
  const { refresh } = useAdminSession()
  const session = await refresh()

  if (to.meta.public) {
    return
  }

  if (!session.authenticated) {
    // Back to the public page with the sign-in modal open, rather than to a
    // second sign-in surface that would drift from the modal.
    return navigateTo({ path: '/', query: { signin: '1' } })
  }
})
