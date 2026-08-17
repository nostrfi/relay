import { joinURL } from 'ufo'

/**
 * The absolute URL the browser signs into a NIP-98 `u` tag when logging in.
 *
 * Extracted and tested because getting it wrong fails in exactly one place —
 * the server's path comparison — and only in a real browser: plain string
 * concatenation against `app.baseURL` ('/admin') silently produces
 * '/adminapi/session/login' and every login is refused with 401.
 */
export function loginUrlFor(baseURL: string, origin: string): string {
  return new URL(joinURL(baseURL, 'api/session/login'), origin).toString()
}
