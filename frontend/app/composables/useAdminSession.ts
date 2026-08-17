import type { ChallengeResponse, SessionState } from '~~/shared/types/session'
import type { EventTemplate } from 'nostr-tools/pure'

const NIP98_AUTH_KIND = 27235

/**
 * Client-side view of the dashboard session, plus the login handshake.
 *
 * The session itself lives in an httpOnly cookie the browser cannot read;
 * this state is only what the server last told us, used to render identity
 * and to decide redirects.
 */
export function useAdminSession() {
  const state = useState<SessionState | null>('admin-session', () => null)

  /** Fetches the session once per navigation unless forced. */
  async function ensureLoaded(force = false): Promise<SessionState> {
    if (state.value && !force) {
      return state.value
    }
    // useRequestFetch forwards the incoming cookie header during SSR;
    // a plain $fetch would arrive at the server route unauthenticated.
    state.value = await useRequestFetch()<SessionState>('/api/session')
    return state.value
  }

  async function login(signer: Signer): Promise<SessionState> {
    const { challenge } = await $fetch<ChallengeResponse>('/api/session/challenge')

    const loginUrl = new URL(useRuntimeConfig().app.baseURL + 'api/session/login', window.location.origin).toString()

    const template: EventTemplate = {
      kind: NIP98_AUTH_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', loginUrl],
        ['method', 'POST'],
        ['challenge', challenge]
      ],
      content: ''
    }

    const signed = await signer.signEvent(template)

    const session = await $fetch<SessionState>('/api/session/login', {
      method: 'POST',
      headers: {
        // The event travels in the header, matching how the relay's NIP-86
        // API is authenticated; the request body stays empty.
        Authorization: `Nostr ${btoa(JSON.stringify(signed))}`
      }
    })

    state.value = session
    return session
  }

  async function logout(): Promise<void> {
    await $fetch<SessionState>('/api/session/logout', { method: 'POST' })
    clearStoredBunker()
    state.value = null
  }

  return { state, ensureLoaded, login, logout }
}
