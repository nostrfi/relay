import type { ChallengeResponse, SessionState } from '~~/shared/types/session'
import type { EventTemplate } from 'nostr-tools/pure'
import { loginUrlFor } from '~~/shared/utils/login-url'
import { WHOAMI_REQUEST } from '~~/shared/utils/session-role'

const NIP98_AUTH_KIND = 27235

/**
 * The re-check in progress, shared across every caller: the overview and the
 * Metrics page each poll metrics, and the operator should be asked to
 * approve one signature, not two.
 */
let recheckInFlight: Promise<SessionState> | null = null

/**
 * Client-side view of the dashboard session, plus the login handshake.
 *
 * The session itself lives in an httpOnly cookie the browser cannot read;
 * this state is only what the server last told us, used to render identity
 * and to decide redirects.
 */
export function useAdminSession() {
  const { sign } = useRelayRequest()
  const state = useState<SessionState | null>('admin-session', () => null)

  /**
   * Re-reads the session from the server. Called on every navigation rather
   * than cached for the lifetime of the SPA: the cookie can expire mid-visit
   * or be cleared in another tab, and a stale cached value would leave the
   * operator navigating a signed-in UI whose every request 401s.
   */
  async function refresh(): Promise<SessionState> {
    // useRequestFetch forwards the incoming cookie header during SSR;
    // a plain $fetch would arrive at the server route unauthenticated.
    state.value = await useRequestFetch()<SessionState>('/api/session')
    return state.value
  }

  /**
   * Signs in as the relay's owner or one of its administrators.
   *
   * Two approvals, by design (D4, nostrfi/relay#56): one for the dashboard's
   * challenge, which proves the key is present, and one for the relay's
   * `whoami`, which asks the relay what that key may do. The relay is the
   * only party that knows, and it accepts nothing it did not see signed.
   */
  async function login(signer: Signer): Promise<SessionState> {
    const { challenge } = await $fetch<ChallengeResponse>('/api/session/challenge')

    const loginUrl = loginUrlFor(useRuntimeConfig().app.baseURL, window.location.origin)

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

    // The dashboard's half first: the relay's half has the tighter freshness
    // window (60 seconds), so it is signed last, closest to being sent.
    const signed = await signer.signEvent(template)
    const whoami = await sign(signer, '/', WHOAMI_REQUEST)

    const session = await $fetch<SessionState>('/api/session/login', {
      method: 'POST',
      // The exact bytes the relay's payload tag hashes; forwarded unread.
      body: whoami.body,
      headers: {
        // The login event travels in the header, matching how the relay's
        // NIP-86 API is authenticated; the whoami rides alongside it.
        'Content-Type': 'application/json',
        'Authorization': `Nostr ${btoa(JSON.stringify(signed))}`,
        'X-Relay-Authorization': whoami.authorization
      }
    })

    state.value = session
    return session
  }

  /**
   * Re-confirms the role with one signed `whoami`, when the server reports
   * the last confirmation has lapsed. Only the browser can sign, so this is
   * how a view that makes no signed relay call re-checks the role (D5).
   *
   * One re-check at a time (see recheckInFlight).
   */
  function recheck(): Promise<SessionState> {
    recheckInFlight ??= (async () => {
      try {
        const { authorization, body } = await withSigner(state.value?.pubkey, signer => sign(signer, '/', WHOAMI_REQUEST))
        state.value = await $fetch<SessionState>('/api/session/recheck', {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/json', 'Authorization': authorization }
        })
        return state.value
      } catch (cause) {
        await signOutIfSessionEnded(cause)
        throw cause
      } finally {
        recheckInFlight = null
      }
    })()
    return recheckInFlight
  }

  /**
   * Leaves the signed-in UI when the server reports the relay no longer
   * recognises this key — an administrator revoked while signed in. The
   * server has already cleared the session; logging out here also drops the
   * stored signer pairing and sends the browser to sign in again.
   */
  async function signOutIfSessionEnded(cause: unknown): Promise<boolean> {
    if (!sessionEndedBy(cause)) {
      return false
    }
    await logout().catch(() => {})
    await navigateTo({ path: '/', query: { signin: '1' } })
    return true
  }

  async function logout(): Promise<void> {
    await $fetch<SessionState>('/api/session/logout', { method: 'POST' })
    clearStoredBunker()
    state.value = null
  }

  return { state, refresh, login, logout, recheck, signOutIfSessionEnded }
}

/** True when a thrown fetch error carries the server's sessionEnded flag. */
function sessionEndedBy(cause: unknown): boolean {
  // $fetch puts the whole error body at `data`, and createError's own
  // `data` one level further down — see refusalDiagnosticsFrom.
  const body = (cause as { data?: { data?: { sessionEnded?: unknown } } })?.data
  return body?.data?.sessionEnded === true
}
