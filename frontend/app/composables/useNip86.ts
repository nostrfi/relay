import type { Nip86Response } from '~~/shared/types/moderation'
import { createRelayRefusalError, refusalDiagnosticsFrom } from '~~/shared/utils/relay-refusal'

/**
 * Signs and sends one NIP-86 management call through the dashboard's
 * server/api/moderation/rpc proxy. Shared by useModeration and
 * useAdministrators so both handle a refusal and an ended session alike.
 *
 * The relay's envelope comes back unchanged, so a method-level `error`
 * reaches the UI as the relay worded it.
 */
export function useNip86() {
  const { sign } = useRelayRequest()
  const { state, signOutIfSessionEnded } = useAdminSession()

  async function call<T>(method: string, params: unknown[]): Promise<Nip86Response<T>> {
    // Signing waits its turn — the page loads three lists at once and a
    // signer approves one thing at a time. The request itself is sent
    // outside that turn, so the three calls still overlap on the wire.
    // The relay serves NIP-86 from its root, so that is the path signed
    // into the u tag — not the dashboard route this request is sent to.
    const { authorization, body, signingMs, pubkey, signedPath }
      = await withSigner(state.value?.pubkey, signer => sign(signer, '/', { method, params }))

    try {
      return await $fetch<Nip86Response<T>>('/api/moderation/rpc', {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authorization
        }
      })
    } catch (cause) {
      // The relay no longer recognises this key (a revoked administrator):
      // the server has ended the session, so leave the signed-in UI.
      if (await signOutIfSessionEnded(cause, pubkey)) {
        throw cause
      }
      if ((cause as { statusCode?: number })?.statusCode !== 401) {
        throw cause
      }
      // A refused operator check, which the relay will not explain. Method
      // errors are unaffected: those arrive as a 200 error envelope and
      // still reach the page verbatim.
      throw createRelayRefusalError({
        signingMs,
        signedInPubkey: state.value?.pubkey,
        signingPubkey: pubkey,
        signedPath,
        ...refusalDiagnosticsFrom(cause)
      })
    }
  }

  return { call }
}
