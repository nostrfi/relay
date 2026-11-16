/**
 * NUXT_ADMIN_PUBKEY named the one key allowed to sign in. Since
 * nostrfi/relay#56 the relay says who may — its owner and the
 * administrators the owner granted — and the variable is ignored. Saying so
 * once at startup beats a deployment that silently relies on it.
 */
export default defineNitroPlugin(() => {
  if (process.env.NUXT_ADMIN_PUBKEY) {
    console.warn(
      'NUXT_ADMIN_PUBKEY is set but no longer used: dashboard sign-in asks the relay for the signer\'s role. '
      + 'The owner is moderation.admin_pubkey in the relay\'s config.yaml. Remove the variable.'
    )
  }
})
