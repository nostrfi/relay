// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  modules: ['@nuxt/eslint', '@nuxt/ui'],

  devtools: {
    enabled: true
  },

  app: {
    baseURL: '/admin'
  },

  css: ['~/assets/css/main.css'],

  runtimeConfig: {
    // Server-only: where the Go relay's HTTP API lives. Never exposed to the
    // client bundle — the browser only ever talks to this Nuxt server, which
    // proxies relay calls through server/api/* routes.
    relayApiBase: process.env.NUXT_RELAY_API_BASE || 'http://localhost:8080',

    // Server-only: seals the admin session cookie. There is deliberately no
    // fallback value — server/utils/session.ts fails closed when this is
    // unset or too short, rather than sealing sessions with a known secret.
    sessionPassword: process.env.NUXT_SESSION_PASSWORD || '',

    // Server-only: the pubkey allowed to open a dashboard session. Defaults
    // to the relay's NIP-11 pubkey when unset, mirroring how the relay
    // defaults moderation.admin_pubkey to relay_info.pubkey. It must match
    // the relay's moderation.admin_pubkey: the relay, not this value, is
    // what authorizes privileged actions.
    adminPubkey: process.env.NUXT_ADMIN_PUBKEY || ''
  },

  compatibilityDate: '2026-08-17',

  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    }
  }
})
