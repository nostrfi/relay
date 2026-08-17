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
    relayApiBase: process.env.NUXT_RELAY_API_BASE || 'http://localhost:8080'
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
