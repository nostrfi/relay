// https://nuxt.com/docs/api/configuration/nuxt-config

// Where the dashboard is mounted behind the reverse proxy. One constant
// because two places need it: app.baseURL, and the redirect targets below —
// a route rule matches the path with the base already stripped, but answers
// with its Location verbatim, so those targets have to carry it.
const baseURL = '/admin'

export default defineNuxtConfig({
  modules: ['@nuxt/eslint', '@nuxt/ui'],

  devtools: {
    enabled: true
  },

  app: {
    baseURL
  },

  css: ['~/assets/css/main.css'],

  runtimeConfig: {
    // Server-only: where the Go relay's HTTP API lives. Never exposed to the
    // client bundle — the browser only ever talks to this Nuxt server, which
    // proxies relay calls through server/api/* routes.
    relayApiBase: process.env.NUXT_RELAY_API_BASE || 'http://localhost:8080',

    // Server-only: where the relay serves /metrics, which is a different
    // listener from the one above and deliberately not reachable from the
    // public internet (nostrfi/workspace#53). Separate from relayApiBase
    // because the two are different addresses, and the default matches the
    // relay's own default so `pnpm dev` against a local relay needs no
    // configuration.
    relayMetricsBase: process.env.NUXT_RELAY_METRICS_BASE || 'http://localhost:2112',

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

  // Unovis ships untranspiled ESM that Nitro will not consume as-is.
  build: {
    transpile: ['@unovis/vue', '@unovis/ts']
  },

  // The private pages moved under /dashboard when they gained the shared
  // dashboard shell (nostrfi/workspace#47). Bookmarks of the old paths still
  // land rather than 404.
  routeRules: {
    '/moderation': { redirect: `${baseURL}/dashboard/moderation` },
    '/configuration': { redirect: `${baseURL}/dashboard/configuration` }
  },

  compatibilityDate: '2026-08-17',

  vite: {
    optimizeDeps: {
      // @unovis/ts imports striptags — a CommonJS package with no ESM build —
      // as an ES default import. Vite's dev server serves dependencies
      // unbundled, so the browser gets `module does not provide an export
      // named 'default'` and the chart module never loads: the page renders
      // server-side and then breaks on hydration, which is a failure only a
      // browser sees (nostrfi/workspace#52). Pre-bundling converts it to ESM.
      // The nested form, because pnpm's strict layout does not hoist
      // striptags to somewhere a bare specifier could resolve from here.
      include: ['@unovis/vue', '@unovis/ts', '@unovis/ts > striptags']
    }
  },

  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    }
  }
})
