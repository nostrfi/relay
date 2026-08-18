# CODINGSTANDARDS.md

Coding standards for this repository. Referenced by `AGENTS.md` and `.junie/guidelines.md`.

The sections below through "Security Guardrails" cover the Go backend (`backend/`). See
"Frontend Conventions (TypeScript / Nuxt)" at the end of this document for the Nuxt admin
dashboard (`frontend/`).

## Coding Conventions (Go 1.25)

Agents MUST use modern Go idioms. Non-exhaustive checklist:

- Use `any`, never `interface{}`.
- Use `errors.Is` / `errors.As` / `errors.Join`, never `err == target`.
- Use `for i := range n` instead of `for i := 0; i < n; i++`.
- Use `slices.*` and `maps.*` (`Contains`, `IndexFunc`, `Clone`, `Copy`, `Sorted`, ...) instead of manual loops.
- Use `min` / `max` / `cmp.Or` / `clear(m)` builtins.
- Use `time.Since` / `time.Until`.
- Use `t.Context()` in tests, `b.Loop()` in benchmarks.
- Use `omitzero` (not `omitempty`) in JSON tags for zero-able types.
- Use `strings.CutPrefix` / `CutSuffix`, `bytes.Cut`, `bytes.Clone`.

Style rules:

- Match the surrounding file's style (indentation, naming, import grouping, comment density).
- Do not add comments where the surrounding code has none, unless explicitly requested.
- Package and file names: lowercase, no underscores, consistent with existing packages under `internal/{domain,application,infrastructure,interfaces}/...`.

## Architectural Rules

1. **Dependency injection via constructors.** No globals, no singletons. Services take their dependencies (repository, logger, config) as explicit parameters in `NewXxx(...)`.
2. **Interfaces at the domain boundary.** Repository interfaces (`event.Repository`, `moderation.Repository`) are defined in `internal/domain/...`, implemented by `internal/infrastructure/duckdb`, and depended on by `internal/application`. External collaborators are otherwise defined as interfaces at the consumer side to keep code testable.
3. **Context propagation.** Every function that performs I/O (DB, network, WebSocket send) must accept `ctx context.Context` as its first argument and forward it downstream. Set timeouts where operations can hang.
4. **Centralized errors.** Return `pkg/errors.AppError` (or wrap with `fmt.Errorf("...: %w", err)`) instead of raw strings. Do not leak internal errors to Nostr clients — map them through the `interfaces/ws` layer.
5. **Domain invariants live in the domain layer.** An event's signature is verified once, in `domain/event.NewEvent`, not re-checked ad hoc at each transport call site — construct a domain `Event` there instead of calling `nostr.Event.CheckSignature` directly in `interfaces/ws`.
6. **Structured logging via `slog`.** Use the logger configured in `pkg/logger`. Include contextual fields (`event_id`, `sub_id`, `pubkey`, `nip`) — never log secrets, full private events, or auth tokens.
7. **Configuration via viper.** New settings go into `config.yaml` and the corresponding `Config` struct with `mapstructure` tags. Provide sensible defaults. Never hardcode secrets.
8. **Database access.** Always use context-aware calls (`QueryContext`, `ExecContext`) and parameterized queries. No string concatenation into SQL. Manage connection pool settings in one place.
9. **Graceful shutdown.** The `main` entrypoint must handle `SIGINT`/`SIGTERM`, drain active WebSocket connections, and close the DB with a bounded timeout.

## Testing Rules

- Add or update tests for every behavior change. For bug fixes, add a failing reproducer first, then fix.
- Prefer table-driven tests. Use `testify/assert` and `testify/require` consistent with existing tests.
- Never disable, skip, weaken, or delete tests to make a build pass. If a test is genuinely obsolete, explain why in the PR/commit message.
- All added/updated tests must be green before submitting.

## Security Guardrails

- Validate and sanitize every field coming from the wire (event kind, tags, signatures, filter shape and size).
- Enforce signature verification for events before persisting.
- Rate-limit / bound message sizes and subscription counts per connection.
- Never log private keys, DMs (NIP-17 payloads), or auth challenges/responses in cleartext.
- Do not add authentication endpoints that store passwords. Nostr uses pubkey-based auth (NIP-42).

## Frontend Conventions (TypeScript / Nuxt)

Applies to `frontend/`, the Nuxt admin dashboard. Stack: Nuxt 4, `@nuxt/ui`, TypeScript, ESLint
(via `@nuxt/eslint`), pnpm — the same stack the Nostrfi marketing site uses, so conventions below
follow that precedent where one already exists.

Conventions:

- TypeScript throughout; no `any` escape hatches without a comment explaining why a stricter type
  isn't available.
- Use `<script setup lang="ts">` single-file components. Prefer the Composition API; no Options
  API components.
- Use `@nuxt/ui` components (`UCard`, `UBadge`, `UButton`, etc.) instead of hand-rolled
  equivalents. Only write bespoke markup/CSS for layout the component library doesn't cover.
- Server-only concerns (calling the relay's HTTP API, reading `runtimeConfig` values that aren't
  under `public`) belong in `server/api/*` Nitro routes, never fetched directly from
  client-reachable code — see `server/api/relay-info.get.ts` for the pattern. This keeps
  internal relay addresses (e.g. the Docker Compose service hostname) out of the client bundle.
- Types shared between `app/` and `server/` go in `shared/types/`, mirroring the Go backend's JSON
  shapes where the frontend consumes them (see `shared/types/relay-info.ts` for an example: it
  mirrors `backend/internal/interfaces/ws/config.go`'s `RelayInfo`/`RelayLimitation`).
- Match ESLint's `@nuxt/eslint` stylistic config already set in `nuxt.config.ts` (no trailing
  commas, 1tbs brace style) — do not hand-format against it.

Styling and brand:

The dashboard implements the Nostrfi **Sovereign Signal** brand system. Nothing in ESLint or CI
checks colour, so these rules are the only thing preventing drift — treat them as review criteria.

- **Signal mode only.** The dashboard is a configuration, moderation, and trust surface, so it
  never takes the Sovereign hero treatment: no glow, no oversized display type, no decorative
  motion. `app/layouts/default.vue` sets `data-nf-mode="signal"` on its root; keep it there.
- **`app/assets/css/brand.css` is a pinned copy of the canonical workspace tokens**, not a file to
  edit. Change it only by re-copying from the workspace (`60-marketing/brand/tokens/brand.css`) and
  updating the provenance header with the new version and date. Never alter a token value locally.
- **No literal colour values in components or scoped styles.** Use the `--nf-*` brand tokens, or
  the `--ui-*` aliases mapped from them in `app/assets/css/main.css`, which is where every mapping
  lives.
- **Use approved foreground/background pairs only** (contrast table in the workspace
  `brand-system.md`). `#f7931a` on white is explicitly not an approved text pair.
- **Colour hierarchy is roughly 65 / 25 / 10** — neutral surface, violet identity, at most 10%
  orange. Orange answers "what matters now?"; it is never the colour of a destructive action, which
  uses `--ui-error`. Never signal state by colour alone: pair it with a label or icon.
- **Typography roles:** Space Grotesk (`font-display`) for headings, Inter (`font-sans`) for body
  and UI, IBM Plex Mono (`font-mono`) for event IDs, pubkeys, relay URLs, and code. Add
  `nf-tabular` to metrics, counts, and timestamps so columns align. Fonts are self-hosted and
  version-pinned; do not add a webfont CDN link.
- **Separate with borders and tonal shift before shadows.** `--nf-shadow-marketing` is for
  marketing surfaces and has no place here.
- **Spacing and radius come from tokens** (`--nf-space-*`, `--nf-radius-*`), not ad-hoc pixels.
- Keep the keyboard focus ring intact — the global `*:focus-visible` rule in `main.css` is the
  brand treatment (3px violet-500, offset) and applies in both light and dark.
- Dark mode is a **calm dark Signal** variant, not Sovereign. New dark styling belongs in the
  `.dark` token block in `main.css`, not as per-component overrides.

Authentication and sessions:

- **The session is an identity assertion, not a capability.** It records which pubkey signed in and
  gates the UI. It is not a credential the relay accepts — every privileged relay operation carries
  its own per-request NIP-98 signature, checked by the relay against `moderation.admin_pubkey`. Do
  not add a server-issued token that stands in for a signature.
- **Route middleware is not a security boundary.** `app/middleware/auth.global.ts` only redirects
  the browser. Every `server/api/*` route that returns operational state or proxies an action must
  call `requireAdminSession(event)` itself.
- **Pages are private by default; publish one deliberately.** The global middleware guards every
  route unless the page sets `definePageMeta({ public: true })`. Only the landing page does. Adding
  a feature page therefore protects it automatically — do not invert this, because forgetting the
  opt-in on a default-public scheme fails open.
- **Public means the relay already serves it anonymously.** `/api/relay-info` is unguarded only
  because the relay hands that same NIP-11 document to any anonymous caller; a guard there would
  protect nothing while making the dashboard's public face a login wall
  (nostrfi/workspace#46). Anything else needs a session.
- **Sign-in lives in one place**, `app/components/SignInModal.vue`, opened from the header or by
  `?signin=1`. Do not add a second sign-in surface — two would drift.
- **Sign privileged relay calls client-side**, then forward the signed event verbatim. The NIP-98
  `u` tag must name the URL *the relay* observes — `/` with no query, since the relay serves NIP-86
  from the same URI as the WebSocket endpoint — not the dashboard path the browser called.
- **Verify the observed path with `getRequestURL(event).pathname`, never `event.path`**, when
  checking a `u` tag against a dashboard endpoint: Nitro strips `app.baseURL` (`/admin`) for route
  matching, but the browser signs the public path.
- **Never log an auth event, session cookie, challenge, or bunker key.** Log the resulting pubkey
  and the outcome, matching the backend's logging guardrail.
- **Fail closed on missing secrets.** `NUXT_SESSION_PASSWORD` has no fallback value by design.
- Obtain signatures through `useSigner`, never by calling `window.nostr` or a bunker directly, so
  both signer types keep working everywhere.

Testing:

- [Vitest](https://vitest.dev) runs the server-side unit tests in `test/` (`pnpm test`, also a CI
  step). Logic worth testing lives in `server/utils/` — challenge lifecycle, NIP-98 verification,
  rate limiting — rather than in route handlers, so it can be tested without a running server.
- Never disable, skip, weaken, or delete a test to make a build pass, matching the backend rule
  above.

Security:

- Never expose secrets, internal service hostnames, or admin credentials to the client bundle —
  keep them in server-only `runtimeConfig` keys (not `runtimeConfig.public`) and route access
  through `server/api/*`.
- The dashboard is an administrative surface: every `server/api/*` route that reads or mutates
  relay state must go through the login/session check landing in nostrfi/workspace#35 once that's
  in place — nothing here yet ships an unauthenticated route beyond the read-only relay-info proxy.
