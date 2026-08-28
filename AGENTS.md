# AGENTS.md

Guidance for AI coding agents (Junie, Claude, Codex, etc.) working in this repository.

## Project Overview

This is the **Nostrfi Relay** monorepo: a **Nostr Relay** backend written in **Go 1.25**
(`backend/`) plus its **admin dashboard**, a **Nuxt 4** SSR app (`frontend/`). The relay speaks
the Nostr WebSocket protocol and implements a range of NIPs (NIP-01, 02, 09, 11, 17, 22, 28, 40,
42, 70, 71, 77, 86, 98). The dashboard runs as its own Node process, reverse-proxied at `/admin`
alongside the relay — see "Two-process architecture" below.

Backend key dependencies:
- `github.com/gorilla/websocket` — WebSocket transport
- `github.com/nbd-wtf/go-nostr` — Nostr protocol primitives
- `github.com/duckdb/duckdb-go/v2` — event storage
- `github.com/spf13/viper` — configuration
- `github.com/stretchr/testify` — testing assertions

Frontend key dependencies:
- `nuxt` — SSR application framework
- `@nuxt/ui` — component library
- `@nuxt/eslint` — lint config

## Repository Layout

```
.
├── backend/                           # Go relay
│   ├── cmd/relay/                      # Application entry point (main.go, backup.go)
│   ├── cmd/loadtest/                   # Manual capacity-baseline CLI (not part of go test)
│   ├── internal/
│   │   ├── domain/                     # Entities, value objects, repository interfaces
│   │   │   ├── event/                   # Event (wraps *nostr.Event), NewEvent() signature invariant, Repository interface
│   │   │   ├── moderation/               # ModerationEntry, Repository interface
│   │   │   └── subscription/             # Subscription value object
│   │   ├── application/                # Use-case orchestration (EventService, ModerationService, MaintenanceService)
│   │   ├── infrastructure/
│   │   │   └── duckdb/                  # DuckDB implementation of the domain repository interfaces
│   │   └── interfaces/
│   │       └── ws/                      # WebSocket/HTTP transport: dispatch, config, NIP-11/86/98 handling
│   ├── pkg/                            # Reusable public libraries
│   │   ├── errors/                      # AppError type + typed constructors
│   │   └── logger/                      # slog-based structured logger setup
│   ├── tests/                          # Integration tests (relay_test.go, one TestNipXX per NIP)
│   ├── .junie/guidelines.md            # Canonical Go style/architecture reference
│   ├── config.yaml                     # Default configuration profile
│   ├── Dockerfile
│   └── go.mod / go.sum
├── frontend/                          # Nuxt 4 admin dashboard (SSR)
│   ├── app/
│   │   ├── app.vue
│   │   └── pages/                      # Routes, mounted under app.baseURL: /admin
│   ├── server/api/                     # Nitro server routes — the only place allowed to call the relay's API
│   ├── shared/types/                   # Types shared between app/ and server/, mirroring backend JSON shapes
│   ├── Dockerfile
│   ├── nuxt.config.ts
│   └── package.json
├── docker-compose.yml                 # relay + dashboard services
├── docker-compose.tls.yml             # + Caddy overlay: TLS termination, /admin routing
├── Caddyfile
├── CODINGSTANDARDS.md                 # Backend + frontend coding standards
└── README.md
```

Follow the **layered DDD** structure already present in `backend/`: `domain` → `application` →
`infrastructure` / `interfaces`, dependencies pointing inward toward `domain`. Do not reorganize
this layering, and do not subdivide by NIP within it (see `backend/.junie/guidelines.md` §1)
without an explicit task requirement.

## Two-process architecture

The relay (`backend/`, port `8080`) and the dashboard (`frontend/`, port `3000`) are separate
processes — the dashboard is a Nuxt **SSR** app, not a static bundle embedded in the Go binary.
`docker-compose.tls.yml`'s Caddy overlay is the only piece that fronts both: `/admin/*` routes to
the dashboard (`handle`, not `handle_path` — Nuxt's `app.baseURL: /admin` expects the prefix to
stay on the request), everything else routes to the relay. The dashboard's `server/api/*` routes
call the relay over the internal Docker network (`NUXT_RELAY_API_BASE=http://relay:8080`); the
browser never talks to the relay directly for dashboard data.

## Build, Run, Test

Backend:

```bash
cd backend

# Build
go build ./...

# Run the relay (listens on :8080 by default)
go run ./cmd/relay

# Run all tests (integration suite lives under ./tests)
go test -v ./tests/...

# Run a single NIP test
go test -v ./tests/... -run TestNip01

# Format / vet before committing
gofmt -w .
go vet ./...
```

Frontend:

```bash
cd frontend
pnpm install

# Dev server (set NUXT_RELAY_API_BASE if the relay isn't at the default http://localhost:8080)
pnpm dev

# Lint / typecheck / production build
pnpm lint
pnpm typecheck
pnpm build
```

Both services together (relay + dashboard + Caddy, matching production topology):

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

Manual smoke tests are documented in `README.md` (`curl` for NIP-11, `wscat` for WebSocket NIPs).

## Per-connection concurrency

Each WebSocket connection runs exactly two goroutines (`interfaces/ws/handler.go`): a **read
pump** that owns `conn.ReadMessage` and rate limiting, and a single **worker** that runs
`handleMessage` in arrival order off a byte-bounded queue (`interfaces/ws/queue.go`). Keep it
that way: the one-worker shape is what guarantees message ordering and lets per-client state
(`challenge`, `authPubkey`, subscription bookkeeping) be written without extra synchronization,
and the pump must never block anywhere but `ReadMessage` — it is the only goroutine that can
observe a disconnect, so a client that overruns the queue's byte budget is disconnected rather
than waited on. The pump also never writes data frames: notices it wants sent ride the queue
for the worker to write in order (a bounded close control frame at overflow is the one
exception gorilla permits concurrently). Every connection carries a
context (`Client.ctx`) cancelled by the pump the moment the socket drops — pass it to repository
calls made on the connection's behalf so a disconnect aborts queries; the one deliberate
exception is the EVENT acceptance path (`handleEvent`'s ban check and save), which uses
`context.WithoutCancel(c.ctx)` because clients publish fire-and-forget and an event the relay
has read in full should survive its author's disconnect. Treat `context.Canceled` from these
calls as the connection ending, not an error worth logging.

## Coding Standards

Coding conventions, architectural rules, testing rules, and security guardrails — for both the
Go backend and the Nuxt frontend — live in [`CODINGSTANDARDS.md`](CODINGSTANDARDS.md). Read it
before making any code change.

## Adding a New NIP

When implementing or modifying a NIP:

1. Add/extend the relevant domain type under `backend/internal/domain/` only if the NIP introduces a new invariant; otherwise reuse `event`, `moderation`, or `subscription`.
2. Add/extend the use-case orchestration under `backend/internal/application/` — pure business logic, no transport concerns.
3. Wire it into the WebSocket dispatch under `backend/internal/interfaces/ws/`.
4. Persist via `backend/internal/infrastructure/duckdb/` using prepared statements, implementing the relevant domain repository interface.
5. Add a `TestNipXX` integration test in `backend/tests/relay_test.go` that spins up the relay and exercises the flow end-to-end.
6. Update the **Supported NIPs** list in `README.md`.

## Do / Don't for Agents

Do:
- Read `backend/.junie/guidelines.md` and [`CODINGSTANDARDS.md`](CODINGSTANDARDS.md) — together they are the canonical style/architecture/standards reference and this file is a summary of them applied to this repo.
- Make the smallest change that solves the task, and run the relevant build/test commands above before finishing (`go build`/`go test` for `backend/` changes, `pnpm lint`/`pnpm typecheck`/`pnpm build` for `frontend/` changes).
- Preserve the existing layered package structure under `backend/internal/{domain,application,infrastructure,interfaces}/`.
- Keep relay API calls in the frontend confined to `frontend/server/api/*` — never fetch the relay directly from client-reachable code (see `CODINGSTANDARDS.md`'s Frontend Conventions).

Don't:
- Introduce new top-level directories unless the task explicitly requires it.
- Add heavyweight dependencies when the standard library (backend) or the existing `@nuxt/ui`/pnpm stack (frontend) suffices.
- Commit changes on the agent's own initiative — only commit when the user explicitly asks. When you do commit, append:
  `--trailer "Co-authored-by: Junie <junie@jetbrains.com>"`
- Modify files under `backend/.junie/` unless the task is specifically about updating guidelines, or is explicitly adding/updating a cross-reference to `CODINGSTANDARDS.md`.
