# AGENTS.md

Guidance for AI coding agents (Junie, Claude, Codex, etc.) working in this repository.

## Project Overview

This is a **Nostr Relay** implementation written in **Go 1.25**. It speaks the Nostr WebSocket protocol and implements a range of NIPs (NIP-01, 02, 09, 11, 17, 22, 28, 40, 42, 70, 71, 77).

Key dependencies:
- `github.com/gorilla/websocket` — WebSocket transport
- `github.com/nbd-wtf/go-nostr` — Nostr protocol primitives
- `github.com/duckdb/duckdb-go/v2` — event storage
- `github.com/spf13/viper` — configuration
- `github.com/stretchr/testify` — testing assertions

## Repository Layout

```
.
├── cmd/relay/                        # Application entry point (main.go, backup.go)
├── internal/
│   ├── domain/                       # Entities, value objects, repository interfaces
│   │   ├── event/                     # Event (wraps *nostr.Event), NewEvent() signature invariant, Repository interface
│   │   ├── moderation/                 # ModerationEntry, Repository interface
│   │   └── subscription/               # Subscription value object
│   ├── application/                  # Use-case orchestration (EventService, ModerationService, MaintenanceService)
│   ├── infrastructure/
│   │   └── duckdb/                    # DuckDB implementation of the domain repository interfaces
│   └── interfaces/
│       └── ws/                        # WebSocket/HTTP transport: dispatch, config, NIP-11/86/98 handling
├── pkg/                               # Reusable public libraries
│   ├── errors/                        # AppError type + typed constructors
│   └── logger/                        # slog-based structured logger setup
├── tests/                             # Integration tests (relay_test.go, one TestNipXX per NIP)
├── config.yaml                        # Default configuration profile
├── go.mod / go.sum
└── README.md
```

Follow the **layered DDD** structure already present: `domain` → `application` → `infrastructure` / `interfaces`, dependencies pointing inward toward `domain`. Do not reorganize this layering, and do not subdivide by NIP within it (see `.junie/guidelines.md` §1) without an explicit task requirement.

## Build, Run, Test

```bash
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

Manual smoke tests are documented in `README.md` (`curl` for NIP-11, `wscat` for WebSocket NIPs).

## Coding Standards

Coding conventions, architectural rules, testing rules, and security guardrails now live in
[`CODINGSTANDARDS.md`](CODINGSTANDARDS.md). Read it before making any code change.

## Adding a New NIP

When implementing or modifying a NIP:

1. Add/extend the relevant domain type under `internal/domain/` only if the NIP introduces a new invariant; otherwise reuse `event`, `moderation`, or `subscription`.
2. Add/extend the use-case orchestration under `internal/application/` — pure business logic, no transport concerns.
3. Wire it into the WebSocket dispatch under `internal/interfaces/ws/`.
4. Persist via `internal/infrastructure/duckdb/` using prepared statements, implementing the relevant domain repository interface.
5. Add a `TestNipXX` integration test in `tests/relay_test.go` that spins up the relay and exercises the flow end-to-end.
6. Update the **Supported NIPs** list in `README.md`.

## Do / Don't for Agents

Do:
- Read `.junie/guidelines.md` and [`CODINGSTANDARDS.md`](CODINGSTANDARDS.md) — together they are the canonical style/architecture/standards reference and this file is a summary of them applied to this repo.
- Make the smallest change that solves the task, and run `go build ./...` + relevant tests before finishing.
- Preserve the existing layered package structure under `internal/{domain,application,infrastructure,interfaces}/`.

Don't:
- Introduce new top-level directories unless the task explicitly requires it.
- Add heavyweight dependencies when the standard library suffices.
- Commit changes on the agent's own initiative — only commit when the user explicitly asks. When you do commit, append:
  `--trailer "Co-authored-by: Junie <junie@jetbrains.com>"`
- Modify files under `.junie/` unless the task is specifically about updating guidelines, or is explicitly adding/updating a cross-reference to `CODINGSTANDARDS.md`.
