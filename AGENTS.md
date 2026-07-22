# AGENTS.md

Guidance for AI coding agents (Junie, Claude, Codex, etc.) working in this repository.

## Project Overview

This is a **Nostr Relay** implementation written in **Go 1.24**. It speaks the Nostr WebSocket protocol and implements a range of NIPs (NIP-01, 02, 09, 11, 17, 22, 28, 40, 42, 70, 71, 77).

Key dependencies:
- `github.com/gorilla/websocket` — WebSocket transport
- `github.com/nbd-wtf/go-nostr` — Nostr protocol primitives
- `github.com/duckdb/duckdb-go/v2` — event storage
- `github.com/spf13/viper` — configuration
- `github.com/stretchr/testify` — testing assertions

## Repository Layout

```
.
├── cmd/relay/                 # Application entry point (main.go)
├── internal/relay/            # Private application code (feature-based)
│   ├── handler/               # WebSocket + HTTP handlers (NIP dispatch)
│   ├── service/               # Business logic per NIP / feature
│   └── repository/            # Data access (DuckDB)
├── pkg/                       # Reusable public libraries
│   ├── errors/                # AppError type + typed constructors
│   └── logger/                # slog-based structured logger setup
├── tests/                     # Integration tests (relay_test.go, one TestNipXX per NIP)
├── config.yaml                # Default configuration profile
├── go.mod / go.sum
└── README.md
```

Follow the **feature/domain-based** layout already present. Do not reorganize by technical layer.

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

## Coding Conventions (Go 1.24)

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
- Package and file names: lowercase, no underscores, consistent with existing packages under `internal/relay/...`.

## Architectural Rules

1. **Dependency injection via constructors.** No globals, no singletons. Services take their dependencies (repository, logger, config) as explicit parameters in `NewXxx(...)`.
2. **Interfaces at boundaries.** Repositories and external collaborators are defined as interfaces at the consumer side to keep code testable.
3. **Context propagation.** Every function that performs I/O (DB, network, WebSocket send) must accept `ctx context.Context` as its first argument and forward it downstream. Set timeouts where operations can hang.
4. **Centralized errors.** Return `pkg/errors.AppError` (or wrap with `fmt.Errorf("...: %w", err)`) instead of raw strings. Do not leak internal errors to Nostr clients — map them through the handler layer.
5. **Structured logging via `slog`.** Use the logger configured in `pkg/logger`. Include contextual fields (`event_id`, `sub_id`, `pubkey`, `nip`) — never log secrets, full private events, or auth tokens.
6. **Configuration via viper.** New settings go into `config.yaml` and the corresponding `Config` struct with `mapstructure` tags. Provide sensible defaults. Never hardcode secrets.
7. **Database access.** Always use context-aware calls (`QueryContext`, `ExecContext`) and parameterized queries. No string concatenation into SQL. Manage connection pool settings in one place.
8. **Graceful shutdown.** The `main` entrypoint must handle `SIGINT`/`SIGTERM`, drain active WebSocket connections, and close the DB with a bounded timeout.

## Adding a New NIP

When implementing or modifying a NIP:

1. Add/extend the service under `internal/relay/service/` — pure business logic, no transport concerns.
2. Wire it into the WebSocket dispatch under `internal/relay/handler/`.
3. Persist via `internal/relay/repository/` using prepared statements.
4. Add a `TestNipXX` integration test in `tests/relay_test.go` that spins up the relay and exercises the flow end-to-end.
5. Update the **Supported NIPs** list in `README.md`.

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

## Do / Don't for Agents

Do:
- Read `.junie/guidelines.md` — it is the canonical style/architecture reference and this file is a summary of it applied to this repo.
- Make the smallest change that solves the task, and run `go build ./...` + relevant tests before finishing.
- Preserve the existing package layout under `internal/relay/{handler,service,repository}`.

Don't:
- Introduce new top-level directories unless the task explicitly requires it.
- Add heavyweight dependencies when the standard library suffices.
- Commit changes on the agent's own initiative — only commit when the user explicitly asks. When you do commit, append:
  `--trailer "Co-authored-by: Junie <junie@jetbrains.com>"`
- Modify files under `.junie/` unless the task is specifically about updating guidelines.
