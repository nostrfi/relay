# CODINGSTANDARDS.md

Coding standards for this repository. Referenced by `AGENTS.md` and `.junie/guidelines.md`.

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
