# Nostr Relay Implementation

A robust and modern Nostr relay written in Go, supporting a wide range of Nostr Improvement Proposals (NIPs).

## Supported NIPs

- **NIP-01**: Basic protocol flow
- **NIP-02**: Contact List and Follows
- **NIP-09**: Event Deletion
- **NIP-11**: Relay Information Document
- **NIP-17**: Private Direct Messages
- **NIP-22**: Comments
- **NIP-28**: Public Chat
- **NIP-40**: Expiration Timestamp
- **NIP-42**: Authentication
- **NIP-70**: Protected Events
- **NIP-71**: Video Events
- **NIP-77**: Negentropy Syncing

---

## Testing NIP Implementations

The relay includes a comprehensive automated test suite and can also be tested manually using standard tools like `curl` and `wscat`.

### Automated Tests

To run the full test suite, use the Go test tool:

```bash
go test -v ./tests/...
```

Each NIP has its own dedicated test function within `tests/relay_test.go` (e.g., `TestNip01`, `TestNip77`).

### Manual Testing with Curl

#### NIP-11: Relay Information Document
The relay returns metadata when queried with the specific `Accept` header.

```bash
curl -i -H "Accept: application/nostr+json" http://localhost:8080
```

### Manual Testing with wscat

To test WebSocket-based NIPs, use `wscat` (install via `npm install -g wscat`).

#### NIP-01: Publish and Subscribe
1. Connect to the relay:
   ```bash
   wscat -c ws://localhost:8080
   ```
2. Send an event:
   ```json
   ["EVENT", {"id": "...", "pubkey": "...", "created_at": 1600000000, "kind": 1, "tags": [], "content": "Hello world", "sig": "..."}]
   ```
3. Subscribe to events:
   ```json
   ["REQ", "sub_1", {"kinds": [1], "limit": 10}]
   ```

#### NIP-40: Expiration
Events with an `expiration` tag in the past will be rejected or hidden.
```json
["EVENT", {"kind": 1, "tags": [["expiration", "1600000000"]], ...}]
```
*Note: The relay will return an `OK` message with `false` and "event already expired" if published after the timestamp.*

#### NIP-42: Authentication
Upon connection, the relay sends an `AUTH` challenge:
```json
["AUTH", "<challenge_string>"]
```
To authenticate, send an `AUTH` event (Kind 22242) containing the challenge.

#### NIP-70: Protected Events
Publish an event with the `"-"` tag. It will be rejected unless you have authenticated as the event's author (NIP-42).
```json
["EVENT", {"kind": 1, "tags": [["-"]], ...}]
```

#### NIP-77: Negentropy Syncing
Initiate a sync using the `NEG-OPEN` message:
```json
["NEG-OPEN", "sync_id", {"authors": ["<pubkey>"]}, "<hex_encoded_negentropy_msg>"]
```

#### NIP-17: Private Direct Messages
The relay protects message metadata by only serving Kind 1059 Gift Wrap events to the recipient (tagged `p`) or the sender.
NIP-42 Authentication is required to retrieve these events.
1. Connect and receive `AUTH` challenge.
2. Authenticate using Kind 22242 event.
3. Subscribe to Kind 1059 events:
   ```json
   ["REQ", "dm_sub", {"kinds": [1059], "#p": ["<your_pubkey>"]}]
   ```

---

## Configuration

The relay can be configured via `config.yaml` in the root directory. You can customize the relay name, description, supported NIPs, and server limitations.

```yaml
relay_info:
  name: "My Custom Relay"
  description: "A specialized Nostr relay."
  supported_nips: [1, 2, 9, 11, 17, 22, 28, 40, 42, 70, 71, 77]
```

### Server and storage

```yaml
server:
  listen_addr: ":8080"             # HTTP/WebSocket listener address
  shutdown_timeout_seconds: 5      # graceful-shutdown deadline

storage:
  db_path: "db/relay.db"           # shared by normal startup and the -backup/-restore flags
```

All three settings default to the values shown above when unset. `storage.db_path` is read by `-backup`/`-restore` too, not just normal startup — see "Backup and restore" below.

### Health and readiness

- **`/healthz`** always returns `200` if the process can respond at all — it does not check any dependency, so it reflects process health only.
- **`/readyz`** returns `200` if the database is reachable (a bounded 2-second ping) and `503` otherwise — use this for load-balancer/orchestrator readiness checks and container health checks (see `docker-compose.yml`).

### Metrics

`/metrics` exposes Prometheus-format metrics (`github.com/prometheus/client_golang`):

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `relay_connections_active` | Gauge | — | Current open WebSocket connections |
| `relay_messages_total` | Counter | `type` | Messages received, by protocol message type |
| `relay_rejections_total` | Counter | `reason` | Rejected messages/events, by rejection reason |
| `relay_subscriptions_active` | Gauge | — | Current active `REQ` subscriptions across all connections |
| `relay_query_duration_seconds` | Histogram | `query` (`req`/`negentropy`) | Repository query duration |
| `relay_events_stored_total` | Counter | — | Events successfully persisted |
| `relay_save_failures_total` | Counter | — | Event save failures |

The `type` and `reason` labels are bounded to the relay's known protocol message types and NIP-01 rejection prefixes — anything else is reported as `unknown` rather than the raw client-supplied string, so a client can't inflate the metrics' cardinality by sending arbitrary garbage values. No metric or label ever includes event content, pubkeys, or other high-cardinality/sensitive values.

### Resource limits

Every field under `relay_info.limitation` is enforced on the request path, not just advertised. Set a field to `0` (or omit it) to leave that dimension unenforced.

```yaml
relay_info:
  limitation:
    max_message_length: 65536      # bytes; enforced on the WebSocket read
    max_subscriptions: 100         # concurrent REQ subscriptions per connection
    max_filters: 20                # filters allowed in a single REQ
    max_limit: 500                 # a REQ's requested "limit" is clamped to this, not rejected
    max_subid_length: 64           # characters
    max_event_tags: 2000           # tags per published event
    max_content_length: 65536      # characters per published event
    min_pow_difficulty: 0          # NIP-13 leading-zero-bit requirement; 0 disables
    auth_required: false           # require NIP-42 auth before any EVENT is accepted
    payment_required: false        # must stay false: no payment mechanism is implemented,
                                    # and the relay refuses to start if this is true
    restricted_writes: false       # currently equivalent to auth_required (no allow-list exists)
    created_at_lower_limit: 94608000 # seconds; rejects events older than now minus this
    created_at_upper_limit: 900      # seconds; rejects events further in the future than this

resource_limits:                 # operational controls outside the NIP-11 spec
  max_connections: 1000          # total concurrent WebSocket connections
  messages_per_second: 20        # per-connection token-bucket rate for all messages
  events_per_second: 5           # per-connection token-bucket rate for EVENT publishes
```

Rejections use a stable, machine-readable prefix (`invalid:`, `restricted:`, `rate-limited:`, `auth-required:`, `pow:`, `error:`) and never include raw internal error text. `REQ`s rejected for filter count, subscription count, or subscription-id length receive a `CLOSED` message; `EVENT`s rejected for any reason receive `OK false <reason>`.

### Authentication and WebSocket origin policy

```yaml
auth:
  relay_url: "" # set to this relay's canonical wss:// URL to enable NIP-42 endpoint binding
  max_event_age_seconds: 600 # NIP-42 AUTH events older or further in the future than this are rejected

websocket:
  mode: "development" # "development" allows any Origin; set "production" for internet-facing deployment
  allowed_origins: [] # required (non-empty) when mode is "production"
```

- **`auth.relay_url`**: when set, a NIP-42 `AUTH` event's signed `relay` tag must match this value (a trailing slash is ignored) or authentication is rejected with `restricted:`. Left empty, only the tag's presence is checked — the historical, development-friendly behavior. This prevents a captured AUTH event from being replayed against a different relay endpoint.
- **`auth.max_event_age_seconds`**: an `AUTH` event whose `created_at` is more than this many seconds away from the relay's clock, in either direction, is rejected with `invalid:`. Defaults to `600` (10 minutes) when unset via `LoadConfig`; `0` disables the check (only relevant when constructing the handler directly, e.g. in tests).
- **`websocket.mode`**: `development` (default) preserves the original permissive behavior — every `Origin` is accepted. `production` is fail-closed: the relay refuses to start unless `websocket.allowed_origins` is non-empty, and any WebSocket upgrade with a missing, malformed, or unlisted `Origin` header is rejected with `403 Forbidden` before the connection is established.
- Authentication never logs the challenge value or the raw `AUTH` event payload — only the resulting authenticated public key.

## Database

The relay uses **DuckDB** for high-performance event storage and querying. The database file is located at `db/relay.db`.

### Schema migrations

Schema changes are applied by a versioned migration runner (`internal/relay/repository/migrations.go`) instead of ad hoc startup checks. Applied versions are recorded in a `schema_migrations` table. A migration failure aborts startup with a clear error rather than serving traffic against a partially-migrated schema; it does not mark itself applied, so a subsequent start retries it. Every migration is written to be idempotent, so a database created before this runner existed is bootstrapped safely on first start with the new binary.

### Retention and maintenance

```yaml
retention:
  purge_interval_seconds: 3600 # how often expired events (and their tags) are deleted and the database checkpointed
```

A background worker deletes events whose NIP-40 `expiration` has passed (and their `tags` rows) on this interval, then runs DuckDB's `CHECKPOINT` and `VACUUM`. Reads already exclude expired events; this is what reclaims the underlying rows instead of leaving them stored forever. Set `purge_interval_seconds: 0` to disable the worker. Each sweep is logged (`purged_events`, `duration`).

### Backup and restore

```sh
# Export the database to a directory (DuckDB's native EXPORT DATABASE, Parquet format)
go run ./cmd/relay -backup /path/to/backup-dir

# Import a backup into a fresh database and verify it
go run ./cmd/relay -restore /path/to/backup-dir
```

Both flags run the requested operation and exit — they do not start the server. `-backup` writes a `backup-manifest.json` (event and tag row counts) alongside the DuckDB export; `-restore` reads that manifest back, imports the backup, and fails loudly if the restored row counts don't match or a smoke-test query fails. `-restore` refuses to run if `db/relay.db` already exists, so it never silently merges with or overwrites a live database — move or remove the existing file first.

This tool is deliberately not scheduled or triggered automatically by the relay itself: running it on a schedule, storing backups off-host, and defining a recovery point objective around that cadence are deployment-layer responsibilities. **Recovery time objective**: restart time plus however long `-restore` takes against your data volume — measure this for your own dataset size as part of your runbook, since it scales with database size and has not been benchmarked at production scale here.
