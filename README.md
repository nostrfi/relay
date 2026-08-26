# Nostrfi Relay

A robust and modern Nostr relay written in Go, supporting a wide range of Nostr Improvement Proposals (NIPs), plus an admin dashboard (Nuxt 4, SSR) for operating it.

This is a two-part monorepo:

- **`backend/`** — the Go relay described below.
- **`frontend/`** — the admin dashboard, reverse-proxied at `/admin` alongside the relay. See [`AGENTS.md`](AGENTS.md) for the full repository layout and the two-process architecture.

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
- **NIP-86**: Relay Management API (ban-list subset: pubkey/event bans, IP blocks)
- **NIP-98**: HTTP Auth (used to authenticate NIP-86 management requests)

---

## Testing NIP Implementations

The relay includes a comprehensive automated test suite and can also be tested manually using standard tools like `curl` and `wscat`.

### Automated Tests

To run the full test suite, use the Go test tool from `backend/`:

```bash
cd backend
go test -v ./tests/...
```

Each NIP has its own dedicated test function within `backend/tests/relay_test.go` (e.g., `TestNip01`, `TestNip77`).

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

The relay can be configured via `backend/config.yaml`. You can customize the relay name, description, supported NIPs, and server limitations.

```yaml
relay_info:
  name: "My Custom Relay"
  description: "A specialized Nostr relay."
  supported_nips: [1, 2, 9, 11, 17, 22, 28, 40, 42, 70, 71, 77]
```

### Where the config file is looked for

`config.yaml` is searched for, in order, in:

1. the working directory (this is where the container finds it: `/app`),
2. the directory holding the relay binary,
3. `backend/`, so a binary started from the repository root finds it too.

Set **`RELAY_CONFIG_FILE`** to a path to skip the search — for a systemd unit or a packaged
install whose config lives somewhere else entirely. A file named that way but missing is a
startup error, rather than a silent fall back to defaults.

The relay logs which file it loaded (`configuration loaded`), and warns when it found none.
Take that warning seriously: a relay running on defaults has no `relay_info.pubkey`, so no
`moderation.admin_pubkey`, and it refuses every NIP-86 and configuration-API request — it says
so in a second warning at startup, and tells the caller as much in its `401`.

### Server and storage

```yaml
server:
  listen_addr: ":8080"                     # HTTP/WebSocket listener address
  metrics_listen_addr: "127.0.0.1:2112"    # separate /metrics listener — see "Metrics"
  shutdown_timeout_seconds: 5              # graceful-shutdown deadline

storage:
  db_path: "db/relay.db"                   # shared by normal startup and the -backup/-restore flags
```

All four settings default to the values shown above when unset. `metrics_listen_addr` may also be
set with the `RELAY_METRICS_LISTEN_ADDR` environment variable, which overrides the file — that is
how `docker-compose.yml` gives the container a non-loopback bind without shipping it a second
config. It must differ from `listen_addr`; the relay refuses to start if the two name the same
address, rather than leaving the two listeners to race for the port. `storage.db_path` is read by
`-backup`/`-restore` too, not just normal startup — see "Backup and restore" below.

A **relative** `db_path` is relative to the configuration file that set it, so the database sits
where the file that names it does — `backend/db/relay.db` for `backend/config.yaml`, whichever
directory the relay was started from, and `/app/db/relay.db` in the container. Give an absolute
path to put it anywhere else.

### Health and readiness

- **`/healthz`** always returns `200` if the process can respond at all — it does not check any dependency, so it reflects process health only.
- **`/readyz`** returns `200` if the database is reachable (a bounded 2-second ping) and `503` otherwise — use this for load-balancer/orchestrator readiness checks and container health checks (see `docker-compose.yml`).

### Metrics

`/metrics` exposes Prometheus-format metrics (`github.com/prometheus/client_golang`) on **its own
listener** — `server.metrics_listen_addr`, `127.0.0.1:2112` by default — and not on the public
`listen_addr`. Reaching it is therefore a statement about where the caller sits: loopback, or
whatever internal address the deployment binds. Nothing is published to the host by
`docker-compose.yml`.

The endpoint serves the default registry, so the Go runtime and process collectors come with the
relay's own series: `go_info` (the exact Go build), `go_goroutines`, `process_open_fds`,
`process_resident_memory_bytes`, `process_start_time_seconds`, and the rest. Those, together with
the relay's traffic shape and connection count, are why the endpoint is not public
(nostrfi/workspace#53) — and they are worth keeping for whoever can reach it: the dashboard's
uptime is `process_start_time_seconds`.

The relay's own metrics:

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

### Moderation (NIP-86 / NIP-98)

```yaml
moderation:
  admin_pubkey: "" # NIP-86 management API caller must sign as this pubkey (NIP-98); defaults to relay_info.pubkey when empty
  max_event_age_seconds: 60 # NIP-98 auth events older or further in the future than this are rejected
```

The relay exposes the ban-list subset of the [NIP-86 relay management API](https://github.com/nostr-protocol/nips/blob/master/86.md) — `supportedmethods`, `banpubkey`/`unbanpubkey`/`listbannedpubkeys`, `banevent`/`allowevent`/`listbannedevents`, `blockip`/`unblockip`/`listblockedips` — as `POST` requests to the same URI as the WebSocket endpoint, with `Content-Type: application/nostr+json+rpc`:

```json
{"method": "banpubkey", "params": ["<32-byte-hex-pubkey>", "spam"]}
```

Every request must carry an `Authorization: Nostr <base64>` header containing a signed [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) kind-`27235` event, with the `payload` tag set (NIP-86 requires it; generic NIP-98 only recommends it) to the hex-encoded SHA-256 of the exact request body. A request is rejected with `401` if the signature, `u`/`method`/`payload` tags, or freshness check fails, or if the signing pubkey does not match `moderation.admin_pubkey`. Any NIP-98-capable client or tool (e.g. [`nak`](https://github.com/fiatjaf/nak)) can construct this header; the relay does not provide a browser UI for it.

Parameter validation (added in nostrfi/workspace#37, so it applies to every caller, not just the
dashboard):

- `banpubkey`/`unbanpubkey` and `banevent`/`allowevent` require a 64-character **lowercase hex**
  identifier. An `npub1…`/`note1…` bech32 form, a prefix, or uppercase hex is rejected.
- `blockip`/`unblockip` require a value `net.ParseIP` or `net.ParseCIDR` accepts — an IPv4 or IPv6
  address, or a CIDR range.
- The optional reason is capped at 500 characters and may not be only whitespace.

A rejected call answers with the normal `{"error": "..."}` envelope and stores nothing. Before this,
malformed values were stored as given: a junk IP entry silently matched no connection at all, so an
operator could believe an address was blocked when it was not.

- **`banpubkey`**: rejects future `EVENT` publishes from that pubkey with `blocked:`. It does not retroactively hide events that pubkey already published — use `banevent` for a specific event.
- **`banevent`**: excludes that event ID from `REQ` results. The underlying row is not deleted, so `allowevent` reverses it; independent of NIP-09 same-author deletion.
- **`blockip`**: rejects future WebSocket upgrade attempts from that IP or CIDR with `403`. Uses the request's observed remote address, not a proxy header like `X-Forwarded-For` — behind a reverse proxy this sees the proxy's address, not the real client's.
- Every management call, successful or not, is logged (`method`, `operator_pubkey`, and outcome) — never event content, private keys, or the raw request body.

### Configuration API (operator only)

`POST /api/config` returns the relay's **effective** operational configuration — what the running
process is enforcing after code defaults are applied, not a copy of `config.yaml`. It is authorized
exactly like the NIP-86 management API: an `Authorization: Nostr <base64>` header carrying a signed
NIP-98 kind-`27235` event whose pubkey matches `moderation.admin_pubkey`. The request body is `{}`;
it exists only so the NIP-98 `payload` tag has something to hash.

```bash
# body must be exactly what the payload tag hashes
curl -X POST https://relay.example.com/api/config \
  -H 'Content-Type: application/json' \
  -H "Authorization: Nostr $(...)" \
  -d '{}'
```

The response carries seven sections — `resource_limits`, `auth`, `moderation`, `websocket`,
`retention`, `server`, `storage` — and deliberately **omits the NIP-11 identity fields**, which the
relay already publishes to anyone.

It is an explicit allow-list of fields, not a dump of the configuration struct: anything added to
the config later stays invisible here until someone exposes it on purpose, so a credential cannot be
published by accident. A test (`TestConfigSnapshotCoversEveryConfigField`) fails the build when a
new config field is neither exposed nor recorded as deliberately withheld.

Two values are worth reading carefully:

- **`resource_limits` of `0` means unlimited, not zero.** Omitting the section from `config.yaml`
  disables the connection cap and rate limiting entirely rather than applying a default — the
  limiter is only created above zero. The dashboard renders these as "Unlimited" and warns when all
  three are off.
- **`websocket.mode` of `development` accepts a WebSocket connection from any Origin.** `production`
  requires a non-empty `allowed_origins` and refuses to start without one.

Configuration is read at start, so this reflects the running process and can differ from the file on
disk if it has been edited since. There is no write endpoint: changes are a deployment concern and
take effect on restart.

### Event browse API (operator only)

`POST /api/events/query` returns stored events for the dashboard's event browser. It is authorized
exactly like the configuration and NIP-86 APIs: an `Authorization: Nostr <base64>` header carrying a
signed NIP-98 kind-`27235` event whose pubkey matches `moderation.admin_pubkey`. POST rather than
GET so the NIP-98 `payload` tag has a body to hash.

```bash
curl -X POST https://relay.example.com/api/events/query \
  -H 'Content-Type: application/json' \
  -H "Authorization: Nostr $(...)" \
  -d '{"kinds":[1],"content_contains":"relay","limit":50}'
```

Request fields, all optional:

| Field | Type | Meaning |
|---|---|---|
| `ids` | `string[]` | Event ids, or prefixes of them (NIP-01 prefix matching) |
| `authors` | `string[]` | Pubkeys, or prefixes |
| `kinds` | `number[]` | Event kinds |
| `tags` | `{ "e": ["..."] }` | Single-letter tag name to values |
| `since` / `until` | `number` | Unix seconds, inclusive |
| `content_contains` | `string` | Case-insensitive substring of the content, **minimum 3 characters** |
| `limit` | `number` | Page size; defaults to `100` |

The response is `{"events": [...], "limit": <applied>, "next_until": <unix seconds>}`. Events are
newest first, in the same shape the relay stores them, and the same exclusions apply as to any read:
expired events and events banned through NIP-86 are not returned.

Three behaviours are worth knowing:

- **`limit` is clamped, not refused.** Anything above `relay_info.limitation.max_limit` (500 in the
  shipped config) is reduced, and `limit` in the response reports what was actually applied. A
  request that names no limit gets 100 — there is no way to ask for the whole table.
- **Pagination is by cursor, not offset.** `next_until` is the oldest `created_at` in the page; send
  it back as `until` for the next one, and it is absent on the last page. Because the cursor is a
  timestamp, events sharing that second can appear on two consecutive pages, so **callers must
  de-duplicate by id** — the dashboard does. Offset paging was avoided deliberately: it re-scans
  everything it skips, so it degrades as the relay fills up.
- **`content_contains` is the one unindexed filter.** It is a case-insensitive scan (`ILIKE`),
  bounded by the rest of the filter and by `limit`, with `%` and `_` in the search text treated as
  literal characters rather than wildcards. It is the first thing that will hurt on a large
  database; narrow it with a kind, author, or time range.

### Event statistics API (operator only)

`POST /api/events/stats` counts stored events by period and by kind, for the dashboard's overview
charts. Authorized exactly like the browse and configuration APIs: a NIP-98 kind-`27235` event whose
pubkey matches `moderation.admin_pubkey`.

```bash
curl -X POST https://relay.example.com/api/events/stats \
  -H 'Content-Type: application/json' \
  -H "Authorization: Nostr $(...)" \
  -d '{"since":1786000000,"until":1786600000,"bucket":"day"}'
```

| Field | Type | Meaning |
|---|---|---|
| `since` / `until` | `number` | Unix seconds, inclusive. Defaults to the last 7 days |
| `bucket` | `hour \| day \| week \| month` | Granularity; defaults to `day` |
| `utc_offset_minutes` | `number` | Shifts period boundaries onto the operator's clock; defaults to UTC |

The response is `{"periods":[{"start":...,"count":...}], "kinds":[{"kind":...,"count":...}],
"other_kinds":..., "total":..., "stored_total":..., "bucket":..., "since":..., "until":...,
"utc_offset_minutes":...}`.

Six behaviours are worth knowing:

- **Periods group by the event's own `created_at`**, which is the author's timestamp — not when the
  relay received it. NIP-01 allows a backdated event and this relay accepts them, so a bulk import
  of old events lands in old periods. These counts describe when events say they were made;
  answering "what arrived today" would need an ingestion timestamp the schema does not record.
- **`stored_total` is absent, not zero, when the count fails.** A failure must not arrive as the
  confident statement that the relay holds nothing.

- **Only periods that hold events are returned.** A range containing a silent day has no entry for
  it, so a caller drawing a chart must fill its own gaps — otherwise three bars in a row read as
  three consecutive days when two quiet ones sit between them. The dashboard does this in
  `frontend/shared/utils/event-stats.ts`.
- **The granularity is coarsened, not refused.** A range that would produce more than 400 periods
  walks up `hour → day → week → month` until it fits, and `bucket` in the response reports what was
  applied — a year of hours comes back as days.
- **`stored_total` is every event on disk**, expired and banned included, so an empty chart can say
  "the relay holds N events, none in this range" rather than leaving an operator to guess which kind
  of empty it is.
- **Counts match what the relay would serve.** Expired events and events banned through NIP-86 are
  excluded, exactly as they are from a `REQ` or a browse query, so the charts and the event browser
  cannot disagree. Both groupings run in one transaction, so the periods and the kinds always count
  the same rows.
- **The kind breakdown is capped** at sixteen entries, with everything past it summed into
  `other_kinds`. Nothing validates the kind range on publish, so an uncapped breakdown would grow
  with whatever strangers have sent.
- **Period boundaries are UTC plus `utc_offset_minutes`, and nothing else** — never the timezone the
  relay process happens to run in. The offset is a fixed number for the whole range, so a range
  crossing a daylight-saving change is bucketed in one consistent clock rather than a mixture;
  callers should label their axes with the offset the response echoes back.

### Admin dashboard event browser

The dashboard's `/admin/dashboard/events` page is a client of the API above. Filters are built in
the browser, each query is signed with the operator's key and forwarded verbatim, and the event
detail view verifies the signature locally over the event exactly as the relay returned it, so it
reports what it checked rather than asking you to trust storage.

Because every query costs a signature, the page runs on an explicit **Run query** action and pages
100 at a time rather than filtering as you type — with a NIP-46 remote signer, each keystroke would
otherwise be an approval round trip.

### Admin dashboard moderation

The dashboard's `/admin/dashboard/moderation` page is a client of the management API above — it holds no
moderation state of its own and adds no endpoints. Each action is signed in the browser by the
operator's key (NIP-07 extension or NIP-46 bunker) and forwarded verbatim by the dashboard server,
so the relay authorizes every call exactly as it would from `nak` or curl.

Because each call carries its own signature, the page needs the operator's signer present, not just
a dashboard session. With the signer unavailable the page says so rather than showing an empty list.

### Admin dashboard metrics

The dashboard reads the relay's `/metrics` endpoint through its own server and renders it on
`/admin/dashboard/metrics`, with a summary strip on the overview. Unlike every other relay call the
dashboard makes, this one carries **no NIP-98 signature**: what stands in for one is the address.
`/metrics` is served on the relay's separate metrics listener, which the deployment does not
publish, so the dashboard's server can read it over the internal network and nobody outside can —
and the operator driving it is authenticated by their dashboard session. That is what makes a live
view possible; a signed endpoint would cost one signer prompt per poll.

The dashboard is told where that listener is with `NUXT_RELAY_METRICS_BASE` (default
`http://localhost:2112`, matching the relay's own default). `docker-compose.yml` sets it to
`http://relay:2112`. Point it at whatever `server.metrics_listen_addr` names; the relay's API base
(`NUXT_RELAY_API_BASE`) is still where `/readyz` is read from, and stays on `:8080`.

Three things to know when reading it:

- **There is no metrics store.** Rates are differences between samples the page itself has taken, so
  the window starts when the page opens and is gone when it closes. Point Prometheus at the same
  endpoint for real history.
- **Sampling pauses when the tab is hidden**, and the page says so, along with the age of the last
  sample — a poller that has stopped otherwise looks exactly like a quiet relay.
- **Counters reset when the relay restarts.** A counter going backwards is shown as `restarted`
  rather than as a rate, and the sparkline breaks rather than drawing a line through the gap.

Query-latency `p50` and `p95` are estimated from the histogram buckets by interpolation, exactly as
`histogram_quantile` does; the mean shown beside them is exact.

### Admin dashboard sign-in

`/admin` itself is public: it renders the relay's NIP-11 information, the same document the relay
serves to any anonymous caller. Everything else lives under `/admin/dashboard` — the overview, plus
`/moderation` and `/configuration` beneath it — and requires a pubkey login. The operator proves ownership of a key by signing a NIP-98 kind-`27235` event over
the login endpoint, with a browser extension (NIP-07) or a remote signer (NIP-46 bunker), and the
dashboard's Nuxt server opens a session for them.

Sign-in is a **Sign in** action in the public page's header, which opens a modal with both
options; the signed-in pages carry the identity and a **Sign out** in their sidebar instead.
Reaching a private page while signed out returns to `/admin` with that modal open.

Two environment variables configure it on the `dashboard` service:

| Variable | Required | Purpose |
|---|---|---|
| `NUXT_SESSION_PASSWORD` | yes | Seals the session cookie. At least 32 characters; generate per deployment with `openssl rand -base64 48`. The dashboard refuses to open a session when it is unset or too short rather than falling back to a known secret. |
| `NUXT_ADMIN_PUBKEY` | no | Hex pubkey allowed to sign in. Defaults to the relay's NIP-11 `pubkey`, mirroring how `moderation.admin_pubkey` defaults. Set it when `moderation.admin_pubkey` differs, and keep the two in step. |

The session is an **identity assertion, not a capability**. It records which pubkey signed in and
gates the dashboard UI; it is not a credential the relay accepts. Privileged relay operations
continue to require their own per-request NIP-98 signature checked against
`moderation.admin_pubkey`, exactly as described above — so a stolen session cookie yields dashboard
access, never the ability to mutate relay state.

The login flow itself:

1. The browser requests a one-time challenge from the dashboard.
2. It signs a kind-`27235` event tagged with `u` (the login URL), `method`, and that `challenge`.
3. It sends the event in an `Authorization: Nostr <base64>` header with an empty body — the same
   header convention the NIP-86 API uses.
4. The server verifies the signature, freshness, tags, and challenge, checks the pubkey against the
   admin pubkey, and sets an httpOnly, `Secure`, `SameSite=Lax` cookie scoped to `/admin`.

Sessions last 8 hours. Signing out clears the cookie and any stored bunker pairing, and returns to
the public page. Login and challenge requests are rate-limited per client address.

### Admin dashboard theme

The dashboard renders in light or dark. It follows the operating system's preference by default;
the sun/moon button pins a choice instead — in the public page's header, and in the sidebar footer
beside **Sign out** on the signed-in pages. The choice is stored in the browser's local storage, so
it is per browser rather than per operator, and is not part of the session.

## Database

The relay uses **DuckDB** for high-performance event storage and querying. The database file is located at `backend/db/relay.db`.

### Schema migrations

Schema changes are applied by a versioned migration runner (`backend/internal/infrastructure/duckdb/migrations.go`) instead of ad hoc startup checks. Applied versions are recorded in a `schema_migrations` table. A migration failure aborts startup with a clear error rather than serving traffic against a partially-migrated schema; it does not mark itself applied, so a subsequent start retries it. Every migration is written to be idempotent, so a database created before this runner existed is bootstrapped safely on first start with the new binary.

### Retention and maintenance

```yaml
retention:
  purge_interval_seconds: 3600 # how often expired events (and their tags) are deleted and the database checkpointed
```

A background worker deletes events whose NIP-40 `expiration` has passed (and their `tags` rows) on this interval, then runs DuckDB's `CHECKPOINT` and `VACUUM`. Reads already exclude expired events; this is what reclaims the underlying rows instead of leaving them stored forever. Set `purge_interval_seconds: 0` to disable the worker. Each sweep is logged (`purged_events`, `duration`).

### Backup and restore

```sh
# Run from backend/. Exports the database to a directory (DuckDB's native
# EXPORT DATABASE, Parquet format)
go run ./cmd/relay -backup /path/to/backup-dir

# Import a backup into a fresh database and verify it
go run ./cmd/relay -restore /path/to/backup-dir
```

Both flags run the requested operation and exit — they do not start the server. `-backup` writes a `backup-manifest.json` (event and tag row counts) alongside the DuckDB export; `-restore` reads that manifest back, imports the backup, and fails loudly if the restored row counts don't match or a smoke-test query fails. `-restore` refuses to run if `db/relay.db` already exists, so it never silently merges with or overwrites a live database — move or remove the existing file first.

This tool is deliberately not scheduled or triggered automatically by the relay itself: running it on a schedule, storing backups off-host, and defining a recovery point objective around that cadence are deployment-layer responsibilities. **Recovery time objective**: restart time plus however long `-restore` takes against your data volume — measure this for your own dataset size as part of your runbook, since it scales with database size and has not been benchmarked at production scale here.

## Deployment

The relay itself never terminates TLS — see `operating-model.md`'s application-vs-deployment boundary. `docker-compose.yml`'s `relay.image` references `ghcr.io/nostrfi/relay:${RELAY_VERSION:-latest}` and `dashboard.image` references `ghcr.io/nostrfi/relay-dashboard:${DASHBOARD_VERSION:-latest}` — the tags CI actually publishes for each (GitVersion-driven semver, `sha-<shortsha>`, and `latest`), so both TLS termination and rollback below use the real deployment artifacts rather than locally-built, disconnected image names.

The relay and the dashboard are **separate processes** (the dashboard is a Nuxt SSR app, not a static bundle baked into the relay binary) — see [`AGENTS.md`](AGENTS.md)'s "Two-process architecture" for how they're wired together.

### TLS termination

`docker-compose.tls.yml` is an overlay that adds a [Caddy](https://caddyserver.com/) reverse proxy in front of the relay and dashboard and removes the relay's own host-published port, so Caddy becomes the sole public entry point. It routes `/admin/*` to the dashboard and everything else to the relay:

```sh
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d
curl https://localhost:8443/ -H "Accept: application/nostr+json"   # relay NIP-11 document; self-signed locally, use -k or trust Caddy's local CA
curl https://localhost:8443/admin                                  # admin dashboard
```

The bundled `Caddyfile` uses `tls internal` (Caddy issues itself a locally-trusted certificate) so this works out of the box with no domain or DNS setup — exactly what's exercised above. For an internet-facing deployment: replace `localhost` in the `Caddyfile` with your real domain and delete the `tls internal` line; Caddy then obtains and renews a real Let's Encrypt certificate automatically via ACME, no other configuration changes needed. Port `8443` is used above because this was verified in a rootless-container environment that can't bind privileged host ports without extra host configuration — on a host that can, map `443:443` (and `80:80` for the ACME HTTP challenge) instead.

### Scraping metrics

`/metrics` is not on the public port and is not published to the host (see "Metrics"). A scraper
reaches it by being somewhere the listener is bound:

- **Compose.** The relay binds `:2112` inside the container (`RELAY_METRICS_LISTEN_ADDR` in
  `docker-compose.yml`) and the port is left out of `ports:`, so it is reachable from the Compose
  network and nowhere else. Attach Prometheus to that network and scrape `relay:2112`; the
  dashboard already reads it the same way. Adding `- "127.0.0.1:2112:2112"` to `ports:` exposes it
  to the host only, which is enough for a Prometheus running there — do that deliberately, and
  never bind it to `0.0.0.0`.
- **A binary on a host.** The default `127.0.0.1:2112` is already right for a node-local
  Prometheus. For a scraper elsewhere, bind the relay's metrics listener to an interface that
  scraper can reach and firewall it — the endpoint has no authentication, and its
  contents describe the host.

```sh
docker compose up -d
docker compose exec relay wget -qO- http://127.0.0.1:2112/metrics   # inside the deployment: served
curl -s localhost:8080/metrics                                      # from outside: not served
```

### Rollback

Every CI build publishes to `ghcr.io/nostrfi/relay` and `ghcr.io/nostrfi/relay-dashboard` under several tags each (see `.github/workflows/ci.yml`): a full semver (`1.2.3`), `sha-<shortsha>`, and `latest` (non-prerelease builds only). To run a specific previously-published version, or roll back to one:

```sh
RELAY_VERSION=1.2.2 docker compose pull relay
RELAY_VERSION=1.2.2 docker compose up -d relay

DASHBOARD_VERSION=1.2.2 docker compose pull dashboard
DASHBOARD_VERSION=1.2.2 docker compose up -d dashboard
```

This mechanism — swap `RELAY_VERSION`/`DASHBOARD_VERSION`, then recreate the container — is what was exercised for the relay during development (using two locally-built images standing in for two releases, since pulling the real published tags requires registry credentials not available in every environment): deploying one version, then switching to the other, confirms the running version (visible in the NIP-11 `version` field) changes correctly on each swap. The dashboard image follows the same mechanism but has no equivalent version-visible-in-response check yet.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request against `master`, with separate jobs for the backend and frontend:

Backend (`backend/`):
1. `go vet ./...`
2. **Vulnerability scan**: `go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...` — pinned to an exact version for reproducibility, not `@latest`. A finding fails the build; it is not merely reported. Since `govulncheck` also checks the standard library itself against the pinned toolchain, keeping `go.mod`'s `toolchain` directive reasonably current is part of keeping this gate green — it isn't only about this module's direct dependencies.
3. `go build`, then `go test -race ./tests/...`

Frontend (`frontend/`):
1. `pnpm lint` (ESLint)
2. `pnpm typecheck` (`nuxt typecheck`)
3. `pnpm build`

Version tagging (GitVersion), the Docker image build/push to `ghcr.io/nostrfi/relay` and `ghcr.io/nostrfi/relay-dashboard`, and GitHub Releases on tag pushes run in later jobs in the same workflow, gated on the steps above passing.
