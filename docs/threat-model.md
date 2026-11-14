# Relay threat model

- **Status:** accepted
- **Date:** 2026-08-12
- **Source revision reviewed:** `9f05b3c` (current `master` at time of writing)
- **Owner:** Nostrfi, as the relay's operator
- **Review triggers:** a new NIP or event class is advertised, the
  application/deployment boundary changes, an actual abuse or capacity
  incident occurs, or any "new ticket" disposition below is closed.
- **Reviewed since acceptance:** the WebSocket origin default, under
  workspace #45 — the boundary trigger, fired by the relay gaining a browser
  surface (#28, #35). Reviewed against `nostrfi/relay#35`, tested at branch
  head `325e71b` and merged to `master` as `001d464`. The default was
  re-accepted with the dashboard and the public-reusable operating model
  considered, a startup warning added for non-loopback binds, and production
  mode changed to admit connections that send no `Origin` header. See the
  "WebSocket origins" rows and accepted residual 4.
- **Reviewed since acceptance:** the search channel, under workspace #48 —
  the "new NIP advertised" trigger, fired by NIP-50. Reviewed against
  `nostrfi/relay#34`, merged to `master` as `f6e18b8`; the outcome is
  accepted residual 8
  below and the two query-cost rows under "Subscription and filter abuse".
  The source revision in the metadata above is unchanged: this reviewed the
  search channel, not the whole document.
- **Reviewed since acceptance:** the search cost residual, under workspace
  #59 — the follow-up #48's review left open: measure the unmeasured scan
  cost, then decide. Reviewed against `nostrfi/relay#38`, merged to
  `master` as `f467467`. The cost was measured at two scales and the
  per-query work bounded by `resource_limits.search_timeout_seconds`
  (default 5s); the "Expensive queries via `search`" row moved from
  accepted residual to mitigated-per-query, and residual 8 narrowed to
  aggregate concurrency and the scan-not-index design.
  The relay gained a dashboard that reads `/metrics` (#39), which made the
  endpoint a product surface rather than an operator's private `curl` and
  fired the boundary trigger above. The disposition changed; see
  "Metadata disclosure".

> **Where this lives.** This threat model moved here from Nostrfi's internal
> workspace on 2026-11-14 and is now maintained alongside the code it
> describes. Update it in the same pull request as any change that fires one
> of the review triggers above.
>
> References such as "workspace #45" are Nostrfi's internal tracking issues.
> `nostrfi/relay` references are pull requests in this repository.
> `operating-model.md`, `operations.md`, and `brief.md` are internal Nostrfi
> documents; their operator-facing content is published in the
> [Nostrfi Relay documentation](https://nostrfi.io/docs/relay/), and the
> summary of this threat model is on
> [trust and data](https://nostrfi.io/docs/relay/security/trust-and-data/).

This document is the threat model required by Nostrfi's relay operating-model
decision (a public reusable relay) and promised by the relay product brief's
"Trust, privacy, and safety" section (workspace issue #10). It enumerates assets, trust boundaries, and
threats for a relay exposed to arbitrary internet input, and maps every
threat to exactly one disposition:

- **Mitigated** — an implemented application control, with the workspace
  issue that delivered it.
- **Deployment layer** — assigned to the deployment edge by
  `operating-model.md`'s application-vs-deployment boundary; the deployment,
  not the application, must provide it.
- **Tracked gap** — already recorded in an existing document or ticket.
- **New ticket** — a code change filed as a `nostrfi/relay` follow-up from
  this threat model.
- **Accepted residual** — deliberately not mitigated; listed in the
  accepted-risks register below.

## Assets

- Stored event envelopes and content in DuckDB, including gift-wrap
  (kind `1059`) ciphertext and its plaintext envelope metadata (recipient
  tag, timestamps, signatures).
- The DuckDB database file and Parquet backup exports (`-backup` writes
  `EXPORT DATABASE` output plus a plaintext row-count manifest; nothing is
  encrypted).
- Connection metadata observable in-process (client IP, timing, subscription
  filters, query patterns) — observable but deliberately not logged.
- Structured JSON logs (authenticated pubkeys at `Info`, moderation calls,
  event ids on failure; no IPs, no event content, no filters).
- NIP-42 session state and per-connection challenges (process memory only).
- The moderation admin key (`moderation.admin_pubkey`) — a signing capability
  for the NIP-86 management API, held by the operator, never by the relay.
- Host and process access (whoever controls the host controls everything
  above).

## Trust boundaries

1. **Internet ↔ WebSocket upgrade.** Unauthenticated. Controls at this
   boundary: NIP-86 IP/CIDR blocklist, production-mode origin allow-list,
   global connection cap, per-connection read limit.
2. **Client ↔ relay application.** Unauthenticated by default; NIP-42 only
   where a kind demands it (protected events, gift-wrap reads). Per-client
   token buckets and NIP-11 limits apply here.
3. **Deployment edge ↔ application.** TLS termination, DDoS absorption, and
   connection-level rate limiting at the edge are deployment-layer
   responsibilities, not application features (`operating-model.md`). The
   documented Caddy overlay terminates TLS; the application sees the proxy's
   address as the remote address.
4. **Application ↔ DuckDB/host.** The operator (and anyone with host access)
   can read every stored envelope, ciphertext, and backup. Controls are
   procedural (`operating-model.md`'s operator-access responsibilities).
5. **Operator ↔ NIP-86 management API.** Authenticated by NIP-98 signatures
   from `moderation.admin_pubkey`, with a freshness window and a bounded
   request-body reader; every call is logged.

## Threats and dispositions

### Malformed, oversized, and malicious JSON payloads

| Threat | Disposition |
| --- | --- |
| Oversized frames consuming memory | **Mitigated** — `max_message_length` is applied as the WebSocket read limit immediately after upgrade, aborting oversized frames during the read rather than after buffering (workspace #3). |
| Malformed or hostile protocol input | **Mitigated** — NIP-01 grammar, malformed-input, duplicate-event, and concurrency conformance tests exercise the parse path (`nostrfi/relay` PR #12); rejections are surfaced per NIP-01 and counted in bounded-cardinality metrics (workspace #14). |
| Oversized NIP-86 management bodies | **Mitigated** — the management endpoint reads through a bounded `io.LimitReader`. |
| Forged events | **Mitigated** — signatures are verified before storage; `created_at` bounds reject far-past/future timestamps (workspace #3). |

### Connection floods

| Threat | Disposition |
| --- | --- |
| Connection exhaustion of the process | **Mitigated** — global `max_connections` cap returns 503 above the limit (workspace #3). |
| Volumetric/distributed floods | **Deployment layer** — DDoS absorption and connection-level rate limiting at the edge, per `operating-model.md`'s boundary. |
| One source consuming the whole connection budget | **New ticket** — the cap is a single process-wide counter with no per-IP component, and per-client rate budgets multiply with each additional connection from the same source. An in-application per-source cap requires trusted-proxy remote-address handling first (see below). |
| Blocked IPs reconnecting behind the TLS proxy | **New ticket** — NIP-86 `blockip` matches the observed remote address, which is the proxy's address in the documented TLS overlay; already flagged in the
[development operation guide](https://nostrfi.io/docs/relay/operations/development-operation/) as open ("until trusted-proxy support exists"). |

### Subscription and filter abuse

| Threat | Disposition |
| --- | --- |
| Unbounded subscriptions/filters per connection | **Mitigated** — `max_subscriptions`, `max_filters`, `max_subid_length` enforced per connection (workspace #3). |
| Expensive queries via large `limit` | **Mitigated** — `limit` values above `max_limit` are clamped (workspace #3). |
| Expensive queries via *omitted* `limit` | **New ticket**, for non-search `REQ` filters — a filter with no `limit` produces a query with no `LIMIT` clause and loads every matching row into memory; `max_limit` clamps down but is never injected as a default. NIP-50 search filters are the exception: they are given the advertised `max_limit` when they name no limit of their own, and an explicit `"limit": 0` now returns no stored events rather than all of them (workspace #48). That bounds what search *returns*, not what it reads — see the row below. |
| Expensive queries via `search` | **Mitigated (per query), accepted residual (in aggregate)** — `search` is matched with an unindexed `ILIKE` scan, and NIP-50 requires the limit to be applied after sorting by relevance, so every candidate row is matched and ordered before any limit selects among them. The cost is now measured (workspace #59; see the [search cost](https://nostrfi.io/docs/relay/operations/capacity/#search-cost) measurements: roughly linear in table size, hundreds of milliseconds at tens of thousands of rows, and ten concurrent searchers cost a third of publish throughput) and bounded per query by `resource_limits.search_timeout_seconds` (shipped default 5s; `0` disables): a search past the budget is cancelled and answered `CLOSED` `error: search timed out` with the subscription dropped. Aggregate search concurrency remains bounded only by the connection and message-rate limits — see residual 8. |
| Negentropy resource exhaustion | **New ticket** — `NEG-OPEN` builds an in-memory vector of the full matching set, is not subject to `max_subscriptions`, and per-connection session count is uncapped. |
| Slow clients stalling fan-out | **Accepted residual** — broadcast is synchronous with a per-client write mutex and a 5-second write deadline; a slow client is dropped by the deadline rather than queued without bound. Revisit if fan-out latency appears in the capacity baseline. |

### Hostile or resource-exhausting event content

| Threat | Disposition |
| --- | --- |
| Spam floods from a pubkey or source | **Mitigated** — per-connection publish rate limiting (workspace #3) plus NIP-86 pubkey bans and IP/CIDR blocks (workspace #9), triaged per the abuse-response runbook in `operations.md`. |
| Oversized content/tag counts | **Mitigated** — `max_content_length`, `max_event_tags` (workspace #3). |
| Illegal or harassing content | **Mitigated** (procedurally) — moderation policy and NIP-86 `banevent`/`banpubkey` enforcement (workspace #9); bans act on this relay's storage and serving only. |
| Computational admission gating | **Accepted residual** — `min_pow_difficulty` is configurable but defaults to 0, and the operating model rules out payment gates; admission stays open by design. |

### WebSocket origins

| Threat | Disposition |
| --- | --- |
| Browser-based cross-origin misuse | **Mitigated** — production mode requires a non-empty exact-match origin allow-list, validated fail-closed at config load (workspace #4). Since workspace #45, the allow-list binds only connections that carry an `Origin` header — which every browser does, so the browser threat this row is about is unchanged. A connection without one (every non-browser client) is admitted, because refusing it excluded `wscat`, CLI clients, and relay-to-relay sync while stopping no attacker: a non-browser client forges any `Origin` it likes. Origin restriction is a cross-site-misuse control, not an access control. |
| Development-mode default accepting all origins | **Accepted residual** — re-decided under workspace #45, not carried forward by inertia. The review trigger fired when the relay gained a browser surface (#28, #35); on inspection the dashboard never opens a browser WebSocket (every relay call is server-side). The default stands because a public reusable relay cannot enumerate the world's browser origins: an allow-list default contradicts the operating model for exactly the clients origin checking binds, and production mode's fail-closed start would refuse to boot a fresh install (`docker compose up` ships `allowed_origins: []`). Production mode *as previously built* also refused every client that sends no `Origin` — most of the ecosystem — which is why the same change fixed it to admit them; that measurement motivated the fix, not the default. What the re-decision added: a startup warning whenever development mode binds a non-loopback interface. That detects **direct** public binds only — a loopback bind behind a same-host reverse proxy, tunnel, or port forward is still internet-facing and does not warn, a residual this row accepts rather than hides. The public `trust-and-data` page describes the modes accurately (production mode "can" be chosen — it has never said "must"). |

### Metadata disclosure

| Threat | Disposition |
| --- | --- |
| Operator observation of connection metadata, filters, and query patterns | **Accepted residual** — inherent to operating a relay; disclosed in `brief.md` and the website's trust-and-data page. Not logged (client IPs never appear in logs). |
| Gift-wrap envelope metadata (recipient tag, timing) | **Accepted residual** — retained and observable like any other event, per `operating-model.md`'s retention section; no separate encryption at rest or shorter retention. |
| Gift-wrap author read access | **Tracked gap** — the implementation also permits access by the event author; the policy and metadata implications are an open review item in [protocol support](https://nostrfi.io/docs/relay/reference/protocol-support/). |
| Log-channel disclosure | **Mitigated** — logs carry authenticated pubkeys and moderation method/operator fields, but no IPs, no event content, no filters, and no raw Negentropy payloads (payload logging removed under workspace #14). |
| Metrics-channel read access | **Mitigated** — decided under workspace #53, not assumed. `/metrics` was registered on the public mux, so any anonymous caller could read 52 series: the relay's traffic volume and shape, its rejection profile, its live connection count, its uptime and resident memory, and — because `promhttp.Handler()` serves the default registry — `go_info`, naming the exact Go build. No event content, but operational intelligence about one host, and a vulnerability-matching aid. It now has its own listener (`server.metrics_listen_addr`), loopback by default and unpublished by the deployment, so reaching it is a statement about where the caller sits — delivered by [nostrfi/relay#33](https://github.com/nostrfi/relay/pull/33). The endpoint still authenticates nobody, so the network position *is* the control: anything that can reach the address reads everything on it. Rejected alternatives: a `Caddyfile` 404, which protects only overlay deployments while `docker-compose.yml` publishes `8080`; and NIP-98 authentication, which no Prometheus scraper can satisfy and which would cost the dashboard a signer prompt per poll (#39). |
| Metrics-channel cardinality inflation | **Mitigated** — `/metrics` labels are bounded to known message types and rejection prefixes, so clients can neither inflate cardinality nor inject values (workspace #14). This is the narrower claim the row above used to rest on: it says what a client can put *into* the metrics, and says nothing about who may read them. |

### Authentication (NIP-42)

| Threat | Disposition |
| --- | --- |
| Forged or stale AUTH events | **Mitigated** — signature, kind, per-connection challenge match, freshness window, and optional canonical-URL binding when `auth.relay_url` is set (workspace #4). |
| AUTH replay | **Accepted residual** — a captured AUTH event only replays against the same live connection's challenge within the freshness window; challenges are generated per connection, so cross-connection replay fails. No lockout/attempt counter exists. |
| Presence-only default when `auth.relay_url` is unset | **Accepted residual** — the development-friendly default is documented in `brief.md` and the website; internet-facing deployments should set `auth.relay_url`. |

### Database and host access

| Threat | Disposition |
| --- | --- |
| Operator or host-level access to stored data | **Accepted residual** — procedural controls only (`operating-model.md`'s operator-access and legal-request sections); the DuckDB file is unencrypted at rest, consistent with the operating model's explicit "no additional encryption at rest" retention position. |
| Backup exposure | **Deployment layer** — backups are unencrypted Parquet exports with a plaintext manifest; scheduling, off-host storage, and encryption of backup media are deployment responsibilities (`operations.md`'s storage lifecycle). |
| Partially-migrated schema serving traffic | **Mitigated** — versioned idempotent migrations abort startup on failure (workspace #5). |

### Retention, deletion, and abuse response

| Threat | Disposition |
| --- | --- |
| Deleted/expired content lingering | **Mitigated** — NIP-09 deletions and NIP-40 expiration are honored; the purge worker reclaims expired rows and checkpoints on an interval (workspace #5). Deleted rows may persist in older backups until those backups rotate — **accepted residual**, deployment-layer rotation. |
| Abuse reports with no intake path | **Mitigated** — NIP-11 contact address, operator triage runbook, and NIP-86 enforcement with logged, authenticated management calls (workspace #9). |
| Moderation-key compromise | **Accepted residual** — `moderation.admin_pubkey` grants ban/unban control (not data read-out); calls are NIP-98-signed with a 60-second freshness window and logged. Key custody is an operator responsibility. |

## Accepted-risks register

Explicitly accepted, with the reasoning; each is revisited at this document's
review triggers:

1. **No encryption at rest** for the DuckDB file, gift-wrap envelopes, or
   backup exports — matches `operating-model.md`'s retention position;
   compensating control is host/backup-media access restriction.
2. **Observable metadata** — connection metadata, filters, query patterns,
   and gift-wrap envelope metadata are visible to the operator and retained;
   disclosed publicly rather than mitigated.
3. **No payment or proof-of-work admission gate** — ruled out by the public
   reusable operating model; abuse is handled reactively via rate limits and
   moderation.
4. **Development-mode defaults.** The all-origins-accepted half was
   re-accepted under workspace #45 with the dashboard and the
   public-reusable operating model explicitly considered: origin restriction
   binds honest browsers only, the relay's purpose is to accept arbitrary
   web clients, and a startup warning now fires whenever development mode
   binds a non-loopback interface directly (a loopback bind behind a
   same-host proxy or tunnel does not warn). The presence-only NIP-42
   relay-tag check
   remains accepted as before — safe for local development, documented as
   unsuitable for internet-facing deployments; re-deciding it is a separate
   ticket if the trigger fires for it.
5. **AUTH replay within a live connection's freshness window** — bounded by
   per-connection challenges; no lockout mechanism.
6. **Slow-client fan-out stalls bounded only by the 5-second write
   deadline** — no per-client outbound queue; acceptable at the current
   capacity baseline.
7. **Best-effort availability, no SLO, volumetric DDoS at the edge** —
   deferred/assigned by `operating-model.md`; tracing also remains open
   (workspace #14 scope note in `operations.md`).
8. **NIP-50 search reads more than it returns, and aggregate search load is
   bounded only indirectly** — an unindexed `ILIKE` scan whose candidates
   must all be matched and ordered before the limit selects among them,
   because the NIP requires the limit applied after ranking. Since
   workspace #59 the per-query work is measured (roughly linear in table
   size; see the
   [search cost](https://nostrfi.io/docs/relay/operations/capacity/#search-cost)
   measurements) and bounded by `resource_limits.search_timeout_seconds`
   (default 5s), so a single query can no longer run arbitrarily long. What
   remains accepted: many concurrent searches are limited only by the
   connection cap and per-connection message rates — the measured cost of
   ten concurrent searchers at ~28k rows was a 34% cut in publish
   throughput — and the scan-not-index design itself stands, because the
   alternative, DuckDB's `fts` extension, is not available to this build
   without a network install or a version- and platform-pinned bundle.

## Follow-up tickets

Findings above marked **New ticket** require `nostrfi/relay` code changes not
covered by workspace issues #3, #4, #5, or #6:

1. **Bound queries when clients omit `limit`, and cap Negentropy sessions** —
   inject a default `LIMIT` (e.g. `max_limit`) when a non-search REQ filter
   omits it, and bound `NEG-OPEN` result-set materialization and
   per-connection session count. Search filters already receive that default
   (workspace #48), so this ticket is the rest of the `REQ` surface.
2. **Trusted-proxy remote-address handling, then per-source connection
   limits** — honor a configured trusted proxy's forwarded address so NIP-86
   IP/CIDR blocks work behind the documented TLS overlay, and add a per-source
   connection cap so one source cannot multiply per-connection rate budgets
   or exhaust the global connection budget.

Ticket links are added here when filed.
