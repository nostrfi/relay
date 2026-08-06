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

## Database

The relay uses **DuckDB** for high-performance event storage and querying. The database file is located at `db/relay.db`.
