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

## Database

The relay uses **DuckDB** for high-performance event storage and querying. The database file is located at `db/relay.db`.
