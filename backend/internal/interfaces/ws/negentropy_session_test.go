package ws

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relay/internal/domain/event"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNegOpenOverSessionCapRunsNoQuery pins that the max_sync_sessions
// check comes before the sync query: a refused NEG-OPEN must cost no
// database work, or the cap would bound memory but not load
// (nostrfi/relay#71).
func TestNegOpenOverSessionCapRunsNoQuery(t *testing.T) {
	var queries atomic.Int32
	events := &stubEventService{
		querySync: func(context.Context, nostr.Filter) ([]event.SyncItem, error) {
			queries.Add(1)
			return nil, nil
		},
	}
	open := dialNegRelay(t, events, ResourceLimits{MaxSyncSessions: 1})

	require.Equal(t, "NEG-MSG", open("first")[0])
	refused := open("second")
	require.Equal(t, "NEG-ERR", refused[0], "got %v", refused)
	assert.Equal(t, "blocked: too many open sync sessions, max 1", refused[2])
	assert.Equal(t, int32(1), queries.Load(), "the refused NEG-OPEN must not query")
}

// TestNegOpenQueryErrorClosesReplacedSession covers a NEG-OPEN that reuses
// an open id and then fails its query: NIP-77 has already closed the old
// session, and the client treats the id as closed after the NEG-ERR, so
// the old session must not survive holding a slot (nostrfi/relay#71).
func TestNegOpenQueryErrorClosesReplacedSession(t *testing.T) {
	var calls atomic.Int32
	events := &stubEventService{
		querySync: func(context.Context, nostr.Filter) ([]event.SyncItem, error) {
			if calls.Add(1) == 2 {
				return nil, errors.New("database unavailable")
			}
			return nil, nil
		},
	}
	open := dialNegRelay(t, events, ResourceLimits{MaxSyncSessions: 1})

	require.Equal(t, "NEG-MSG", open("a")[0])
	failed := open("a")
	require.Equal(t, "NEG-ERR", failed[0], "got %v", failed)
	assert.True(t, strings.HasPrefix(failed[2], "error:"), "got %q", failed[2])

	// At a cap of one, a new id gets through only if "a" is gone.
	assert.Equal(t, "NEG-MSG", open("b")[0], "the replaced session still holds its slot")
}

// dialNegRelay starts a stub-backed relay with the given limits and
// returns a function that sends an empty-set NEG-OPEN and returns the
// relay's NEG-MSG or NEG-ERR reply as strings.
func dialNegRelay(t *testing.T, events *stubEventService, limits ResourceLimits) func(subID string) []string {
	t.Helper()
	handler := NewRelayHandlerFull(events, stubModerationService{}, RelayInfo{}, limits, AuthConfig{}, ModerationConfig{}, WebsocketConfig{}, "test")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	items := negentropy.NewVector()
	items.Seal()
	clientNeg, err := negentropy.NewNegentropy(items, 0)
	require.NoError(t, err)
	initial, err := clientNeg.Initiate()
	require.NoError(t, err)

	return func(subID string) []string {
		t.Helper()
		msg, _ := json.Marshal([]any{"NEG-OPEN", subID, nostr.Filter{}, hex.EncodeToString(initial)})
		require.NoError(t, conn.WriteMessage(websocket.TextMessage, msg))
		for {
			// Skip the AUTH challenge the relay greets every connection with.
			_, data, err := conn.ReadMessage()
			require.NoError(t, err)
			var reply []any
			require.NoError(t, json.Unmarshal(data, &reply))
			if kind := reply[0].(string); kind == "NEG-MSG" || kind == "NEG-ERR" {
				out := make([]string, len(reply))
				for i, v := range reply {
					out[i], _ = v.(string)
				}
				return out
			}
		}
	}
}
