package ws

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"relay/internal/domain/event"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the NIP-50 search work budget (workspace #59): a search
// query past resource_limits.search_timeout_seconds is cancelled and the
// client answered with CLOSED; ordinary REQ filters and a zero timeout get
// no deadline at all.

func dialStubRelayLimits(t *testing.T, events *stubEventService, limits ResourceLimits) *websocket.Conn {
	t.Helper()
	handler := NewRelayHandlerFull(events, stubModerationService{}, RelayInfo{}, limits, AuthConfig{}, ModerationConfig{}, WebsocketConfig{}, "test")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "dial failed")
	return conn
}

// readSubMessage reads frames until one addressed to subID arrives,
// returning its message type and, for CLOSED, the reason.
func readSubMessage(t *testing.T, conn *websocket.Conn, subID string) (string, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		require.NoError(t, conn.SetReadDeadline(deadline))
		_, raw, err := conn.ReadMessage()
		require.NoError(t, err, "read failed waiting for %s", subID)
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
			continue
		}
		var msgType, gotSub string
		json.Unmarshal(arr[0], &msgType)
		json.Unmarshal(arr[1], &gotSub)
		if gotSub != subID {
			continue
		}
		var reason string
		if msgType == "CLOSED" && len(arr) > 2 {
			json.Unmarshal(arr[2], &reason)
		}
		return msgType, reason
	}
}

// TestSearchTimeoutCancelsAndCloses is the bound working end to end: with a
// configured budget, a search whose stored query outruns it is cancelled
// with DeadlineExceeded and the client receives CLOSED naming the timeout —
// not an EOSE pretending the search ran.
func TestSearchTimeoutCancelsAndCloses(t *testing.T) {
	queryErr := make(chan error, 1)
	events := &stubEventService{
		queryEvents: func(ctx context.Context, _ nostr.Filter) ([]*event.Event, error) {
			<-ctx.Done()
			queryErr <- ctx.Err()
			return nil, ctx.Err()
		},
	}

	conn := dialStubRelayLimits(t, events, ResourceLimits{SearchTimeoutSeconds: 1})
	defer conn.Close()
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["REQ","sub_search",{"search":"orange"}]`)))

	select {
	case err := <-queryErr:
		assert.ErrorIs(t, err, context.DeadlineExceeded, "the search query must be cancelled by the work budget")
	case <-time.After(3 * time.Second):
		t.Fatal("the search query was never cancelled")
	}

	msgType, reason := readSubMessage(t, conn, "sub_search")
	assert.Equal(t, "CLOSED", msgType)
	assert.Equal(t, "error: search timed out", reason)
}

// TestSearchTimeoutScope pins the budget's boundaries: it applies only to
// filters carrying a search term, and a zero configuration disables it
// entirely.
func TestSearchTimeoutScope(t *testing.T) {
	run := func(t *testing.T, limits ResourceLimits, req, subID string) bool {
		t.Helper()
		hadDeadline := make(chan bool, 1)
		events := &stubEventService{
			queryEvents: func(ctx context.Context, _ nostr.Filter) ([]*event.Event, error) {
				_, ok := ctx.Deadline()
				hadDeadline <- ok
				return nil, nil
			},
		}
		conn := dialStubRelayLimits(t, events, limits)
		defer conn.Close()
		require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(req)))
		msgType, _ := readSubMessage(t, conn, subID)
		require.Equal(t, "EOSE", msgType)
		select {
		case ok := <-hadDeadline:
			return ok
		case <-time.After(2 * time.Second):
			t.Fatal("QueryEvents was never called")
			return false
		}
	}

	t.Run("a search filter gets the deadline", func(t *testing.T) {
		assert.True(t, run(t, ResourceLimits{SearchTimeoutSeconds: 5}, `["REQ","s1",{"search":"orange"}]`, "s1"))
	})
	t.Run("a non-search filter does not", func(t *testing.T) {
		assert.False(t, run(t, ResourceLimits{SearchTimeoutSeconds: 5}, `["REQ","s2",{"kinds":[1]}]`, "s2"))
	})
	t.Run("zero disables the budget for search too", func(t *testing.T) {
		assert.False(t, run(t, ResourceLimits{}, `["REQ","s3",{"search":"orange"}]`, "s3"))
	})
}
