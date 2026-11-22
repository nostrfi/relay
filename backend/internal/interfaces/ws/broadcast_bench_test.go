package ws

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
)

// broadcastFixture is a relay with conns connected clients, each holding
// subs subscriptions that all match kind 1, and readers draining every
// EVENT frame the relay sends, so broadcast measures encoding and writing
// rather than a full socket buffer. With keepFrames each received frame is
// passed on; without, frames are discarded without being buffered, so a
// benchmark counts the relay's allocations rather than its test client's.
type broadcastFixture struct {
	handler    *RelayHandler
	received   chan []byte
	keepFrames bool
}

func newBroadcastFixture(tb testing.TB, conns, subs int, keepFrames bool) *broadcastFixture {
	tb.Helper()
	handler := NewRelayHandlerFull(&stubEventService{}, stubModerationService{}, RelayInfo{}, ResourceLimits{}, AuthConfig{}, ModerationConfig{}, WebsocketConfig{}, "test")
	server := httptest.NewServer(handler)
	tb.Cleanup(server.Close)

	f := &broadcastFixture{handler: handler, received: make(chan []byte, 1024), keepFrames: keepFrames}
	for range conns {
		f.connect(tb, server, subs)
	}
	return f
}

func (f *broadcastFixture) connect(tb testing.TB, server *httptest.Server, subs int) {
	tb.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { conn.Close() })

	// Open the subscriptions one at a time, waiting for each EOSE, so the
	// relay's inbound queue never overflows.
	for i := range subs {
		req, _ := json.Marshal([]any{"REQ", fmt.Sprintf("sub-%d", i), nostr.Filter{Kinds: []int{1}}})
		if err := conn.WriteMessage(websocket.TextMessage, req); err != nil {
			tb.Fatalf("REQ: %v", err)
		}
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				tb.Fatalf("read: %v", err)
			}
			if strings.HasPrefix(string(data), `["EOSE"`) {
				break
			}
		}
	}

	go func() {
		for {
			if f.keepFrames {
				_, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				f.received <- data
				continue
			}
			_, r, err := conn.NextReader()
			if err != nil {
				return
			}
			if _, err := io.Copy(io.Discard, r); err != nil {
				return
			}
			f.received <- nil
		}
	}()
}

func benchEvent(tb testing.TB) *nostr.Event {
	tb.Helper()
	ev := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   strings.Repeat("broadcast benchmark <content> & more ", 8),
		Tags:      nostr.Tags{{"t", "bench"}, {"p", strings.Repeat("ab", 32)}},
	}
	if err := ev.Sign(nostr.GeneratePrivateKey()); err != nil {
		tb.Fatalf("sign: %v", err)
	}
	return ev
}

// BenchmarkBroadcast publishes one event to N subscriptions that all match
// it (nostrfi/relay#72). Before the fix, allocations grew with N by the
// whole event encode per subscription.
func BenchmarkBroadcast(b *testing.B) {
	for _, subs := range []int{1, 100, 1000} {
		b.Run(fmt.Sprintf("subs=%d", subs), func(b *testing.B) {
			f := newBroadcastFixture(b, 1, subs, false)
			ev := benchEvent(b)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				f.handler.broadcast(ev)
				for range subs {
					<-f.received
				}
			}
		})
	}
}
