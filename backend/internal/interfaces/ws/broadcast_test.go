package ws

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countEncodes swaps encodeEvent for a counting wrapper until the test ends.
func countEncodes(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	orig := encodeEvent
	encodeEvent = func(ev *nostr.Event) ([]byte, error) {
		n.Add(1)
		return orig(ev)
	}
	t.Cleanup(func() { encodeEvent = orig })
	return &n
}

// TestBroadcastEncodesEventOnce is the acceptance criterion of
// nostrfi/relay#72: one event encode per broadcast however many
// subscriptions match it, none when nothing matches, and every matching
// subscription still gets its own correctly addressed frame.
func TestBroadcastEncodesEventOnce(t *testing.T) {
	f := newBroadcastFixture(t, 2, 25, true)
	encodes := countEncodes(t)
	ev := benchEvent(t)

	f.handler.broadcast(ev)

	want, err := json.Marshal(ev)
	require.NoError(t, err)
	got := map[string]int{}
	deadline := time.After(5 * time.Second)
	for range 50 {
		select {
		case frame := <-f.received:
			var parsed []json.RawMessage
			require.NoError(t, json.Unmarshal(frame, &parsed))
			require.Len(t, parsed, 3)
			var subID string
			require.NoError(t, json.Unmarshal(parsed[1], &subID))
			assert.Equal(t, string(want), string(parsed[2]))
			got[subID]++
		case <-deadline:
			t.Fatalf("got %d of 50 frames", len(got))
		}
	}
	assert.Len(t, got, 25, "each connection's 25 subscription ids, delivered once per connection")
	for subID, n := range got {
		assert.Equal(t, 2, n, "subscription %s", subID)
	}
	assert.Equal(t, int32(1), encodes.Load(), "one encode for 50 matching subscriptions")

	unmatched := benchEvent(t)
	unmatched.Kind = 7
	require.NoError(t, unmatched.Sign(nostr.GeneratePrivateKey()))
	f.handler.broadcast(unmatched)
	assert.Equal(t, int32(1), encodes.Load(), "a broadcast nothing matches encodes nothing")
}

// TestAppendEventFrameMatchesMarshal pins byte-identity with the frames
// the relay sent before nostrfi/relay#72, json.Marshal of the whole
// envelope, across the inputs whose escaping could differ: HTML
// characters, quotes and backslashes, line and paragraph separators,
// invalid UTF-8, and client-chosen subscription ids.
func TestAppendEventFrameMatchesMarshal(t *testing.T) {
	contents := map[string]string{
		"html":            `<script>alert("x")</script> & more`,
		"quote/backslash": `say "hi" \ bye`,
		"separators":      "line para end",
		"emoji":           "🙂 ünïcödé",
		"invalid utf-8":   "bad \xff\xfe bytes",
		"control":         "tab\tnul\x00bell\x07",
		"empty":           "",
	}
	tagSets := map[string]nostr.Tags{
		"none":   {},
		"nested": {{"e", strings.Repeat("ab", 32), "wss://relay.example/?a=1&b=<2>"}, {"t", `"quoted"`}},
		"nil":    nil,
	}
	subIDs := []string{"", "sub", `a"b`, `a\b`, "</script>", "ctl\x01\n", "ünï🙂", " "}

	for contentName, content := range contents {
		for tagName, tags := range tagSets {
			for _, kind := range []int{0, 1, 1059} {
				ev := &nostr.Event{Kind: kind, CreatedAt: 1700000000, Content: content, Tags: tags}
				require.NoError(t, ev.Sign(nostr.GeneratePrivateKey()))
				eventJSON, err := encodeEvent(ev)
				require.NoError(t, err)
				for _, subID := range subIDs {
					want, err := json.Marshal([]any{"EVENT", subID, ev})
					require.NoError(t, err)
					got := appendEventFrame(nil, subID, eventJSON)
					assert.Equal(t, string(want), string(got), "content=%s tags=%s kind=%d subID=%q", contentName, tagName, kind, subID)
				}
			}
		}
	}
}

// TestAppendEventFrameReusesBuffer checks the pool's contract: a frame
// built into a reused buffer carries nothing over from the previous one.
func TestAppendEventFrameReusesBuffer(t *testing.T) {
	long := appendEventFrame(nil, strings.Repeat("x", 200), []byte(`{"id":"long"}`))
	short := appendEventFrame(long[:0], "s", []byte(`{}`))
	assert.Equal(t, `["EVENT","s",{}]`, string(short))
}
