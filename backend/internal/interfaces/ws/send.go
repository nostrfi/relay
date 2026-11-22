package ws

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"relay/pkg/metrics"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
)

// NIP-01 machine-readable rejection prefixes, shared across OK, CLOSED, and
// NOTICE responses so clients see one consistent vocabulary.
const (
	prefixInvalid      = "invalid"
	prefixRestricted   = "restricted"
	prefixRateLimited  = "rate-limited"
	prefixAuthRequired = "auth-required"
	prefixPow          = "pow"
	prefixError        = "error"
	prefixBlocked      = "blocked"
)

const writeDeadline = 5 * time.Second

// write sends a pre-encoded message with a bounded write deadline so a
// stalled or malicious client cannot block the sender indefinitely. Errors
// (including deadline exceeded) are logged and swallowed; the caller already
// has nothing useful to do with a failed send to one client.
func (h *RelayHandler) write(c *Client, msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		slog.Warn("write failed, dropping message for client", "error", err)
	}
}

// encodeEvent is the one place an event becomes wire JSON. It must be
// json.Marshal, not ev.MarshalJSON: nostr.Event's generated encoder does
// not HTML-escape, and json.Marshal compacts and escapes its output, so
// only this form is byte-identical to the frames the relay has always
// sent. A variable so tests can count encodes (nostrfi/relay#72).
var encodeEvent = func(ev *nostr.Event) ([]byte, error) {
	return json.Marshal(ev)
}

// framePool holds the buffers EVENT frames are built in. gorilla's server
// WriteMessage, without compression (which the relay's Upgrader does not
// enable), copies the frame into its own write buffer and keeps no
// reference once it returns, so a buffer can go back as soon as write does.
var framePool = sync.Pool{New: func() any {
	b := make([]byte, 0, 1024)
	return &b
}}

// maxPooledFrame keeps one outsized event from pinning a large buffer in
// the pool; such frames are built and left to the garbage collector.
const maxPooledFrame = 64 << 10

// appendEventFrame appends ["EVENT",<subID>,<event>] to dst, splicing in
// an event already encoded by encodeEvent. The result is byte-identical to
// json.Marshal([]any{"EVENT", subID, ev}). subID is client-supplied, so it
// always goes through json.Marshal for the same escaping as before.
func appendEventFrame(dst []byte, subID string, eventJSON []byte) []byte {
	subIDJSON, _ := json.Marshal(subID) // a string always encodes
	dst = append(dst, `["EVENT",`...)
	dst = append(dst, subIDJSON...)
	dst = append(dst, ',')
	dst = append(dst, eventJSON...)
	return append(dst, ']')
}

// sendEventJSON sends one EVENT frame for an event encoded once by the
// caller, so a broadcast to many subscriptions encodes it a single time.
func (h *RelayHandler) sendEventJSON(c *Client, subID string, eventJSON []byte) {
	bp := framePool.Get().(*[]byte)
	frame := appendEventFrame((*bp)[:0], subID, eventJSON)
	h.write(c, frame)
	if cap(frame) <= maxPooledFrame {
		*bp = frame[:0]
		framePool.Put(bp)
	}
}

func (h *RelayHandler) sendOK(c *Client, eventID string, ok bool, reason string) {
	if !ok {
		recordRejection(reason)
	}
	msg, _ := json.Marshal([]any{"OK", eventID, ok, reason})
	h.write(c, msg)
}

// recordRejection extracts the leading NIP-01 prefix from reason (the text
// before the first ":") and increments RejectionsTotal, bounded to the
// relay's known prefix vocabulary regardless of what the caller passes in.
func recordRejection(reason string) {
	prefix := reason
	if i := strings.Index(reason, ":"); i >= 0 {
		prefix = reason[:i]
	}
	metrics.RejectionsTotal.WithLabelValues(metrics.KnownRejectionReason(prefix)).Inc()
}

// sendNotice is used only for rejection/error notices in this handler; every
// call records a rejection.
func (h *RelayHandler) sendNotice(c *Client, message string) {
	recordRejection(message)
	msg, _ := json.Marshal([]any{"NOTICE", message})
	h.write(c, msg)
}

func (h *RelayHandler) sendAuth(c *Client, challenge string) {
	msg, _ := json.Marshal([]any{"AUTH", challenge})
	h.write(c, msg)
}

func (h *RelayHandler) sendEOSE(c *Client, subID string) {
	msg, _ := json.Marshal([]any{"EOSE", subID})
	h.write(c, msg)
}

// sendClosed sends a NIP-01 CLOSED message and drops the subscription, used
// when a REQ is rejected instead of served.
// sendClosed refuses a subscription and tells the client why.
//
// LoadAndDelete rather than Delete, so a refusal that replaces a live
// subscription decrements the counters that creating it incremented — the
// same pairing the CLOSE handler uses. Deleting without decrementing left
// the count permanently high: disconnect cleanup only counts subscriptions
// still in the map, so nothing later repaired it, and the dashboard went on
// reporting a subscription that had been closed.
func (h *RelayHandler) sendClosed(c *Client, subID string, reason string) {
	recordRejection(reason)
	if _, existed := c.subscriptions.LoadAndDelete(subID); existed {
		h.subCount.Add(-1)
		metrics.SubscriptionsActive.Dec()
	}
	msg, _ := json.Marshal([]any{"CLOSED", subID, reason})
	h.write(c, msg)
}

func (h *RelayHandler) sendNegErr(c *Client, subID string, reason string) {
	recordRejection(reason)
	msg, _ := json.Marshal([]any{"NEG-ERR", subID, reason})
	h.write(c, msg)
}

func (h *RelayHandler) sendNegMsg(c *Client, subID string, msgHex string) {
	slog.Debug("Sending NEG-MSG", "sub_id", subID)
	msg, _ := json.Marshal([]any{"NEG-MSG", subID, msgHex})
	h.write(c, msg)
}
