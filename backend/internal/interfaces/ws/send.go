package ws

import (
	"encoding/json"
	"log/slog"
	"strings"
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

func (h *RelayHandler) sendEvent(c *Client, subID string, ev *nostr.Event) {
	msg, _ := json.Marshal([]any{"EVENT", subID, ev})
	h.write(c, msg)
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
