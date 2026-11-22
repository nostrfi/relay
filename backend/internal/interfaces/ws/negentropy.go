package ws

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"relay/pkg/metrics"

	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
)

func (h *RelayHandler) handleNegOpen(c *Client, subID string, filter nostr.Filter, initialMsgHex string) {
	initialMsg, err := hex.DecodeString(initialMsgHex)
	if err != nil {
		h.sendNegErr(c, subID, prefixInvalid+": could not decode hex message")
		return
	}

	// max_sync_events bounds the reconciliation set. A query asking for
	// more — no limit, or one above the cap — reads one row past the cap,
	// so an oversized set is detected without being loaded, and refused
	// rather than truncated: sync order is oldest first, so a truncated
	// vector would tell the peer this relay lacks every newer event, with
	// no error to say so. NIP-77 names "blocked" for exactly this refusal.
	maxItems := h.resourceLimits.MaxSyncEvents
	query := filter
	capped := maxItems > 0 && (filter.Limit <= 0 || filter.Limit > maxItems)
	if capped {
		query.Limit = maxItems + 1
	}

	start := time.Now()
	syncItems, err := h.eventService.QuerySyncItems(c.ctx, query)
	metrics.QueryDuration.WithLabelValues("negentropy").Observe(time.Since(start).Seconds())
	if err != nil {
		// As in handleReq: a disconnect mid-query is the connection ending,
		// not an error worth logging, and there is nobody left to send the
		// NEG-ERR to.
		if errors.Is(err, context.Canceled) {
			return
		}
		slog.Error("negentropy query failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": could not build reconciliation set")
		return
	}

	if capped && len(syncItems) > maxItems {
		// A NEG-OPEN replaces any session under the same id, so a refused
		// one must not leave the previous session answering NEG-MSGs.
		c.negSessions.Delete(subID)
		h.sendNegErr(c, subID, prefixBlocked+": this query is too big")
		return
	}

	items := negentropy.NewVector()
	for _, item := range syncItems {
		idBytes, err := hex.DecodeString(item.ID)
		if err != nil {
			continue
		}
		items.Insert(uint64(item.CreatedAt), idBytes)
	}
	items.Seal()

	storage, err := negentropy.NewNegentropy(items, 0)
	if err != nil {
		slog.Error("negentropy session init failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": could not open reconciliation session")
		return
	}

	session := &NegentropySession{
		id:      subID,
		filter:  filter,
		storage: storage,
	}
	c.negSessions.Store(subID, session)

	response, err := storage.Reconcile(initialMsg)
	if err != nil {
		slog.Error("negentropy reconcile failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": reconciliation failed")
		return
	}

	h.sendNegMsg(c, subID, hex.EncodeToString(response))
}

func (h *RelayHandler) handleNegMsg(c *Client, subID string, msgHex string) {
	val, ok := c.negSessions.Load(subID)
	if !ok {
		h.sendNegErr(c, subID, "closed: session not found")
		return
	}
	session := val.(*NegentropySession)

	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		h.sendNegErr(c, subID, prefixInvalid+": could not decode hex message")
		return
	}

	response, err := session.storage.Reconcile(msg)
	if err != nil {
		slog.Error("negentropy reconcile failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": reconciliation failed")
		return
	}

	if len(response) == 0 {
		// reconciliation complete or nothing to send
		return
	}

	h.sendNegMsg(c, subID, hex.EncodeToString(response))
}
