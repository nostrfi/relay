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

	start := time.Now()
	events, err := h.eventService.QueryEventsSorted(c.ctx, filter)
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

	items := negentropy.NewVector()
	for _, ev := range events {
		idBytes, err := hex.DecodeString(ev.ID)
		if err != nil {
			continue
		}
		items.Insert(uint64(ev.CreatedAt), idBytes)
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
