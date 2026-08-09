package handler

import (
	"context"
	"log/slog"
	"time"

	"relay/pkg/metrics"

	"github.com/nbd-wtf/go-nostr"
)

func countSubscriptions(c *Client) int {
	n := 0
	c.subscriptions.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func (h *RelayHandler) handleReq(c *Client, subID string, filters []nostr.Filter) {
	c.subscriptions.Store(subID, filters)

	seenIDs := make(map[string]bool)
	for _, f := range filters {
		start := time.Now()
		events, err := h.service.QueryEvents(context.Background(), f)
		metrics.QueryDuration.WithLabelValues("req").Observe(time.Since(start).Seconds())
		if err != nil {
			slog.Error("query error", "error", err)
			continue
		}
		for _, ev := range events {
			if !seenIDs[ev.ID] {
				// NIP-17: Relays MAY protect message metadata by only serving kind:1059 events to users p-tagged on the event
				if ev.Kind == 1059 {
					isRecipient := false
					for _, tag := range ev.Tags {
						if len(tag) >= 2 && tag[0] == "p" && tag[1] == c.authPubkey {
							isRecipient = true
							break
						}
					}
					// Also allow the author to see their own gift wrap
					if !isRecipient && ev.PubKey != c.authPubkey {
						continue
					}
				}

				h.sendEvent(c, subID, ev)
				seenIDs[ev.ID] = true
			}
		}
	}
	h.sendEOSE(c, subID)
}

func (h *RelayHandler) broadcast(ev *nostr.Event) {
	h.clients.Range(func(key, value any) bool {
		client := key.(*Client)
		client.subscriptions.Range(func(sKey, sValue any) bool {
			subID := sKey.(string)
			filters := sValue.([]nostr.Filter)
			for _, f := range filters {
				if f.Matches(ev) {
					// NIP-17: Kind 1059 access control for live updates
					if ev.Kind == 1059 {
						isRecipient := false
						for _, tag := range ev.Tags {
							if len(tag) >= 2 && tag[0] == "p" && tag[1] == client.authPubkey {
								isRecipient = true
								break
							}
						}
						if !isRecipient && ev.PubKey != client.authPubkey {
							return true // continue to next subscription
						}
					}

					h.sendEvent(client, subID, ev)
					break
				}
			}
			return true
		})
		return true
	})
}
