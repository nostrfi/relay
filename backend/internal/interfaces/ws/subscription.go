package ws

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"relay/internal/domain/subscription"
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
	c.subscriptions.Store(subID, subscription.New(subID, filters))

	seenIDs := make(map[string]bool)
	for _, f := range filters {
		start := time.Now()
		events, err := h.eventService.QueryEvents(context.Background(), f)
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

				h.sendEvent(c, subID, ev.Event)
				seenIDs[ev.ID] = true
			}
		}
	}
	h.sendEOSE(c, subID)
}

// matchesFilter is nostr.Filter.Matches plus the one dimension it does not
// know about: NIP-50's search term.
//
// go-nostr's Matches ignores Search entirely, so it answers true for an
// event whose content does not contain the term (v0.52.3, filter.go). Left
// alone, an open REQ carrying a search term would return a correctly
// filtered batch of stored events and then stream every later event
// matching the rest of the filter — the search silently expiring at EOSE.
//
// The term is parsed here the same way the stored query parses it, so a
// live event is judged by exactly the criterion the stored results were.
func matchesFilter(f nostr.Filter, ev *nostr.Event) bool {
	if !f.Matches(ev) {
		return false
	}
	if f.Search == "" {
		return true
	}
	term := parseSearchTerm(f.Search)
	if term == "" {
		// Nothing searchable survived the extensions. handleReq refuses
		// such a filter outright, so this is unreachable from a live
		// subscription; matching nothing is the safe reading if it ever
		// becomes reachable, since the alternative is streaming everything.
		return false
	}
	return strings.Contains(strings.ToLower(ev.Content), strings.ToLower(term))
}

func (h *RelayHandler) broadcast(ev *nostr.Event) {
	h.clients.Range(func(key, value any) bool {
		client := key.(*Client)
		client.subscriptions.Range(func(sKey, sValue any) bool {
			subID := sKey.(string)
			sub := sValue.(*subscription.Subscription)
			for _, f := range sub.Filters {
				if matchesFilter(f, ev) {
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
