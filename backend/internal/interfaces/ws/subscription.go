package ws

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	domainevent "relay/internal/domain/event"
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
		// NIP-01: limit is the maximum number of events to return in the
		// initial query, so "limit":0 asks for none of them — a client
		// that wants live updates only. queryEvents emits no SQL LIMIT
		// below a positive limit, so querying here would answer that
		// request with every matching row instead of none. The
		// subscription is already stored, so live delivery continues.
		if f.LimitZero {
			continue
		}
		start := time.Now()
		events, err := h.queryFilter(c, f)
		metrics.QueryDuration.WithLabelValues("req").Observe(time.Since(start).Seconds())
		if err != nil {
			// The client hanging up mid-query is the connection ending, not
			// a query failing; logging it as an error would let any client
			// spam the relay's error log by disconnecting at the right
			// moment. Nothing more useful remains to do for this REQ either
			// way — the remaining filters would be cancelled too.
			if errors.Is(err, context.Canceled) {
				return
			}
			// A search that outran its work budget answers with an explicit
			// failure and the subscription is dropped: a cancelled query
			// returns no partial rows, so the only honest alternative to
			// this CLOSED is an EOSE that silently pretends the search ran.
			// The client can retry with a narrower term.
			if errors.Is(err, context.DeadlineExceeded) {
				h.sendClosed(c, subID, prefixError+": search timed out")
				return
			}
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

// queryFilter runs one REQ filter's stored query on the connection's
// context, applying the configured search work budget when the filter
// carries a NIP-50 term. Search is the one query no index can answer — an
// unindexed ILIKE scan whose quality ordering is computed across every
// candidate row before LIMIT selects among them, so max_limit bounds what
// it returns, not what it reads — which is why it alone gets a deadline
// (workspace #59; measured in capacity-baseline.md's search scenarios).
// Zero or negative search_timeout_seconds disables the budget.
func (h *RelayHandler) queryFilter(c *Client, f nostr.Filter) ([]*domainevent.Event, error) {
	ctx := c.ctx
	if f.Search != "" && h.resourceLimits.SearchTimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.resourceLimits.SearchTimeoutSeconds)*time.Second)
		defer cancel()
	}
	return h.eventService.QueryEvents(ctx, f)
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
// The term was parsed and folded once, when the REQ was accepted, so a live
// event is judged by exactly the criterion the stored results were —
// without re-deriving it per event.
//
// loweredContent folds the event's content at most once per broadcast; see
// the comment in broadcast for why that matters.
func matchesFilter(f nostr.Filter, ev *nostr.Event, loweredContent func() string) bool {
	if !f.Matches(ev) {
		return false
	}
	if f.Search == "" {
		return true
	}
	term := strings.TrimSpace(f.Search)
	if term == "" {
		// A filter carrying only whitespace never reaches here: handleReq
		// refuses it before the subscription is stored. Matching nothing is
		// the safe reading if it ever does, since strings.Contains would
		// otherwise treat it as matching every event.
		return false
	}
	return strings.Contains(loweredContent(), term)
}

func (h *RelayHandler) broadcast(ev *nostr.Event) {
	// Case-folded at most once per event, and only if some subscription
	// actually carries a search term. Folding inside the per-filter match
	// instead meant one allocation of the whole content per filter: a
	// connection may hold max_subscriptions × max_filters of them, content
	// may be max_content_length, and every connected client is walked on
	// every publish — so a single event could have turned into thousands of
	// 64 KiB copies. Range runs its callbacks on this goroutine, so the
	// captured variables need no synchronization.
	var lowered string
	var folded bool
	loweredContent := func() string {
		if !folded {
			lowered = strings.ToLower(ev.Content)
			folded = true
		}
		return lowered
	}

	h.clients.Range(func(key, value any) bool {
		client := key.(*Client)
		client.subscriptions.Range(func(sKey, sValue any) bool {
			subID := sKey.(string)
			sub := sValue.(*subscription.Subscription)
			for _, f := range sub.Filters {
				if matchesFilter(f, ev, loweredContent) {
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
