// Package subscription holds the relay's Subscription domain type: a
// client's REQ subscription ID and the filters it watches, for both the
// initial backfill and live broadcast matching.
package subscription

import "github.com/nbd-wtf/go-nostr"

// Subscription is a client's REQ subscription: the ID the client assigned
// it and the filters events are matched against.
//
// Per-relay limits on subscription count, filter count, and ID length
// (RelayLimitation) are operator configuration, not a domain invariant of a
// Subscription itself, and are enforced by the interfaces layer where that
// configuration lives.
type Subscription struct {
	ID      string
	Filters []nostr.Filter
}

// New returns a Subscription for id and filters, exactly as received: it
// intentionally does not reject an empty ID or empty filters, preserving
// the relay's existing behavior of accepting whatever a client sends.
func New(id string, filters []nostr.Filter) *Subscription {
	return &Subscription{ID: id, Filters: filters}
}
