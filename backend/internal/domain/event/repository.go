package event

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

// Query is a nostr.Filter plus the one dimension NIP-01 does not model: a
// substring of the event content.
//
// It exists so the operator event browser (nostrfi/workspace#36) can offer
// that search without it leaking into the protocol. Putting it in
// nostr.Filter's Search field would have been shorter and wrong: that field
// is NIP-50, the relay does not implement NIP-50, and the same filter type
// is built from whatever a REQ subscriber sends — so any client could then
// have used it, and the relay would be quietly answering a NIP it does not
// advertise.
type Query struct {
	Filter nostr.Filter
	// ContentContains matches case-insensitively anywhere in the content.
	// Empty means no content condition.
	ContentContains string
}

// Repository is the persistence port for events: implemented by the
// infrastructure layer, depended on by the application layer.
type Repository interface {
	SaveEvent(ctx context.Context, event *Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	// QueryEventsMatching is QueryEvents with Query's extra dimension, in
	// the same newest-first order.
	QueryEventsMatching(ctx context.Context, query Query) ([]*Event, error)
	// CountEvents is how many events are stored, including ones no query
	// would serve. It answers "is this the database I filled", which a
	// filtered count cannot.
	CountEvents(ctx context.Context) (int64, error)
	PurgeExpired(ctx context.Context) (int64, error)
	Checkpoint(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error
}
