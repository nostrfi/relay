package event

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

// Repository is the persistence port for events: implemented by the
// infrastructure layer, depended on by the application layer.
type Repository interface {
	SaveEvent(ctx context.Context, event *Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	PurgeExpired(ctx context.Context) (int64, error)
	Checkpoint(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error
}
