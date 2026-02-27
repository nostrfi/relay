package repository

import (
	"context"
	"github.com/nbd-wtf/go-nostr"
)

type Repository interface {
	SaveEvent(ctx context.Context, event *nostr.Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
	Close() error
}
