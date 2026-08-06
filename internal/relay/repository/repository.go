package repository

import (
	"context"
	"github.com/nbd-wtf/go-nostr"
)

type Repository interface {
	SaveEvent(ctx context.Context, event *nostr.Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
	PurgeExpired(ctx context.Context) (int64, error)
	Checkpoint(ctx context.Context) error
	Close() error
}
