// Package application holds the relay's use-case orchestration: each
// service depends on a domain repository interface and coordinates calls
// to it, with no business logic beyond flow control — domain invariants
// (e.g. signature verification) live in the domain layer instead.
package application

import (
	"context"

	"relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

// EventService orchestrates event persistence and retrieval.
type EventService interface {
	SaveEvent(ctx context.Context, ev *event.Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*event.Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*event.Event, error)
	QueryEventsMatching(ctx context.Context, query event.Query) ([]*event.Event, error)
}

type eventService struct {
	repo event.Repository
}

func NewEventService(repo event.Repository) EventService {
	return &eventService{
		repo: repo,
	}
}

func (s *eventService) SaveEvent(ctx context.Context, ev *event.Event) (bool, error) {
	return s.repo.SaveEvent(ctx, ev)
}

func (s *eventService) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*event.Event, error) {
	return s.repo.QueryEvents(ctx, filter)
}

func (s *eventService) QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*event.Event, error) {
	return s.repo.QueryEventsSorted(ctx, filter)
}

func (s *eventService) QueryEventsMatching(ctx context.Context, query event.Query) ([]*event.Event, error) {
	return s.repo.QueryEventsMatching(ctx, query)
}
