package service

import (
	"context"
	"relay/internal/relay/repository"

	"github.com/nbd-wtf/go-nostr"
)

type RelayService interface {
	SaveEvent(ctx context.Context, event *nostr.Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error)
}

type relayService struct {
	repo repository.Repository
}

func NewRelayService(repo repository.Repository) RelayService {
	return &relayService{
		repo: repo,
	}
}

func (s *relayService) SaveEvent(ctx context.Context, event *nostr.Event) (bool, error) {
	return s.repo.SaveEvent(ctx, event)
}

func (s *relayService) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return s.repo.QueryEvents(ctx, filter)
}

func (s *relayService) QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return s.repo.QueryEventsSorted(ctx, filter)
}
