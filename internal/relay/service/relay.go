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

	BanPubkey(ctx context.Context, pubkey, reason string) error
	UnbanPubkey(ctx context.Context, pubkey string) error
	ListBannedPubkeys(ctx context.Context) ([]repository.ModerationEntry, error)
	IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error)

	BanEvent(ctx context.Context, eventID, reason string) error
	AllowEvent(ctx context.Context, eventID string) error
	ListBannedEvents(ctx context.Context) ([]repository.ModerationEntry, error)

	BlockIP(ctx context.Context, ipOrCIDR, reason string) error
	UnblockIP(ctx context.Context, ipOrCIDR string) error
	ListBlockedIPs(ctx context.Context) ([]repository.ModerationEntry, error)
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

func (s *relayService) BanPubkey(ctx context.Context, pubkey, reason string) error {
	return s.repo.BanPubkey(ctx, pubkey, reason)
}

func (s *relayService) UnbanPubkey(ctx context.Context, pubkey string) error {
	return s.repo.UnbanPubkey(ctx, pubkey)
}

func (s *relayService) ListBannedPubkeys(ctx context.Context) ([]repository.ModerationEntry, error) {
	return s.repo.ListBannedPubkeys(ctx)
}

func (s *relayService) IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error) {
	return s.repo.IsPubkeyBanned(ctx, pubkey)
}

func (s *relayService) BanEvent(ctx context.Context, eventID, reason string) error {
	return s.repo.BanEvent(ctx, eventID, reason)
}

func (s *relayService) AllowEvent(ctx context.Context, eventID string) error {
	return s.repo.AllowEvent(ctx, eventID)
}

func (s *relayService) ListBannedEvents(ctx context.Context) ([]repository.ModerationEntry, error) {
	return s.repo.ListBannedEvents(ctx)
}

func (s *relayService) BlockIP(ctx context.Context, ipOrCIDR, reason string) error {
	return s.repo.BlockIP(ctx, ipOrCIDR, reason)
}

func (s *relayService) UnblockIP(ctx context.Context, ipOrCIDR string) error {
	return s.repo.UnblockIP(ctx, ipOrCIDR)
}

func (s *relayService) ListBlockedIPs(ctx context.Context) ([]repository.ModerationEntry, error) {
	return s.repo.ListBlockedIPs(ctx)
}
