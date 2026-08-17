package application

import (
	"context"

	"relay/internal/domain/moderation"
)

// ModerationService orchestrates pubkey bans, event bans, and IP/CIDR
// blocks.
type ModerationService interface {
	BanPubkey(ctx context.Context, pubkey, reason string) error
	UnbanPubkey(ctx context.Context, pubkey string) error
	ListBannedPubkeys(ctx context.Context) ([]moderation.ModerationEntry, error)
	IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error)

	BanEvent(ctx context.Context, eventID, reason string) error
	AllowEvent(ctx context.Context, eventID string) error
	ListBannedEvents(ctx context.Context) ([]moderation.ModerationEntry, error)

	BlockIP(ctx context.Context, ipOrCIDR, reason string) error
	UnblockIP(ctx context.Context, ipOrCIDR string) error
	ListBlockedIPs(ctx context.Context) ([]moderation.ModerationEntry, error)
}

type moderationService struct {
	repo moderation.Repository
}

func NewModerationService(repo moderation.Repository) ModerationService {
	return &moderationService{
		repo: repo,
	}
}

func (s *moderationService) BanPubkey(ctx context.Context, pubkey, reason string) error {
	return s.repo.BanPubkey(ctx, pubkey, reason)
}

func (s *moderationService) UnbanPubkey(ctx context.Context, pubkey string) error {
	return s.repo.UnbanPubkey(ctx, pubkey)
}

func (s *moderationService) ListBannedPubkeys(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return s.repo.ListBannedPubkeys(ctx)
}

func (s *moderationService) IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error) {
	return s.repo.IsPubkeyBanned(ctx, pubkey)
}

func (s *moderationService) BanEvent(ctx context.Context, eventID, reason string) error {
	return s.repo.BanEvent(ctx, eventID, reason)
}

func (s *moderationService) AllowEvent(ctx context.Context, eventID string) error {
	return s.repo.AllowEvent(ctx, eventID)
}

func (s *moderationService) ListBannedEvents(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return s.repo.ListBannedEvents(ctx)
}

func (s *moderationService) BlockIP(ctx context.Context, ipOrCIDR, reason string) error {
	return s.repo.BlockIP(ctx, ipOrCIDR, reason)
}

func (s *moderationService) UnblockIP(ctx context.Context, ipOrCIDR string) error {
	return s.repo.UnblockIP(ctx, ipOrCIDR)
}

func (s *moderationService) ListBlockedIPs(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return s.repo.ListBlockedIPs(ctx)
}
