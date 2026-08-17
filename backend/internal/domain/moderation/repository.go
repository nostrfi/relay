package moderation

import "context"

// Repository is the persistence port for moderation actions: pubkey bans,
// event bans, and IP/CIDR blocks.
type Repository interface {
	BanPubkey(ctx context.Context, pubkey, reason string) error
	UnbanPubkey(ctx context.Context, pubkey string) error
	ListBannedPubkeys(ctx context.Context) ([]ModerationEntry, error)
	IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error)

	BanEvent(ctx context.Context, eventID, reason string) error
	AllowEvent(ctx context.Context, eventID string) error
	ListBannedEvents(ctx context.Context) ([]ModerationEntry, error)

	BlockIP(ctx context.Context, ipOrCIDR, reason string) error
	UnblockIP(ctx context.Context, ipOrCIDR string) error
	ListBlockedIPs(ctx context.Context) ([]ModerationEntry, error)
}
