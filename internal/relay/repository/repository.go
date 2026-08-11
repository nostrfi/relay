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
	Ping(ctx context.Context) error
	Close() error

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

// ModerationEntry is a single row from a moderation list: a banned pubkey,
// a banned event ID, or a blocked IP/CIDR, along with the operator's
// reason (if given) and when the action was applied.
type ModerationEntry struct {
	Value     string `json:"value"`
	Reason    string `json:"reason,omitzero"`
	AppliedAt int64  `json:"applied_at"`
}
