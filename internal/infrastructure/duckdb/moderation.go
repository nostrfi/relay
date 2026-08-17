package duckdb

import (
	"context"
	"database/sql"

	"relay/internal/domain/moderation"

	"github.com/nbd-wtf/go-nostr"
)

func (r *Repository) BanPubkey(ctx context.Context, pubkey, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO banned_pubkeys (pubkey, reason, banned_at) VALUES (?, ?, ?)
		ON CONFLICT (pubkey) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at
	`, pubkey, reason, int64(nostr.Now()))
	return err
}

func (r *Repository) UnbanPubkey(ctx context.Context, pubkey string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM banned_pubkeys WHERE pubkey = ?", pubkey)
	return err
}

func (r *Repository) ListBannedPubkeys(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return listModerationEntries(ctx, r.db, "SELECT pubkey, reason, banned_at FROM banned_pubkeys ORDER BY banned_at")
}

func (r *Repository) IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM banned_pubkeys WHERE pubkey = ?)", pubkey).Scan(&exists)
	return exists, err
}

func (r *Repository) BanEvent(ctx context.Context, eventID, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO banned_events (event_id, reason, banned_at) VALUES (?, ?, ?)
		ON CONFLICT (event_id) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at
	`, eventID, reason, int64(nostr.Now()))
	return err
}

func (r *Repository) AllowEvent(ctx context.Context, eventID string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM banned_events WHERE event_id = ?", eventID)
	return err
}

func (r *Repository) ListBannedEvents(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return listModerationEntries(ctx, r.db, "SELECT event_id, reason, banned_at FROM banned_events ORDER BY banned_at")
}

func (r *Repository) BlockIP(ctx context.Context, ipOrCIDR, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO blocked_ips (ip_or_cidr, reason, blocked_at) VALUES (?, ?, ?)
		ON CONFLICT (ip_or_cidr) DO UPDATE SET reason = excluded.reason, blocked_at = excluded.blocked_at
	`, ipOrCIDR, reason, int64(nostr.Now()))
	return err
}

func (r *Repository) UnblockIP(ctx context.Context, ipOrCIDR string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM blocked_ips WHERE ip_or_cidr = ?", ipOrCIDR)
	return err
}

func (r *Repository) ListBlockedIPs(ctx context.Context) ([]moderation.ModerationEntry, error) {
	return listModerationEntries(ctx, r.db, "SELECT ip_or_cidr, reason, blocked_at FROM blocked_ips ORDER BY blocked_at")
}

func listModerationEntries(ctx context.Context, db *sql.DB, query string) ([]moderation.ModerationEntry, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []moderation.ModerationEntry{}
	for rows.Next() {
		var e moderation.ModerationEntry
		var reason sql.NullString
		if err := rows.Scan(&e.Value, &reason, &e.AppliedAt); err != nil {
			return nil, err
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
