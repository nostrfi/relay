package repository

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

// PurgeExpired deletes events whose NIP-40 expiration has passed, along with
// their tag rows, and reports how many events were removed. Reads already
// filter expired events out (see queryEvents); this is what actually
// reclaims the rows instead of leaving them stored forever.
func (r *duckDBRepository) PurgeExpired(ctx context.Context) (int64, error) {
	now := nostr.Now()

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM tags WHERE event_id IN (
			SELECT id FROM events WHERE expiration IS NOT NULL AND expiration <= ?
		)
	`, now); err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx, "DELETE FROM events WHERE expiration IS NOT NULL AND expiration <= ?", now)
	if err != nil {
		return 0, err
	}
	purged, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return purged, nil
}

// Checkpoint persists DuckDB's write-ahead log and runs VACUUM so the engine
// can reclaim and reorganize space freed by PurgeExpired and by deletions
// and replacements elsewhere. Run periodically by the maintenance worker,
// not on every write.
func (r *duckDBRepository) Checkpoint(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, "CHECKPOINT"); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, "VACUUM")
	return err
}
