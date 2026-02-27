package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/nbd-wtf/go-nostr"
)

type duckDBRepository struct {
	db *sql.DB
}

func NewDuckDBRepository(path string) (Repository, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, err
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id TEXT PRIMARY KEY,
			pubkey TEXT,
			created_at INTEGER,
			kind INTEGER,
			content TEXT,
			sig TEXT,
			d_tag TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_events_pubkey ON events (pubkey);
		CREATE INDEX IF NOT EXISTS idx_events_kind ON events (kind);
		CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at);

		CREATE TABLE IF NOT EXISTS tags (
			event_id TEXT,
			tag TEXT,
			value TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_tags_event_id ON tags (event_id);
		CREATE INDEX IF NOT EXISTS idx_tags_tag_value ON tags (tag, value);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Schema migration: Add expiration column if it doesn't exist
	var hasExpiration bool
	rows, err := db.Query("PRAGMA table_info('events')")
	if err != nil {
		return nil, fmt.Errorf("failed to query table info: %w", err)
	}
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull bool
		var dfltValue any
		var pk bool
		if err := rows.Scan(&cid, &name, &dtype, &notnull, &dfltValue, &pk); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan table info: %w", err)
		}
		if name == "expiration" {
			hasExpiration = true
			break
		}
	}
	rows.Close()

	if !hasExpiration {
		_, err = db.Exec("ALTER TABLE events ADD COLUMN expiration INTEGER")
		if err != nil {
			return nil, fmt.Errorf("failed to add expiration column: %w", err)
		}
		_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_events_expiration ON events (expiration)")
		if err != nil {
			return nil, fmt.Errorf("failed to create expiration index: %w", err)
		}
	}

	return &duckDBRepository{db: db}, nil
}

func (r *duckDBRepository) SaveEvent(ctx context.Context, event *nostr.Event) (bool, error) {
	// Handle replaceable and addressable events
	if (event.Kind >= 10000 && event.Kind < 20000) || event.Kind == 0 || event.Kind == 3 {
		_, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE pubkey = ? AND kind = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, event.CreatedAt, event.CreatedAt, event.ID)
		if err != nil {
			return false, err
		}

		var count int
		err = r.db.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
			event.PubKey, event.Kind, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	} else if event.Kind == 41 {
		// NIP-28: Kind 41 - Set channel metadata
		// "Only the most recent kind 41 per 'e' tag value MAY be available."
		eTag := ""
		for _, tag := range event.Tags {
			if len(tag) > 1 && tag[0] == "e" {
				eTag = tag[1]
				break
			}
		}

		if eTag != "" {
			// Find all kind 41 events with the same 'e' tag
			_, err := r.db.ExecContext(ctx, `
				DELETE FROM events 
				WHERE kind = 41 
				AND id IN (SELECT event_id FROM tags WHERE tag = 'e' AND value = ?)
				AND (created_at < ? OR (created_at = ? AND id > ?))
			`, eTag, event.CreatedAt, event.CreatedAt, event.ID)
			if err != nil {
				return false, err
			}

			var count int
			err = r.db.QueryRowContext(ctx, `
				SELECT count(*) FROM events 
				WHERE kind = 41 
				AND id IN (SELECT event_id FROM tags WHERE tag = 'e' AND value = ?)
				AND (created_at > ? OR (created_at = ? AND id <= ?))
			`, eTag, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
			if err != nil {
				return false, err
			}
			if count > 0 {
				return true, nil
			}
		}
	} else if event.Kind >= 30000 && event.Kind < 40000 {
		dTag := ""
		for _, tag := range event.Tags {
			if len(tag) > 1 && tag[0] == "d" {
				dTag = tag[1]
				break
			}
		}
		_, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE pubkey = ? AND kind = ? AND d_tag = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, dTag, event.CreatedAt, event.CreatedAt, event.ID)
		if err != nil {
			return false, err
		}

		var count int
		err = r.db.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND d_tag = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
			event.PubKey, event.Kind, dTag, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}

	if event.Kind == 5 {
		for _, tag := range event.Tags {
			if len(tag) < 2 {
				continue
			}
			if tag[0] == "e" {
				targetID := tag[1]
				_, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE id = ? AND pubkey = ?", targetID, event.PubKey)
				if err != nil {
					slog.Error("failed to delete event by e tag", "target_id", targetID, "error", err)
				}
			} else if tag[0] == "a" {
				parts := strings.Split(tag[1], ":")
				if len(parts) >= 2 {
					kind := parts[0]
					pubkey := parts[1]
					dTag := ""
					if len(parts) >= 3 {
						dTag = parts[2]
					}

					if pubkey == event.PubKey {
						if dTag != "" {
							_, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE pubkey = ? AND kind = ? AND d_tag = ? AND created_at <= ?",
								pubkey, kind, dTag, event.CreatedAt)
							if err != nil {
								slog.Error("failed to delete event by a tag with d_tag", "pubkey", pubkey, "kind", kind, "d_tag", dTag, "error", err)
							}
						} else {
							_, err := r.db.ExecContext(ctx, "DELETE FROM events WHERE pubkey = ? AND kind = ? AND created_at <= ?",
								pubkey, kind, event.CreatedAt)
							if err != nil {
								slog.Error("failed to delete event by a tag", "pubkey", pubkey, "kind", kind, "error", err)
							}
						}
					}
				}
			}
		}
	}

	dTag := sql.NullString{}
	expiration := sql.NullInt64{}
	for _, tag := range event.Tags {
		if len(tag) > 1 {
			if tag[0] == "d" {
				dTag.String = tag[1]
				dTag.Valid = true
			} else if tag[0] == "expiration" {
				var ts int64
				if _, err := fmt.Sscanf(tag[1], "%d", &ts); err == nil {
					expiration.Int64 = ts
					expiration.Valid = true
				}
			}
		}
	}

	// NIP-40: Relays SHOULD drop any events that are published to them if they are expired.
	if expiration.Valid && expiration.Int64 < int64(event.CreatedAt) {
		return false, fmt.Errorf("event already expired")
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, content, sig, d_tag, expiration)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.PubKey, event.CreatedAt, event.Kind, event.Content, event.Sig, dTag, expiration)
	if err != nil {
		return false, err
	}

	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		if len(tag[0]) == 1 && ((tag[0][0] >= 'a' && tag[0][0] <= 'z') || (tag[0][0] >= 'A' && tag[0][0] <= 'Z')) {
			_, err = r.db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, ?, ?)", event.ID, tag[0], tag[1])
			if err != nil {
				slog.Error("failed to insert tag", "event_id", event.ID, "tag", tag[0], "error", err)
			}
		}
	}

	return true, nil
}

func (r *duckDBRepository) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return r.queryEvents(ctx, filter, false)
}

func (r *duckDBRepository) QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return r.queryEvents(ctx, filter, true)
}

func (r *duckDBRepository) queryEvents(ctx context.Context, filter nostr.Filter, sortedForSync bool) ([]*nostr.Event, error) {
	var conditions []string
	var args []any

	if len(filter.IDs) > 0 {
		conditions = append(conditions, fmt.Sprintf("e.id IN (%s)", r.placeholders(len(filter.IDs))))
		for _, id := range filter.IDs {
			args = append(args, id)
		}
	}

	if len(filter.Authors) > 0 {
		conditions = append(conditions, fmt.Sprintf("e.pubkey IN (%s)", r.placeholders(len(filter.Authors))))
		for _, author := range filter.Authors {
			args = append(args, author)
		}
	}

	if len(filter.Kinds) > 0 {
		conditions = append(conditions, fmt.Sprintf("e.kind IN (%s)", r.placeholders(len(filter.Kinds))))
		for _, kind := range filter.Kinds {
			args = append(args, kind)
		}
	}

	if filter.Since != nil {
		conditions = append(conditions, "e.created_at >= ?")
		args = append(args, *filter.Since)
	}

	if filter.Until != nil {
		conditions = append(conditions, "e.created_at <= ?")
		args = append(args, *filter.Until)
	}

	for tag, values := range filter.Tags {
		if len(values) == 0 {
			continue
		}
		conditions = append(conditions, fmt.Sprintf(`
			e.id IN (SELECT event_id FROM tags WHERE tag = ? AND value IN (%s))
		`, r.placeholders(len(values))))
		args = append(args, tag)
		for _, val := range values {
			args = append(args, val)
		}
	}

	query := "SELECT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig FROM events e"
	now := nostr.Now()
	conditions = append(conditions, "(e.expiration IS NULL OR e.expiration > ?)")
	args = append(args, now)

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	if sortedForSync {
		query += " ORDER BY e.created_at ASC, e.id ASC"
	} else {
		query += " ORDER BY e.created_at DESC, e.id ASC"
	}
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*nostr.Event
	for rows.Next() {
		var ev nostr.Event
		err := rows.Scan(&ev.ID, &ev.PubKey, &ev.CreatedAt, &ev.Kind, &ev.Content, &ev.Sig)
		if err != nil {
			return nil, err
		}
		ev.Tags = r.getTags(ctx, ev.ID)
		events = append(events, &ev)
	}
	return events, nil
}

func (r *duckDBRepository) placeholders(n int) string {
	ps := make([]string, n)
	for i := range n {
		ps[i] = "?"
	}
	return strings.Join(ps, ",")
}

func (r *duckDBRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

func (r *duckDBRepository) getTags(ctx context.Context, eventID string) nostr.Tags {
	rows, err := r.db.QueryContext(ctx, "SELECT tag, value FROM tags WHERE event_id = ?", eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var tags nostr.Tags
	for rows.Next() {
		var tag, value string
		if err := rows.Scan(&tag, &value); err == nil {
			tags = append(tags, []string{tag, value})
		}
	}
	return tags
}
