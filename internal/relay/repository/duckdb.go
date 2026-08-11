package repository

import (
	"context"
	"database/sql"
	"encoding/json"
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

	if err := RunMigrations(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}

	return &duckDBRepository{db: db}, nil
}

// SaveEvent runs entirely inside one transaction: every branch that deletes
// or replaces an event also removes that event's tag rows in the same
// transaction, so a failure partway through never leaves orphaned tags or a
// half-applied replace/delete.
func (r *duckDBRepository) SaveEvent(ctx context.Context, event *nostr.Event) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	saved, err := saveEventTx(ctx, tx, event)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return saved, nil
}

func saveEventTx(ctx context.Context, tx *sql.Tx, event *nostr.Event) (bool, error) {
	// Handle replaceable and addressable events
	if (event.Kind >= 10000 && event.Kind < 20000) || event.Kind == 0 || event.Kind == 3 {
		if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
			return false, err
		}

		var count int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
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
			if _, err := deleteMatchingEvents(ctx, tx, `
				kind = 41
				AND id IN (SELECT event_id FROM tags WHERE tag = 'e' AND value = ?)
				AND (created_at < ? OR (created_at = ? AND id > ?))
			`, eTag, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
				return false, err
			}

			var count int
			err := tx.QueryRowContext(ctx, `
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
		if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND d_tag = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, dTag, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
			return false, err
		}

		var count int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND d_tag = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
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
				if _, err := deleteMatchingEvents(ctx, tx, "id = ? AND pubkey = ?", targetID, event.PubKey); err != nil {
					return false, fmt.Errorf("failed to delete event by e tag %q: %w", targetID, err)
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
							if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND d_tag = ? AND created_at <= ?",
								pubkey, kind, dTag, event.CreatedAt); err != nil {
								return false, fmt.Errorf("failed to delete event by a tag %q: %w", tag[1], err)
							}
						} else {
							if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND created_at <= ?",
								pubkey, kind, event.CreatedAt); err != nil {
								return false, fmt.Errorf("failed to delete event by a tag %q: %w", tag[1], err)
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

	tagsJSON, err := json.Marshal(event.Tags)
	if err != nil {
		return false, fmt.Errorf("failed to marshal tags: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, content, sig, d_tag, expiration, tags_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.PubKey, event.CreatedAt, event.Kind, event.Content, event.Sig, dTag, expiration, string(tagsJSON))
	if err != nil {
		return false, err
	}

	// A duplicate publish of an event already in storage is not an error —
	// report success as usual — but its tags index rows are already there
	// too, so inserting them again would duplicate them on every republish.
	inserted, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if inserted == 0 {
		return true, nil
	}

	// This index only ever needs to serve NIP-01 single-letter tag filters
	// (`#e`, `#p`, ...), which match on a tag's name and first value alone —
	// full tag fidelity for served events comes from tags_json above, not
	// from this table.
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		if len(tag[0]) == 1 && ((tag[0][0] >= 'a' && tag[0][0] <= 'z') || (tag[0][0] >= 'A' && tag[0][0] <= 'Z')) {
			_, err = tx.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, ?, ?)", event.ID, tag[0], tag[1])
			if err != nil {
				slog.Error("failed to insert tag", "event_id", event.ID, "tag", tag[0], "error", err)
			}
		}
	}

	return true, nil
}

// deleteMatchingEvents deletes every event matching whereClause, along with
// its tag rows, in two IN-list statements rather than a subquery on tags
// nested inside a delete from tags (which would self-reference the table
// being deleted from). Returns the number of events deleted.
func deleteMatchingEvents(ctx context.Context, tx *sql.Tx, whereClause string, args ...any) (int64, error) {
	ids, err := selectEventIDs(ctx, tx, "SELECT id FROM events WHERE "+whereClause, args...)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}

	idArgs := make([]any, len(ids))
	for i, id := range ids {
		idArgs[i] = id
	}
	ph := placeholders(len(ids))

	if _, err := tx.ExecContext(ctx, "DELETE FROM tags WHERE event_id IN ("+ph+")", idArgs...); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE id IN ("+ph+")", idArgs...); err != nil {
		return 0, err
	}
	return int64(len(ids)), nil
}

func selectEventIDs(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
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
		cond, condArgs := prefixMatchCondition("e.id", filter.IDs)
		conditions = append(conditions, cond)
		args = append(args, condArgs...)
	}

	if len(filter.Authors) > 0 {
		cond, condArgs := prefixMatchCondition("e.pubkey", filter.Authors)
		conditions = append(conditions, cond)
		args = append(args, condArgs...)
	}

	if len(filter.Kinds) > 0 {
		conditions = append(conditions, fmt.Sprintf("e.kind IN (%s)", placeholders(len(filter.Kinds))))
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
		`, placeholders(len(values))))
		args = append(args, tag)
		for _, val := range values {
			args = append(args, val)
		}
	}

	query := "SELECT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig, e.tags_json FROM events e"
	now := nostr.Now()
	conditions = append(conditions, "(e.expiration IS NULL OR e.expiration > ?)")
	args = append(args, now)
	conditions = append(conditions, "e.id NOT IN (SELECT event_id FROM banned_events)")

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
		var tagsJSON sql.NullString
		err := rows.Scan(&ev.ID, &ev.PubKey, &ev.CreatedAt, &ev.Kind, &ev.Content, &ev.Sig, &tagsJSON)
		if err != nil {
			return nil, err
		}
		ev.Tags = r.reconstructTags(ctx, ev.ID, tagsJSON)
		events = append(events, &ev)
	}
	return events, nil
}

// reconstructTags returns the event's tags with full fidelity when
// tagsJSON was populated at save time. A row saved before the tags_json
// migration has tagsJSON NULL; for that case only, fall back to the
// lossy two-field reconstruction the relay used previously, since the
// original tag fields were never stored and cannot be recovered.
func (r *duckDBRepository) reconstructTags(ctx context.Context, eventID string, tagsJSON sql.NullString) nostr.Tags {
	if !tagsJSON.Valid {
		return r.getLegacyTags(ctx, eventID)
	}
	var tags nostr.Tags
	if err := json.Unmarshal([]byte(tagsJSON.String), &tags); err != nil {
		slog.Error("failed to unmarshal tags_json, falling back to legacy reconstruction", "event_id", eventID, "error", err)
		return r.getLegacyTags(ctx, eventID)
	}
	return tags
}

func placeholders(n int) string {
	ps := make([]string, n)
	for i := range n {
		ps[i] = "?"
	}
	return strings.Join(ps, ",")
}

// prefixMatchCondition builds an OR-combined WHERE fragment matching column
// against any of values. Per NIP-01, "ids" and "authors" filter values
// shorter than a full 64-character hex id/pubkey are prefix matches; a
// full-length value uses exact equality (equivalent to a 64-character
// prefix match, but index-friendly rather than a full scan).
func prefixMatchCondition(column string, values []string) (string, []any) {
	parts := make([]string, len(values))
	args := make([]any, len(values))
	for i, v := range values {
		if len(v) == 64 {
			parts[i] = column + " = ?"
		} else {
			parts[i] = "starts_with(" + column + ", ?)"
		}
		args[i] = v
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

func (r *duckDBRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// getLegacyTags reconstructs an event's tags from the tags index table,
// which only ever recorded a tag's name and first value. It is the fallback
// path for events saved before the tags_json migration (see
// reconstructTags); every event saved since then is reconstructed from its
// own tags_json column instead.
func (r *duckDBRepository) getLegacyTags(ctx context.Context, eventID string) nostr.Tags {
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
