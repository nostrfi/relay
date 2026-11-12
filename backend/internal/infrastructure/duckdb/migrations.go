package duckdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

type migration struct {
	version     int
	description string
	up          func(ctx context.Context, tx *sql.Tx) error
}

// migrations must stay in ascending, gapless version order. Every step must
// remain idempotent (IF NOT EXISTS / existence checks) so that bootstrapping
// a database created before this runner existed is just "run everything,
// then record it as applied" rather than requiring separate detection logic.
var migrations = []migration{
	{
		version:     1,
		description: "create events and tags tables",
		up: func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `
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
			return err
		},
	},
	{
		version:     2,
		description: "add events.expiration column and index",
		up: func(ctx context.Context, tx *sql.Tx) error {
			hasColumn, err := columnExists(ctx, tx, "events", "expiration")
			if err != nil {
				return err
			}
			if !hasColumn {
				if _, err := tx.ExecContext(ctx, "ALTER TABLE events ADD COLUMN expiration INTEGER"); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_events_expiration ON events (expiration)")
			return err
		},
	},
	{
		version:     3,
		description: "add events.tags_json column for full tag fidelity",
		up: func(ctx context.Context, tx *sql.Tx) error {
			hasColumn, err := columnExists(ctx, tx, "events", "tags_json")
			if err != nil {
				return err
			}
			if !hasColumn {
				if _, err := tx.ExecContext(ctx, "ALTER TABLE events ADD COLUMN tags_json TEXT"); err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		version:     4,
		description: "create moderation tables (banned_pubkeys, banned_events, blocked_ips)",
		up: func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `
				CREATE TABLE IF NOT EXISTS banned_pubkeys (
					pubkey TEXT PRIMARY KEY,
					reason TEXT,
					banned_at INTEGER
				);
				CREATE TABLE IF NOT EXISTS banned_events (
					event_id TEXT PRIMARY KEY,
					reason TEXT,
					banned_at INTEGER
				);
				CREATE TABLE IF NOT EXISTS blocked_ips (
					ip_or_cidr TEXT PRIMARY KEY,
					reason TEXT,
					blocked_at INTEGER
				);
			`)
			return err
		},
	},
	{
		version:     5,
		description: "index the operator's allowlisted multi-letter and value-less tags",
		up:          backfillExtendedTagRows,
	},
}

// backfillTagsPageSize bounds how many events migration 5 holds in memory
// at once while it rebuilds their extended tag rows.
const backfillTagsPageSize = 1000

// backfillExtendedTagRows gives every stored event the tag index rows
// domainevent.IndexedTag now asks for beyond NIP-01's single-letter tags:
// allowlisted multi-letter tags, and value-less tags (nostrfi/relay#45).
//
// Built from tags_json, so an event saved before migration 3 gets nothing:
// its multi-letter tags were never stored and cannot be recovered. Its
// single-letter rows are untouched, as are everyone's.
//
// Idempotent by rebuilding rather than appending: the extended rows are
// deleted first, then written again from tags_json, which also keeps them
// identical to what saveEventTx writes for a new event.
func backfillExtendedTagRows(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM tags WHERE length(tag) <> 1 OR value IS NULL"); err != nil {
		return fmt.Errorf("clear extended tag rows: %w", err)
	}

	after := ""
	for {
		page, err := readTagsJSONPage(ctx, tx, after)
		if err != nil {
			return err
		}
		for _, row := range page {
			for _, tag := range row.tags {
				name, _, hasValue, ok := domainevent.IndexedTag(tag)
				// Single-letter tags with a value are indexed already.
				if !ok || (hasValue && domainevent.IsSingleLetterTag(name)) {
					continue
				}
				if err := insertTagRow(ctx, tx, row.id, tag); err != nil {
					return fmt.Errorf("index tag %q of event %s: %w", name, row.id, err)
				}
			}
		}
		if len(page) < backfillTagsPageSize {
			return nil
		}
		after = page[len(page)-1].id
	}
}

type tagsJSONRow struct {
	id   string
	tags nostr.Tags
}

// readTagsJSONPage reads the next page of events by id, fully, before any
// tag row is written: the transaction's connection cannot write while it
// still has a result set open.
func readTagsJSONPage(ctx context.Context, tx *sql.Tx, after string) ([]tagsJSONRow, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT id, tags_json FROM events WHERE tags_json IS NOT NULL AND id > ? ORDER BY id LIMIT ?",
		after, backfillTagsPageSize)
	if err != nil {
		return nil, fmt.Errorf("read events for tag backfill: %w", err)
	}
	defer rows.Close()

	var page []tagsJSONRow
	for rows.Next() {
		var id, tagsJSON string
		if err := rows.Scan(&id, &tagsJSON); err != nil {
			return nil, err
		}
		var tags nostr.Tags
		if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
			// The read path falls back to the legacy rows for such an
			// event too (reconstructTags); there is nothing to index.
			slog.Warn("skipping unreadable tags_json in tag backfill", "event_id", id, "error", err)
			tags = nil
		}
		page = append(page, tagsJSONRow{id: id, tags: tags})
	}
	return page, rows.Err()
}

func columnExists(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info('%s')", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull bool
		var dfltValue any
		var pk bool
		if err := rows.Scan(&cid, &name, &dtype, &notnull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// RunMigrations applies every migration newer than the database's recorded
// schema version, in order.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	return runMigrationList(ctx, db, migrations)
}

// runMigrationList is the parameterized implementation behind RunMigrations,
// factored out so tests can exercise the runner against a test-local
// migration list (including a deliberately failing one) without touching the
// real, versioned migrations slice. Each migration runs inside its own
// transaction; a failure rolls back that migration and aborts the run rather
// than recording it as applied or leaving the schema partially changed.
func runMigrationList(ctx context.Context, db *sql.DB, list []migration) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	current, err := currentSchemaVersion(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to read current schema version: %w", err)
	}

	for _, m := range list {
		if m.version <= current {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.description, err)
		}
	}
	return nil
}

func currentSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil {
		return 0, err
	}
	return int(version.Int64), nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := m.up(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, now())", m.version); err != nil {
		return err
	}
	return tx.Commit()
}
