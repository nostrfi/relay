package repository

import (
	"context"
	"database/sql"
	"fmt"
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
