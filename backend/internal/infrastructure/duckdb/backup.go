package duckdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const backupManifestFileName = "backup-manifest.json"

// BackupManifest records the row counts observed at backup time so Restore
// can verify the restored database matches what was exported.
type BackupManifest struct {
	CreatedAt  time.Time `json:"created_at"`
	EventCount int64     `json:"event_count"`
	TagCount   int64     `json:"tag_count"`
}

// Backup exports db to dir using DuckDB's native EXPORT DATABASE and writes
// a row-count manifest alongside it. dir must not contain a single quote:
// DuckDB does not support parameter binding for EXPORT DATABASE's target
// path, so the value is interpolated into the statement after that check.
// This is acceptable because the caller is an operator-controlled CLI flag,
// not untrusted network input.
func Backup(ctx context.Context, db *sql.DB, dir string) (BackupManifest, error) {
	if err := validateBackupPath(dir); err != nil {
		return BackupManifest{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to create backup directory: %w", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("EXPORT DATABASE '%s' (FORMAT PARQUET)", dir)); err != nil {
		return BackupManifest{}, fmt.Errorf("EXPORT DATABASE failed: %w", err)
	}

	manifest, err := countRows(ctx, db)
	if err != nil {
		return BackupManifest{}, err
	}
	manifest.CreatedAt = time.Now()

	f, err := os.Create(filepath.Join(dir, backupManifestFileName))
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to write backup manifest: %w", err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(manifest); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to encode backup manifest: %w", err)
	}

	return manifest, nil
}

// Restore imports a backup created by Backup into db, which must be an
// otherwise-empty database (IMPORT DATABASE recreates the exported schema,
// including schema_migrations, so a fresh database is left in the same
// migrated state the backup was taken from). It verifies the restored row
// counts against the manifest written at backup time and runs a smoke-test
// query before returning success.
func Restore(ctx context.Context, db *sql.DB, dir string) (BackupManifest, error) {
	if err := validateBackupPath(dir); err != nil {
		return BackupManifest{}, err
	}

	manifestBytes, err := os.ReadFile(filepath.Join(dir, backupManifestFileName))
	if err != nil {
		return BackupManifest{}, fmt.Errorf("failed to read backup manifest: %w", err)
	}
	var want BackupManifest
	if err := json.Unmarshal(manifestBytes, &want); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to parse backup manifest: %w", err)
	}

	if _, err := db.ExecContext(ctx, fmt.Sprintf("IMPORT DATABASE '%s'", dir)); err != nil {
		return BackupManifest{}, fmt.Errorf("IMPORT DATABASE failed: %w", err)
	}

	got, err := countRows(ctx, db)
	if err != nil {
		return BackupManifest{}, err
	}
	if got.EventCount != want.EventCount || got.TagCount != want.TagCount {
		return got, fmt.Errorf("restore integrity check failed: backup manifest recorded %d events / %d tags, restored database has %d events / %d tags",
			want.EventCount, want.TagCount, got.EventCount, got.TagCount)
	}

	if _, err := db.QueryContext(ctx, "SELECT id FROM events LIMIT 1"); err != nil {
		return got, fmt.Errorf("restore smoke-test query failed: %w", err)
	}

	return got, nil
}

func countRows(ctx context.Context, db *sql.DB) (BackupManifest, error) {
	var m BackupManifest
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&m.EventCount); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to count events: %w", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM tags").Scan(&m.TagCount); err != nil {
		return BackupManifest{}, fmt.Errorf("failed to count tags: %w", err)
	}
	return m, nil
}

func validateBackupPath(dir string) error {
	if dir == "" {
		return fmt.Errorf("backup directory must not be empty")
	}
	if strings.Contains(dir, "'") {
		return fmt.Errorf("backup directory must not contain a single quote: %q", dir)
	}
	return nil
}
