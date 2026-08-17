package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"relay/internal/infrastructure/duckdb"

	_ "github.com/duckdb/duckdb-go/v2"
)

// runBackup exports the database at dbPath to dir and exits. Intended to be
// run while the server is stopped or against a replica; DuckDB's EXPORT
// DATABASE does not coordinate with a concurrently writing process in
// another connection.
func runBackup(dbPath, dir string) {
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		slog.Error("failed to open storage for backup", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Ensure the schema exists (idempotent) before backing up: -backup can
	// be run against a database the server has never started against yet.
	ctx := context.Background()
	if err := duckdb.RunMigrations(ctx, db); err != nil {
		slog.Error("failed to prepare database schema for backup", "error", err)
		os.Exit(1)
	}

	manifest, err := duckdb.Backup(ctx, db, dir)
	if err != nil {
		slog.Error("backup failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Backup complete", "output_dir", dir, "events", manifest.EventCount, "tags", manifest.TagCount)
}

// runRestore imports a backup created by runBackup into dbPath and exits.
// It refuses to run if dbPath already exists, so a live database is never
// silently merged with restored data; the operator must move or remove the
// existing file first, as documented in the runbook.
func runRestore(dbPath, dir string) {
	if _, err := os.Stat(dbPath); err == nil {
		slog.Error("refusing to restore: database file already exists; move or remove it first", "path", dbPath)
		os.Exit(1)
	}

	// Restore is a disaster-recovery path and may run against a fresh host
	// where the database directory itself doesn't exist yet, not just the
	// file — unlike normal startup, don't assume it's already there.
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		slog.Error("failed to create database directory for restore", "error", err)
		os.Exit(1)
	}

	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		slog.Error("failed to open storage for restore", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	manifest, err := duckdb.Restore(context.Background(), db, dir)
	if err != nil {
		slog.Error("restore failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Restore complete and verified", "events", manifest.EventCount, "tags", manifest.TagCount)
}
