package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTempDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := sql.Open("duckdb", path)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db, path
}

func TestRunMigrationsFreshDatabase(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()

	require.NoError(t, RunMigrations(ctx, db))

	version, err := currentSchemaVersion(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, len(migrations), version)

	// Idempotent: running again against an already-migrated database is a
	// no-op, not an error.
	require.NoError(t, RunMigrations(ctx, db))
}

func TestRunMigrationsBootstrapsPreFrameworkDatabase(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()

	// Simulate a database created before the migration runner existed: the
	// tables are already there (from the old ad hoc setup), but there is no
	// schema_migrations table and no recorded version at all.
	_, err := db.ExecContext(ctx, `
		CREATE TABLE events (
			id TEXT PRIMARY KEY, pubkey TEXT, created_at INTEGER, kind INTEGER,
			content TEXT, sig TEXT, d_tag TEXT
		);
		CREATE TABLE tags (event_id TEXT, tag TEXT, value TEXT);
	`)
	require.NoError(t, err)

	require.NoError(t, RunMigrations(ctx, db))

	version, err := currentSchemaVersion(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, len(migrations), version, "bootstrap should backfill schema_migrations to the latest version")

	hasExpiration, err := columnExistsOnConn(ctx, db, "events", "expiration")
	require.NoError(t, err)
	assert.True(t, hasExpiration, "the expiration column migration should still apply to a pre-framework database")
}

// columnExistsOnConn mirrors columnExists but works against a *sql.DB
// directly rather than an in-flight transaction, for assertions after a
// migration run has already committed.
func columnExistsOnConn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	return columnExists(ctx, tx, table, column)
}

func TestRunMigrationsAbortsOnFailure(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()

	boom := errors.New("boom")
	testMigrations := []migration{
		{
			version:     1,
			description: "create a marker table",
			up: func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, "CREATE TABLE marker (id INTEGER)")
				return err
			},
		},
		{
			version:     2,
			description: "deliberately fails",
			up: func(ctx context.Context, tx *sql.Tx) error {
				return boom
			},
		},
	}

	err := runMigrationList(ctx, db, testMigrations)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)

	version, err := currentSchemaVersion(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, 1, version, "the failed migration must not be recorded as applied")

	// A subsequent, successful run should retry only the failed migration.
	testMigrations[1].up = func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "ALTER TABLE marker ADD COLUMN retried INTEGER")
		return err
	}
	require.NoError(t, runMigrationList(ctx, db, testMigrations))
	version, err = currentSchemaVersion(ctx, db)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func seedEvent(t *testing.T, ctx context.Context, repo *duckDBRepository, expiration *int64) {
	t.Helper()
	seedEventAt(t, ctx, repo, nostr.Now(), expiration)
}

// seedEventAt seeds an event with an explicit created_at, so a test can
// construct one that was valid to publish at the time (expiration after
// created_at) but has since become expired relative to the real current
// time — SaveEvent itself rejects an event that is already expired at
// publish time, so that state can only be reached this way.
func seedEventAt(t *testing.T, ctx context.Context, repo *duckDBRepository, createdAt nostr.Timestamp, expiration *int64) {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: createdAt,
		Kind:      1,
		Tags:      nostr.Tags{{"t", "lifecycle-test"}},
		Content:   "hi",
	}
	if expiration != nil {
		ev.Tags = append(ev.Tags, nostr.Tag{"expiration", strconv.FormatInt(*expiration, 10)})
	}
	require.NoError(t, ev.Sign(sk))
	ok, err := repo.SaveEvent(ctx, &ev)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPurgeExpired(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	// Valid when published (expiration after created_at), but now in the
	// past relative to the real current time — eligible for purge.
	alreadyExpired := int64(nostr.Now()) - 3600
	seedEventAt(t, ctx, repo, nostr.Now()-7200, &alreadyExpired)

	future := int64(nostr.Now()) + 3600
	seedEvent(t, ctx, repo, &future) // not yet expired, must survive
	seedEvent(t, ctx, repo, nil)     // no expiration, must survive

	purged, err := repo.PurgeExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), purged)

	var eventCount, tagCount int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&eventCount))
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags").Scan(&tagCount))
	assert.Equal(t, int64(2), eventCount, "only the expired event should be removed")
	assert.Equal(t, int64(2), tagCount, "the purged event's tag row must go with it")

	// Purging again with nothing left to purge is a safe no-op.
	purged, err = repo.PurgeExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), purged)
}

func TestCheckpoint(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	seedEvent(t, ctx, repo, nil)

	assert.NoError(t, repo.Checkpoint(ctx))
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()

	sourceDB, _ := openTempDB(t)
	require.NoError(t, RunMigrations(ctx, sourceDB))
	sourceRepo := &duckDBRepository{db: sourceDB}

	for range 5 {
		seedEvent(t, ctx, sourceRepo, nil)
	}
	future := int64(nostr.Now()) + 3600
	seedEvent(t, ctx, sourceRepo, &future)

	backupDir := filepath.Join(t.TempDir(), "backup")
	manifest, err := Backup(ctx, sourceDB, backupDir)
	require.NoError(t, err)
	assert.Equal(t, int64(6), manifest.EventCount)
	assert.Equal(t, int64(6), manifest.TagCount)

	restorePath := filepath.Join(t.TempDir(), "restored.db")
	_, statErr := os.Stat(restorePath)
	require.True(t, os.IsNotExist(statErr), "restore target must not already exist")

	targetDB, err := sql.Open("duckdb", restorePath)
	require.NoError(t, err)
	defer targetDB.Close()

	restored, err := Restore(ctx, targetDB, backupDir)
	require.NoError(t, err)
	assert.Equal(t, manifest.EventCount, restored.EventCount)
	assert.Equal(t, manifest.TagCount, restored.TagCount)

	// The restored database must be immediately usable through the normal
	// repository surface, including a fresh call into the migration runner
	// (mirroring what happens when the relay is next started against it).
	require.NoError(t, RunMigrations(ctx, targetDB))
	restoredRepo := &duckDBRepository{db: targetDB}
	events, err := restoredRepo.QueryEvents(ctx, nostr.Filter{})
	require.NoError(t, err)
	assert.Len(t, events, 6)
}

func TestRestoreRejectsMismatchedManifest(t *testing.T) {
	ctx := context.Background()

	sourceDB, _ := openTempDB(t)
	require.NoError(t, RunMigrations(ctx, sourceDB))
	sourceRepo := &duckDBRepository{db: sourceDB}
	seedEvent(t, ctx, sourceRepo, nil)

	backupDir := filepath.Join(t.TempDir(), "backup")
	_, err := Backup(ctx, sourceDB, backupDir)
	require.NoError(t, err)

	// Tamper with the manifest after the fact to simulate corruption.
	manifestPath := filepath.Join(backupDir, backupManifestFileName)
	require.NoError(t, os.WriteFile(manifestPath, []byte(`{"event_count":999,"tag_count":999}`), 0o644))

	restorePath := filepath.Join(t.TempDir(), "restored.db")
	targetDB, err := sql.Open("duckdb", restorePath)
	require.NoError(t, err)
	defer targetDB.Close()

	_, err = Restore(ctx, targetDB, backupDir)
	assert.Error(t, err, "a manifest mismatch must be reported, not silently accepted")
}
