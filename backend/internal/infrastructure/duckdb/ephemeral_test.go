package duckdb

import (
	"context"
	"testing"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveEventRefusesEphemeral guards the repository itself: the publish
// path never asks it to store an ephemeral event, but any future caller
// that forgets to check must get an error, not a stored row.
func TestSaveEventRefusesEphemeral(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	require.NoError(t, err)
	ev := &nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 20001, Content: "online", Tags: nostr.Tags{{"t", "presence"}}}
	require.NoError(t, ev.Sign(sk))
	wrapped, err := domainevent.NewEvent(ev)
	require.NoError(t, err)

	saved, err := repo.SaveEvent(ctx, wrapped)
	assert.ErrorIs(t, err, domainevent.ErrEphemeral)
	assert.False(t, saved)

	var events, tags int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&events))
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags").Scan(&tags))
	assert.Zero(t, events)
	assert.Zero(t, tags)
}

// TestMigrationPurgesStoredEphemeralEvents builds a database as a pre-0.3.0
// relay left it — ephemeral events stored beside ordinary ones — and checks
// migration 6 removes exactly the ephemeral rows and their tags.
func TestMigrationPurgesStoredEphemeralEvents(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()

	// Schema as of the release before the purge migration.
	require.NoError(t, runMigrationList(ctx, db, migrations[:5]))

	// Inserted directly: SaveEvent now refuses ephemeral kinds.
	kinds := map[string]int{"keep-19999": 19999, "drop-20000": 20000, "drop-20001": 20001, "drop-29999": 29999, "keep-30000": 30000, "keep-1": 1}
	for id, kind := range kinds {
		_, err := db.ExecContext(ctx, "INSERT INTO events (id, pubkey, created_at, kind, content, sig) VALUES (?, 'pk', 1, ?, '', 'sig')", id, kind)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, 't', 'x')", id)
		require.NoError(t, err)
	}

	require.NoError(t, RunMigrations(ctx, db))

	rows, err := db.QueryContext(ctx, "SELECT id FROM events ORDER BY id")
	require.NoError(t, err)
	var remaining []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		remaining = append(remaining, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	assert.Equal(t, []string{"keep-1", "keep-19999", "keep-30000"}, remaining)

	var orphaned int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags WHERE event_id NOT IN (SELECT id FROM events)").Scan(&orphaned))
	assert.Zero(t, orphaned, "an ephemeral event's tag rows must go with it")

	var tagRows int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags").Scan(&tagRows))
	assert.Equal(t, int64(3), tagRows, "tag rows of kept events must survive")

	// Re-running the purge itself is a no-op.
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, purgeEphemeralEvents(ctx, tx))
	require.NoError(t, tx.Commit())
}
