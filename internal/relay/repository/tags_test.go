package repository

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signAndSave signs ev with a fresh key (or the given one) and saves it
// through the repository, exactly as the handler would.
func signAndSave(t *testing.T, ctx context.Context, repo *duckDBRepository, sk string, ev *nostr.Event) {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	require.NoError(t, err)
	ev.PubKey = pk
	require.NoError(t, ev.Sign(sk))
	ok, err := repo.SaveEvent(ctx, ev)
	require.NoError(t, err)
	require.True(t, ok)
}

func tagRowCount(t *testing.T, ctx context.Context, db *sql.DB, eventID string) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags WHERE event_id = ?", eventID).Scan(&count))
	return count
}

func TestSaveEventFullTagFidelity(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	sk := nostr.GeneratePrivateKey()
	ev := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      1,
		Content:   "fidelity check",
		Tags: nostr.Tags{
			{"e", "0000000000000000000000000000000000000000000000000000000000000001", "wss://relay.example/", "reply"},
			{"published_at", "1700000000"},
			{"-"},
			{"t", "one"},
			{"t", "two"},
		},
	}
	signAndSave(t, ctx, repo, sk, &ev)

	got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{ev.ID}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ev.Tags, got[0].Tags, "tags must round-trip with every field, in order, including multi-letter and single-element tags")
}

func TestSaveEventLegacyRowFallsBackToTwoFieldTags(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	// Simulate a row written before the tags_json migration: tags_json is
	// left NULL, and only the legacy two-field tags index has data.
	const eventID = "legacyeventid0000000000000000000000000000000000000000000000000"
	_, err := db.ExecContext(ctx, `
		INSERT INTO events (id, pubkey, created_at, kind, content, sig)
		VALUES (?, ?, ?, ?, ?, ?)
	`, eventID, "somepubkey", nostr.Now(), 1, "legacy content", "sig")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, ?, ?)", eventID, "e", "abc")
	require.NoError(t, err)

	got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{eventID}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, nostr.Tags{{"e", "abc"}}, got[0].Tags, "a pre-migration row must still be readable via the legacy two-field path")
}

func TestSaveEventCleansUpOrphanedTags(t *testing.T) {
	ctx := context.Background()

	t.Run("replaceable overwrite", func(t *testing.T) {
		db, _ := openTempDB(t)
		require.NoError(t, RunMigrations(ctx, db))
		repo := &duckDBRepository{db: db}
		sk := nostr.GeneratePrivateKey()

		ev1 := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 0, Content: `{"name":"v1"}`, Tags: nostr.Tags{{"t", "first"}}}
		signAndSave(t, ctx, repo, sk, &ev1)
		ev2 := nostr.Event{CreatedAt: nostr.Now(), Kind: 0, Content: `{"name":"v2"}`, Tags: nostr.Tags{{"t", "second"}}}
		signAndSave(t, ctx, repo, sk, &ev2)

		assert.Equal(t, int64(0), tagRowCount(t, ctx, db, ev1.ID), "the replaced event's tag rows must not survive")
		assert.Equal(t, int64(1), tagRowCount(t, ctx, db, ev2.ID))
	})

	t.Run("parameterized replaceable overwrite", func(t *testing.T) {
		db, _ := openTempDB(t)
		require.NoError(t, RunMigrations(ctx, db))
		repo := &duckDBRepository{db: db}
		sk := nostr.GeneratePrivateKey()

		ev1 := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 30001, Content: "v1", Tags: nostr.Tags{{"d", "slug"}, {"t", "first"}}}
		signAndSave(t, ctx, repo, sk, &ev1)
		ev2 := nostr.Event{CreatedAt: nostr.Now(), Kind: 30001, Content: "v2", Tags: nostr.Tags{{"d", "slug"}, {"t", "second"}}}
		signAndSave(t, ctx, repo, sk, &ev2)

		assert.Equal(t, int64(0), tagRowCount(t, ctx, db, ev1.ID))
		assert.Equal(t, int64(2), tagRowCount(t, ctx, db, ev2.ID))
	})

	t.Run("kind 41 channel metadata replace", func(t *testing.T) {
		db, _ := openTempDB(t)
		require.NoError(t, RunMigrations(ctx, db))
		repo := &duckDBRepository{db: db}
		sk := nostr.GeneratePrivateKey()

		ev40 := nostr.Event{CreatedAt: nostr.Now() - 20, Kind: 40, Content: `{"name":"chan"}`}
		signAndSave(t, ctx, repo, sk, &ev40)

		ev41a := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 41, Content: "v1", Tags: nostr.Tags{{"e", ev40.ID}}}
		signAndSave(t, ctx, repo, sk, &ev41a)
		ev41b := nostr.Event{CreatedAt: nostr.Now(), Kind: 41, Content: "v2", Tags: nostr.Tags{{"e", ev40.ID}}}
		signAndSave(t, ctx, repo, sk, &ev41b)

		assert.Equal(t, int64(0), tagRowCount(t, ctx, db, ev41a.ID), "the superseded kind 41 event's tag rows must not survive")
		assert.Equal(t, int64(1), tagRowCount(t, ctx, db, ev41b.ID))
	})

	t.Run("kind 5 deletion by e tag", func(t *testing.T) {
		db, _ := openTempDB(t)
		require.NoError(t, RunMigrations(ctx, db))
		repo := &duckDBRepository{db: db}
		sk := nostr.GeneratePrivateKey()

		ev1 := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 1, Content: "delete me", Tags: nostr.Tags{{"t", "first"}}}
		signAndSave(t, ctx, repo, sk, &ev1)
		require.Equal(t, int64(1), tagRowCount(t, ctx, db, ev1.ID))

		evDel := nostr.Event{CreatedAt: nostr.Now(), Kind: 5, Content: "", Tags: nostr.Tags{{"e", ev1.ID}}}
		signAndSave(t, ctx, repo, sk, &evDel)

		assert.Equal(t, int64(0), tagRowCount(t, ctx, db, ev1.ID), "the deleted event's tag rows must not survive")
	})

	t.Run("kind 5 deletion by a tag", func(t *testing.T) {
		db, _ := openTempDB(t)
		require.NoError(t, RunMigrations(ctx, db))
		repo := &duckDBRepository{db: db}
		sk := nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(sk)
		require.NoError(t, err)

		ev1 := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 30023, Content: "article", Tags: nostr.Tags{{"d", "slug"}, {"t", "first"}}}
		signAndSave(t, ctx, repo, sk, &ev1)
		require.Equal(t, int64(2), tagRowCount(t, ctx, db, ev1.ID))

		evDel := nostr.Event{CreatedAt: nostr.Now(), Kind: 5, Content: "", Tags: nostr.Tags{{"a", fmt.Sprintf("30023:%s:slug", pk)}}}
		signAndSave(t, ctx, repo, sk, &evDel)

		assert.Equal(t, int64(0), tagRowCount(t, ctx, db, ev1.ID), "the deleted parameterized-replaceable event's tag rows must not survive")
	})
}

// TestSaveEventDuplicatePublishDoesNotDuplicateTags is a regression test:
// republishing an event that already exists (same ID) used to insert its
// tags-index rows again on every call, since the tags-insert loop ran
// unconditionally after an INSERT OR IGNORE that silently no-oped on the
// duplicate. SaveEvent now checks RowsAffected and skips the tags loop
// entirely when the event row wasn't newly inserted.
func TestSaveEventDuplicatePublishDoesNotDuplicateTags(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}
	sk := nostr.GeneratePrivateKey()

	ev := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "republish me", Tags: nostr.Tags{{"t", "dup"}}}
	signAndSave(t, ctx, repo, sk, &ev)
	require.Equal(t, int64(1), tagRowCount(t, ctx, db, ev.ID))

	// Republish the identical, already-signed event (not signAndSave, which
	// would re-sign and mutate CreatedAt/ID).
	ok, err := repo.SaveEvent(ctx, &ev)
	require.NoError(t, err)
	require.True(t, ok, "a duplicate publish must still report success")

	assert.Equal(t, int64(1), tagRowCount(t, ctx, db, ev.ID), "republishing an existing event must not duplicate its tag rows")
}
