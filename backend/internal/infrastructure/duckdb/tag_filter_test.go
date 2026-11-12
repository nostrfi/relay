package duckdb

import (
	"context"
	"database/sql"
	"testing"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryEventsMatchingTagConditions covers the operator's tag filter
// (nostrfi/relay#45) at the repository: multi-letter and value-less tags,
// AND across names, OR within one, and the public filter left as it was.
func TestQueryEventsMatchingTagConditions(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	now := nostr.Now()
	tagged := nostr.Event{CreatedAt: now, Kind: 1, Content: "tagged", Tags: nostr.Tags{
		{"t", "nostr"}, {"client", "amethyst"}, {"emoji", "soapbox", "https://example.com/soapbox.png"},
	}}
	signAndSave(t, ctx, repo, sk, &tagged)
	protected := nostr.Event{CreatedAt: now - 1, Kind: 1, Content: "protected", Tags: nostr.Tags{{"-"}, {"t", "bitcoin"}}}
	signAndSave(t, ctx, repo, sk, &protected)
	unlisted := nostr.Event{CreatedAt: now - 2, Kind: 1, Content: "unlisted", Tags: nostr.Tags{{"published_at", "1700000000"}}}
	signAndSave(t, ctx, repo, sk, &unlisted)

	match := func(t *testing.T, conditions map[string][]string) []string {
		t.Helper()
		got, err := repo.QueryEventsMatching(ctx, domainevent.Query{TagConditions: conditions})
		require.NoError(t, err)
		contents := make([]string, len(got))
		for i, ev := range got {
			contents[i] = ev.Content
		}
		return contents
	}

	assert.Equal(t, []string{"tagged"}, match(t, map[string][]string{"client": {"amethyst"}}))
	assert.Equal(t, []string{"tagged"}, match(t, map[string][]string{"emoji": {"soapbox"}}), "matches on the first value")
	assert.Equal(t, []string{"tagged"}, match(t, map[string][]string{"t": {"nostr"}, "client": {"amethyst"}}))
	assert.Empty(t, match(t, map[string][]string{"t": {"bitcoin"}, "client": {"amethyst"}}), "different names must all match")
	assert.Equal(t, []string{"tagged", "protected"}, match(t, map[string][]string{"t": {"nostr", "bitcoin"}}), "values of one name are alternatives")
	assert.Equal(t, []string{"protected"}, match(t, map[string][]string{"-": nil}), "no values means present")
	assert.Equal(t, []string{"tagged"}, match(t, map[string][]string{"client": {}}))
	assert.Empty(t, match(t, map[string][]string{"published_at": nil}), "a tag outside the list is never indexed")

	public, err := repo.QueryEvents(ctx, nostr.Filter{Tags: nostr.TagMap{"client": {"amethyst"}}})
	require.NoError(t, err)
	assert.Empty(t, public, "a public filter must not match a multi-letter tag")

	got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{protected.ID}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, protected.Tags, got[0].Tags, "indexing a value-less tag must not change the served tags")
}

// TestMigrationBackfillsExtendedTagRows covers migration 5: an event stored
// before it gains its allowlisted multi-letter and value-less tag rows from
// tags_json; an event older than tags_json gains nothing; running it again
// changes nothing.
func TestMigrationBackfillsExtendedTagRows(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, runMigrationList(ctx, db, migrations[:4]))

	// Rows as the relay wrote them before this change: tags_json in full,
	// single-letter tags with a value in the index, nothing else.
	const modern = "modern00000000000000000000000000000000000000000000000000000000"
	_, err := db.ExecContext(ctx, `
		INSERT INTO events (id, pubkey, created_at, kind, content, sig, tags_json)
		VALUES (?, 'pk', 1, 1, 'modern', 'sig', ?)
	`, modern, `[["t","nostr"],["client","amethyst"],["-"],["published_at","1"],["e"]]`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, 't', 'nostr')", modern)
	require.NoError(t, err)

	const legacy = "legacy00000000000000000000000000000000000000000000000000000000"
	_, err = db.ExecContext(ctx, "INSERT INTO events (id, pubkey, created_at, kind, content, sig) VALUES (?, 'pk', 1, 1, 'legacy', 'sig')", legacy)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, 'p', 'abc')", legacy)
	require.NoError(t, err)

	require.NoError(t, RunMigrations(ctx, db))

	rows := func(eventID string) map[string]sql.NullString {
		t.Helper()
		r, err := db.QueryContext(ctx, "SELECT tag, value FROM tags WHERE event_id = ?", eventID)
		require.NoError(t, err)
		defer r.Close()
		got := map[string]sql.NullString{}
		for r.Next() {
			var tag string
			var value sql.NullString
			require.NoError(t, r.Scan(&tag, &value))
			got[tag] = value
		}
		require.NoError(t, r.Err())
		return got
	}

	want := map[string]sql.NullString{
		"t":      {String: "nostr", Valid: true},
		"client": {String: "amethyst", Valid: true},
		"-":      {},
		"e":      {},
	}
	assert.Equal(t, want, rows(modern), "allowlisted and value-less tags are indexed; published_at is not")
	assert.Equal(t, map[string]sql.NullString{"p": {String: "abc", Valid: true}}, rows(legacy), "a pre-tags_json event is left as it was")

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, backfillExtendedTagRows(ctx, tx))
	require.NoError(t, tx.Commit())
	assert.Equal(t, want, rows(modern), "running the backfill again must not duplicate rows")

	var count int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM tags WHERE event_id = ?", modern).Scan(&count))
	assert.Equal(t, int64(4), count)
}
