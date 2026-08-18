package duckdb

import (
	"context"
	"strconv"
	"testing"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryEventsMatchingContent covers the content substring the operator
// event browser searches on (nostrfi/workspace#36): case-insensitive,
// anywhere in the content, and combining with the rest of the filter rather
// than replacing it.
func TestQueryEventsMatchingContent(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	note := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "Relay operators need VISIBILITY"}
	reaction := nostr.Event{CreatedAt: nostr.Now(), Kind: 7, Content: "visibility, in a reaction"}
	unrelated := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "something else entirely"}
	for _, ev := range []*nostr.Event{&note, &reaction, &unrelated} {
		signAndSave(t, ctx, repo, sk, ev)
	}

	matching := func(t *testing.T, query domainevent.Query) []string {
		t.Helper()
		got, err := repo.QueryEventsMatching(ctx, query)
		require.NoError(t, err)
		ids := make([]string, len(got))
		for i, ev := range got {
			ids[i] = ev.ID
		}
		return ids
	}

	t.Run("matches anywhere in the content, ignoring case", func(t *testing.T) {
		ids := matching(t, domainevent.Query{ContentContains: "visibility"})
		assert.ElementsMatch(t, []string{note.ID, reaction.ID}, ids)
	})

	t.Run("narrows the rest of the filter rather than replacing it", func(t *testing.T) {
		ids := matching(t, domainevent.Query{
			Filter:          nostr.Filter{Kinds: []int{1}},
			ContentContains: "visibility",
		})
		assert.Equal(t, []string{note.ID}, ids)
	})

	t.Run("an empty substring adds no condition", func(t *testing.T) {
		ids := matching(t, domainevent.Query{})
		assert.Len(t, ids, 3)
	})

	// Without escaping, these are LIKE wildcards: "%" would match every
	// event and "_" every single character, so a search that should find
	// nothing would quietly return the whole table.
	t.Run("wildcards in the search text are literal", func(t *testing.T) {
		assert.Empty(t, matching(t, domainevent.Query{ContentContains: "%"}))
		assert.Empty(t, matching(t, domainevent.Query{ContentContains: "n_ed"}))

		literal := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "100% signal, 0_noise"}
		signAndSave(t, ctx, repo, sk, &literal)
		assert.Equal(t, []string{literal.ID}, matching(t, domainevent.Query{ContentContains: "100%"}))
		assert.Equal(t, []string{literal.ID}, matching(t, domainevent.Query{ContentContains: "0_noise"}))
	})

	t.Run("newest first, like every other browse query", func(t *testing.T) {
		older := nostr.Event{CreatedAt: nostr.Now() - 600, Kind: 1, Content: "ordering probe, older"}
		newer := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "ordering probe, newer"}
		signAndSave(t, ctx, repo, sk, &older)
		signAndSave(t, ctx, repo, sk, &newer)

		ids := matching(t, domainevent.Query{ContentContains: "ordering probe"})
		assert.Equal(t, []string{newer.ID, older.ID}, ids)
	})
}

// TestCountEventsCountsWhatIsOnDisk pins the startup count to the whole
// table. It answers "is this the database I filled", so an event that a
// query would exclude must still be counted — otherwise a relay holding
// only expired or banned events would report zero and look like the wrong
// file (nostrfi/workspace#49).
func TestCountEventsCountsWhatIsOnDisk(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	count, err := repo.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count, "a fresh database holds nothing")

	sk := nostr.GeneratePrivateKey()
	visible := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "counted"}
	signAndSave(t, ctx, repo, sk, &visible)

	// Valid when published — its expiration is after its created_at — but
	// both are in the past now, which is the only way to reach that state
	// (SaveEvent refuses an event already expired at publish time).
	expired := nostr.Event{
		CreatedAt: nostr.Now() - 7200,
		Kind:      1,
		Content:   "expired but still on disk",
		Tags:      nostr.Tags{{"expiration", strconv.FormatInt(int64(nostr.Now())-3600, 10)}},
	}
	signAndSave(t, ctx, repo, sk, &expired)

	count, err = repo.CountEvents(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	served, err := repo.QueryEvents(ctx, nostr.Filter{})
	require.NoError(t, err)
	assert.Len(t, served, 1, "the expired event is on disk but not served — the count is not the query")
}
