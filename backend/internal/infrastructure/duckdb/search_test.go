package duckdb

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryEventsSearchOrdering pins the ordering NIP-50 search returns
// results in, which README.md documents and which the protocol says must
// not be the usual created_at: earliest occurrence of the term, then
// shortest content, then newest.
func TestQueryEventsSearchOrdering(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	now := nostr.Now()

	// Each pair differs by exactly one ordering key.
	older := nostr.Event{CreatedAt: now - 100, Kind: 1, Content: "orange aaa"}
	newer := nostr.Event{CreatedAt: now - 50, Kind: 1, Content: "orange bbb"}
	longer := nostr.Event{CreatedAt: now - 10, Kind: 1, Content: "orange and then a good deal more text"}
	later := nostr.Event{CreatedAt: now, Kind: 1, Content: "a note mentioning orange near its end"}
	for _, ev := range []*nostr.Event{&older, &newer, &longer, &later} {
		signAndSave(t, ctx, repo, sk, ev)
	}

	got, err := repo.QueryEvents(ctx, nostr.Filter{Search: "orange"})
	require.NoError(t, err)
	contents := make([]string, len(got))
	for i, ev := range got {
		contents[i] = ev.Content
	}
	assert.Equal(t, []string{
		"orange bbb",
		"orange aaa",
		"orange and then a good deal more text",
		"a note mentioning orange near its end",
	}, contents, "position, then length, then recency")
}

// TestQueryEventsSearchIgnoredForSync covers the one path a search term can
// reach without passing the REQ handler's guardrails: NEG-OPEN hands its
// filter straight from the wire to QueryEventsSorted. NIP-77 defines no
// search semantics, and narrowing a reconciliation by an unvalidated
// substring would leave two peers disagreeing about what the other holds,
// so sync reads ignore the field entirely.
func TestQueryEventsSearchIgnoredForSync(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	matching := nostr.Event{CreatedAt: nostr.Now() - 10, Kind: 1, Content: "orange"}
	other := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "lemon"}
	signAndSave(t, ctx, repo, sk, &matching)
	signAndSave(t, ctx, repo, sk, &other)

	sorted, err := repo.QueryEventsSorted(ctx, nostr.Filter{Search: "orange"})
	require.NoError(t, err)
	require.Len(t, sorted, 2, "a sync read must reconcile the whole set, search term or not")
	assert.Equal(t, matching.ID, sorted[0].ID, "and stay in its own created_at ASC order")
	assert.Equal(t, other.ID, sorted[1].ID)

	// The same filter through the REQ path does apply it.
	searched, err := repo.QueryEvents(ctx, nostr.Filter{Search: "orange"})
	require.NoError(t, err)
	require.Len(t, searched, 1)
	assert.Equal(t, matching.ID, searched[0].ID)
}
