package duckdb

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQueryEventsPrefixFilter covers NIP-01 prefix matching on "ids" and
// "authors": a filter value shorter than the full 64-character hex id/pubkey
// matches any event whose id/pubkey starts with it; a full-length value
// matches only exactly.
func TestQueryEventsPrefixFilter(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	ev := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "prefix me"}
	signAndSave(t, ctx, repo, sk, &ev)

	t.Run("id prefix matches", func(t *testing.T) {
		got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{ev.ID[:8]}})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, ev.ID, got[0].ID)
	})

	t.Run("author prefix matches", func(t *testing.T) {
		got, err := repo.QueryEvents(ctx, nostr.Filter{Authors: []string{ev.PubKey[:12]}})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, ev.ID, got[0].ID)
	})

	t.Run("full-length id still matches exactly", func(t *testing.T) {
		got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{ev.ID}})
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, ev.ID, got[0].ID)
	})

	t.Run("mismatched prefix matches nothing", func(t *testing.T) {
		got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{"deadbeef"}})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("mixed prefix and full-length values in one filter", func(t *testing.T) {
		other := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "unrelated"}
		signAndSave(t, ctx, repo, nostr.GeneratePrivateKey(), &other)

		got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{ev.ID[:6], other.ID}})
		require.NoError(t, err)
		gotIDs := []string{got[0].ID}
		if len(got) > 1 {
			gotIDs = append(gotIDs, got[1].ID)
		}
		assert.Len(t, got, 2)
		assert.Contains(t, gotIDs, ev.ID)
		assert.Contains(t, gotIDs, other.ID)
	})
}
