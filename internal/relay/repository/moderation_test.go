package repository

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBanPubkeyRoundTrip(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	banned, err := repo.IsPubkeyBanned(ctx, "pk1")
	require.NoError(t, err)
	assert.False(t, banned)

	require.NoError(t, repo.BanPubkey(ctx, "pk1", "spam"))
	banned, err = repo.IsPubkeyBanned(ctx, "pk1")
	require.NoError(t, err)
	assert.True(t, banned)

	entries, err := repo.ListBannedPubkeys(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pk1", entries[0].Value)
	assert.Equal(t, "spam", entries[0].Reason)

	// Banning again updates the reason rather than erroring or duplicating.
	require.NoError(t, repo.BanPubkey(ctx, "pk1", "updated reason"))
	entries, err = repo.ListBannedPubkeys(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "updated reason", entries[0].Reason)

	require.NoError(t, repo.UnbanPubkey(ctx, "pk1"))
	banned, err = repo.IsPubkeyBanned(ctx, "pk1")
	require.NoError(t, err)
	assert.False(t, banned)

	entries, err = repo.ListBannedPubkeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBanEventExcludesFromQuery(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	sk := nostr.GeneratePrivateKey()
	ev := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "hide me"}
	signAndSave(t, ctx, repo, sk, &ev)

	filter := nostr.Filter{IDs: []string{ev.ID}}
	got, err := repo.QueryEvents(ctx, filter)
	require.NoError(t, err)
	require.Len(t, got, 1)

	require.NoError(t, repo.BanEvent(ctx, ev.ID, "reported"))

	got, err = repo.QueryEvents(ctx, filter)
	require.NoError(t, err)
	assert.Empty(t, got, "a banned event must not be returned by queries")

	entries, err := repo.ListBannedEvents(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, ev.ID, entries[0].Value)
	assert.Equal(t, "reported", entries[0].Reason)

	require.NoError(t, repo.AllowEvent(ctx, ev.ID))
	got, err = repo.QueryEvents(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, got, 1, "allowevent must restore visibility")
}

func TestBlockIPRoundTrip(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := context.Background()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &duckDBRepository{db: db}

	require.NoError(t, repo.BlockIP(ctx, "203.0.113.5", "abuse"))
	require.NoError(t, repo.BlockIP(ctx, "198.51.100.0/24", "range block"))

	entries, err := repo.ListBlockedIPs(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	require.NoError(t, repo.UnblockIP(ctx, "203.0.113.5"))
	entries, err = repo.ListBlockedIPs(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "198.51.100.0/24", entries[0].Value)
}
