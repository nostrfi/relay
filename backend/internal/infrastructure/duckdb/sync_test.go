package duckdb

import (
	"bytes"
	"cmp"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncProjection is what QuerySyncItems should return for a filter: the
// REQ path's answer reduced to (id, created_at) and put in NIP-77 order.
func syncProjection(events []*domainevent.Event) []domainevent.SyncItem {
	items := make([]domainevent.SyncItem, len(events))
	for i, ev := range events {
		items[i] = domainevent.SyncItem{ID: ev.ID, CreatedAt: ev.CreatedAt}
	}
	slices.SortFunc(items, func(a, b domainevent.SyncItem) int {
		return cmp.Or(cmp.Compare(a.CreatedAt, b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return items
}

// TestQuerySyncItemsMatchesQueryEvents pins the sync read to the REQ read:
// for every filter shape, the (id, created_at) set a sync reconciles is the
// set a REQ would serve, expired and banned events excluded from both
// (nostrfi/relay#70).
func TestQuerySyncItemsMatchesQueryEvents(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := t.Context()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	alice := nostr.GeneratePrivateKey()
	bob := nostr.GeneratePrivateKey()
	now := nostr.Now()

	root := nostr.Event{CreatedAt: now - 100, Kind: 1, Content: "root"}
	signAndSave(t, ctx, repo, alice, &root)
	reply := nostr.Event{CreatedAt: now - 50, Kind: 1, Content: "reply", Tags: nostr.Tags{{"e", root.ID}}}
	signAndSave(t, ctx, repo, bob, &reply)
	reaction := nostr.Event{CreatedAt: now - 50, Kind: 7, Content: "+", Tags: nostr.Tags{{"e", root.ID}}}
	signAndSave(t, ctx, repo, alice, &reaction)
	later := nostr.Event{CreatedAt: now - 10, Kind: 1, Content: "later"}
	signAndSave(t, ctx, repo, bob, &later)

	expired := nostr.Event{
		CreatedAt: now - 7200,
		Kind:      1,
		Content:   "expired",
		Tags:      nostr.Tags{{"expiration", strconv.FormatInt(int64(now)-3600, 10)}},
	}
	signAndSave(t, ctx, repo, alice, &expired)
	banned := nostr.Event{CreatedAt: now - 20, Kind: 1, Content: "banned"}
	signAndSave(t, ctx, repo, bob, &banned)
	require.NoError(t, repo.BanEvent(ctx, banned.ID, "test"))

	since := now - 60
	until := now - 20
	filters := map[string]nostr.Filter{
		"empty":         {},
		"kinds":         {Kinds: []int{1}},
		"author":        {Authors: []string{root.PubKey}},
		"author prefix": {Authors: []string{reply.PubKey[:8]}},
		"id prefix":     {IDs: []string{later.ID[:10]}},
		"tag":           {Tags: nostr.TagMap{"e": {root.ID}}},
		"since/until":   {Since: &since, Until: &until},
		"combined":      {Kinds: []int{1, 7}, Tags: nostr.TagMap{"e": {root.ID}}, Since: &since},
	}
	for name, filter := range filters {
		t.Run(name, func(t *testing.T) {
			stored, err := repo.QueryEvents(ctx, filter)
			require.NoError(t, err)
			synced, err := repo.QuerySyncItems(ctx, filter)
			require.NoError(t, err)
			assert.Equal(t, syncProjection(stored), synced)
		})
	}

	all, err := repo.QuerySyncItems(ctx, nostr.Filter{})
	require.NoError(t, err)
	ids := make([]string, len(all))
	for i, item := range all {
		ids[i] = item.ID
	}
	assert.NotContains(t, ids, expired.ID)
	assert.NotContains(t, ids, banned.ID)
	assert.Len(t, ids, 4)
}

// TestQuerySyncItemsLimitKeepsOldest documents the one place the two reads
// differ: a sync is ordered oldest first, so a limit keeps the oldest
// events where a REQ keeps the newest.
func TestQuerySyncItemsLimitKeepsOldest(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := t.Context()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	sk := nostr.GeneratePrivateKey()
	var saved []nostr.Event
	for i := range 3 {
		ev := nostr.Event{CreatedAt: nostr.Now() - nostr.Timestamp(30-i*10), Kind: 1, Content: strconv.Itoa(i)}
		signAndSave(t, ctx, repo, sk, &ev)
		saved = append(saved, ev)
	}

	items, err := repo.QuerySyncItems(ctx, nostr.Filter{Limit: 2})
	require.NoError(t, err)
	require.Len(t, items, 2)
	assert.Equal(t, saved[0].ID, items[0].ID)
	assert.Equal(t, saved[1].ID, items[1].ID)
}

// TestSyncQuerySelectsOnlyIDAndCreatedAt pins the point of the sync read:
// it never touches content, sig or tags_json.
func TestSyncQuerySelectsOnlyIDAndCreatedAt(t *testing.T) {
	statement, _ := syncQuery(nostr.Filter{Kinds: []int{1}, Search: "orange", Limit: 10})

	selectList, _, found := strings.Cut(strings.TrimPrefix(statement, "SELECT "), " FROM ")
	require.True(t, found, statement)
	assert.Equal(t, "e.id, e.created_at", selectList)
	for _, column := range []string{"content", "sig", "tags_json"} {
		assert.NotContains(t, statement, "e."+column, "the sync statement must not reference %s", column)
	}
	assert.Contains(t, statement, "ORDER BY e.created_at ASC, e.id ASC")
	assert.True(t, strings.HasSuffix(statement, " LIMIT 10"), statement)
}

// TestQuerySyncItemsSkipsTagReconstruction proves no tags are rebuilt for
// a sync: a row whose tags_json cannot be parsed still syncs, without the
// parse failure (and legacy fallback query) the REQ path goes through.
func TestQuerySyncItemsSkipsTagReconstruction(t *testing.T) {
	db, _ := openTempDB(t)
	ctx := t.Context()
	require.NoError(t, RunMigrations(ctx, db))
	repo := &Repository{db: db}

	ev := nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "hi", Tags: nostr.Tags{{"t", "x"}}}
	signAndSave(t, ctx, repo, nostr.GeneratePrivateKey(), &ev)
	_, err := db.ExecContext(ctx, "UPDATE events SET tags_json = 'not json' WHERE id = ?", ev.ID)
	require.NoError(t, err)

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)

	items, err := repo.QuerySyncItems(ctx, nostr.Filter{})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, ev.ID, items[0].ID)
	assert.Equal(t, ev.CreatedAt, items[0].CreatedAt)
	assert.NotContains(t, logs.String(), "tags_json", "a sync read must not parse tags")

	// The REQ path does parse them, which is what makes the assertion
	// above meaningful.
	_, err = repo.QueryEvents(ctx, nostr.Filter{})
	require.NoError(t, err)
	assert.Contains(t, logs.String(), "failed to unmarshal tags_json")
}
