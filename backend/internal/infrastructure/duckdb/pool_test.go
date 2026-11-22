package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatsCollectorReportsPool pins the go_sql_* series the relay
// registers for its DuckDB pool (nostrfi/relay#73): an operator watching a
// pool bound needs open, in-use and wait figures, labelled for this pool.
func TestStatsCollectorReportsPool(t *testing.T) {
	db, _ := openTempDB(t)
	require.NoError(t, RunMigrations(context.Background(), db))
	repo := &Repository{db: db}

	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(repo.StatsCollector()))
	families, err := reg.Gather()
	require.NoError(t, err)

	names := map[string]string{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "db_name" {
					names[mf.GetName()] = l.GetValue()
				}
			}
		}
	}
	for _, want := range []string{"go_sql_open_connections", "go_sql_in_use_connections", "go_sql_wait_count_total", "go_sql_wait_duration_seconds_total", "go_sql_max_idle_time_closed_total"} {
		assert.Equal(t, "duckdb", names[want], "%s labelled db_name=duckdb", want)
	}
}

// insertLegacyEvent writes a row the way the relay did before the
// tags_json migration: tags_json NULL, tags only in the two-field index,
// so reading it takes the getLegacyTags fallback.
func insertLegacyEvent(t *testing.T, db *sql.DB, eventID string) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
		INSERT INTO events (id, pubkey, created_at, kind, content, sig)
		VALUES (?, ?, ?, ?, ?, ?)
	`, eventID, "somepubkey", nostr.Now(), 1, "legacy content", "sig")
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, ?, ?)", eventID, "e", "abc")
	require.NoError(t, err)
}

// TestQueryEventsLegacyTagsWithOneConnection pins that reading a legacy
// row needs only one pooled connection. queryEvents used to fetch legacy
// tags while still iterating its result set, taking a second connection
// for each such row: with the pool bounded at N, N concurrent REQs over
// legacy rows would each hold one and wait forever for another
// (nostrfi/relay#73).
func TestQueryEventsLegacyTagsWithOneConnection(t *testing.T) {
	db, _ := openTempDB(t)
	require.NoError(t, RunMigrations(context.Background(), db))
	repo := &Repository{db: db}
	ids := []string{
		"legacy1000000000000000000000000000000000000000000000000000000001",
		"legacy2000000000000000000000000000000000000000000000000000000002",
	}
	for _, id := range ids {
		insertLegacyEvent(t, db, id)
	}
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: ids})
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, ev := range got {
		assert.Equal(t, nostr.Tags{{"e", "abc"}}, ev.Tags, "event %s", ev.ID)
	}
	require.NoError(t, ctx.Err(), "the query had to wait for a second connection")
}

// TestQueryEventsConcurrentAtOneConnection runs two legacy reads at once
// through a single-connection pool: the second must queue behind the
// first, not deadlock against it.
func TestQueryEventsConcurrentAtOneConnection(t *testing.T) {
	db, _ := openTempDB(t)
	require.NoError(t, RunMigrations(context.Background(), db))
	repo := &Repository{db: db}
	const id = "legacy3000000000000000000000000000000000000000000000000000000003"
	insertLegacyEvent(t, db, id)
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			got, err := repo.QueryEvents(ctx, nostr.Filter{IDs: []string{id}})
			if err == nil && (len(got) != 1 || len(got[0].Tags) != 1) {
				err = fmt.Errorf("got %d events, tags %v", len(got), got)
			}
			errs <- err
		}()
	}
	for range 2 {
		require.NoError(t, <-errs)
	}
	require.NoError(t, ctx.Err())
}
