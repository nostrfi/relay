package duckdb

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
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
	repo, err := NewRepository(filepath.Join(t.TempDir(), "stats.db"))
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	reg := prometheus.NewPedanticRegistry()
	for _, c := range repo.StatsCollectors() {
		require.NoError(t, reg.Register(c))
	}
	families, err := reg.Gather()
	require.NoError(t, err)

	pools := map[string]map[string]bool{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "db_name" {
					if pools[mf.GetName()] == nil {
						pools[mf.GetName()] = map[string]bool{}
					}
					pools[mf.GetName()][l.GetValue()] = true
				}
			}
		}
	}
	for _, want := range []string{"go_sql_open_connections", "go_sql_in_use_connections", "go_sql_wait_count_total", "go_sql_wait_duration_seconds_total", "go_sql_max_idle_time_closed_total"} {
		assert.Equal(t, map[string]bool{"duckdb_query": true, "duckdb_control": true}, pools[want], "%s for both pools", want)
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

// TestNewRepositoryBoundsPools pins the bounds configurePools applies:
// the query pool at two connections per core, the control pool at one,
// each at least minPoolConns.
func TestNewRepositoryBoundsPools(t *testing.T) {
	repo, err := NewRepository(filepath.Join(t.TempDir(), "pool.db"))
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	assert.Equal(t, maxQueryConns(), repo.queryDB.Stats().MaxOpenConnections)
	assert.Equal(t, max(minPoolConns, queryConnsPerCPU*runtime.NumCPU()), maxQueryConns())
	assert.Equal(t, maxControlConns(), repo.db.Stats().MaxOpenConnections)
	assert.Equal(t, max(minPoolConns, runtime.NumCPU()), maxControlConns())
}

// TestControlPathsDoNotQueueBehindQueries is why there are two pools: with
// every query-pool connection held — a search burst — a save, the
// publish path's ban check, the per-connection IP block check and the
// readiness ping must still go straight through (nostrfi/relay#73).
func TestControlPathsDoNotQueueBehindQueries(t *testing.T) {
	repo, err := NewRepository(filepath.Join(t.TempDir(), "split.db"))
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })
	ctx := context.Background()

	for range maxQueryConns() {
		conn, err := repo.queryDB.Conn(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
	}
	require.Equal(t, maxQueryConns(), repo.queryDB.Stats().InUse, "the query pool is saturated")

	// Proof the saturation is real: a query has to wait and times out.
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	_, err = repo.QueryEvents(short, nostr.Filter{Kinds: []int{1}})
	require.ErrorIs(t, err, context.DeadlineExceeded)

	deadline, cancelDeadline := context.WithTimeout(ctx, 2*time.Second)
	defer cancelDeadline()
	signAndSave(t, deadline, repo, nostr.GeneratePrivateKey(), &nostr.Event{Kind: 1, CreatedAt: nostr.Now(), Content: "published during a burst"})
	_, err = repo.IsPubkeyBanned(deadline, "somepubkey")
	require.NoError(t, err)
	_, err = repo.ListBlockedIPs(deadline)
	require.NoError(t, err)
	require.NoError(t, repo.Ping(deadline))
	require.NoError(t, deadline.Err())
}

// TestRepositoryCloseClosesBothPools checks the shared database is closed
// once, by its owner, after the query pool.
func TestRepositoryCloseClosesBothPools(t *testing.T) {
	repo, err := NewRepository(filepath.Join(t.TempDir(), "close.db"))
	require.NoError(t, err)
	require.NoError(t, repo.Ping(context.Background()))
	require.NoError(t, repo.Close())
	assert.Error(t, repo.queryDB.Ping(), "query pool closed")
	assert.Error(t, repo.db.Ping(), "control pool closed")
}

// TestNewRepositoryMemoryLimit checks storage.memory_limit reaches DuckDB:
// set, it is DuckDB's memory_limit; unset, DuckDB keeps its own default; a
// value DuckDB rejects fails the open, so a typo stops the relay at startup
// instead of leaving it on the default.
func TestNewRepositoryMemoryLimit(t *testing.T) {
	setting := func(t *testing.T, repo *Repository) string {
		t.Helper()
		var v string
		require.NoError(t, repo.db.QueryRowContext(context.Background(), "SELECT current_setting('memory_limit')").Scan(&v))
		return v
	}

	t.Run("set", func(t *testing.T) {
		repo, err := NewRepositoryWithOptions(filepath.Join(t.TempDir(), "limited.db"), Options{MemoryLimit: "256MB"})
		require.NoError(t, err)
		t.Cleanup(func() { repo.Close() })
		// DuckDB reports the limit in its own units (256MB is 244.1 MiB).
		assert.Equal(t, "244.1 MiB", setting(t, repo))
	})

	t.Run("unset keeps DuckDB's default", func(t *testing.T) {
		limited, err := NewRepositoryWithOptions(filepath.Join(t.TempDir(), "limited.db"), Options{MemoryLimit: "256MB"})
		require.NoError(t, err)
		t.Cleanup(func() { limited.Close() })
		repo, err := NewRepository(filepath.Join(t.TempDir(), "default.db"))
		require.NoError(t, err)
		t.Cleanup(func() { repo.Close() })
		assert.NotEqual(t, setting(t, limited), setting(t, repo))
	})

	t.Run("an invalid value fails the open", func(t *testing.T) {
		_, err := NewRepositoryWithOptions(filepath.Join(t.TempDir(), "bad.db"), Options{MemoryLimit: "lots"})
		require.Error(t, err)
	})
}
