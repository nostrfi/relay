package duckdb

import (
	"context"
	"testing"

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
