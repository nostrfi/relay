// Command loadtest drives configurable concurrent WebSocket clients against
// a running relay instance and reports per-scenario latency percentiles and
// throughput, including NIP-50 search scenarios of varying selectivity with
// a concurrent publish workload (workspace #59). It is a manual capacity-baseline tool, not part of the relay
// server or its test suite: run it against a relay you started separately
// (see products/relay/source/README.md), then record its output in
// products/relay/docs/capacity-baseline.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

func main() {
	relayURL := flag.String("url", "ws://localhost:8080", "relay WebSocket URL")
	connections := flag.Int("connections", 50, "concurrent connections for the connection-ramp and sustained-publish scenarios")
	duration := flag.Duration("duration", 10*time.Second, "duration of the sustained-publish scenario")
	rate := flag.Float64("rate", 5, "target events/sec per connection during the sustained-publish scenario")
	subscribers := flag.Int("subscribers", 10, "subscriber connections for the live-fanout scenario")
	fanoutEvents := flag.Int("fanout-events", 200, "events published during the live-fanout scenario")
	negentropyItems := flag.Int("negentropy-items", 1000, "events seeded on the relay before the Negentropy reconciliation scenario")
	searchSeed := flag.Int("search-seed", 5000, "events seeded on the relay before the search scenarios")
	searchers := flag.Int("searchers", 10, "concurrent searcher connections during the search scenarios")
	searchDuration := flag.Duration("search-duration", 15*time.Second, "duration of the concurrent search phase (a sustained-publish workload runs alongside it)")
	dbPath := flag.String("db-path", "", "optional: relay's DuckDB file path, to record database growth across the run")
	outputJSON := flag.String("json", "", "optional path to also write results as JSON")
	flag.Parse()

	env := Environment{
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		NumCPU:    runtime.NumCPU(),
		RelayURL:  *relayURL,
		StartedAt: time.Now().UTC(),
	}

	dbSizeBefore := dbFootprintBytes(*dbPath)

	fmt.Printf("loadtest: connecting to %s\n", *relayURL)

	results := Results{Environment: env}
	fmt.Println("--- connection ramp ---")
	results.ConnectionRamp = runConnectionRamp(*relayURL, *connections)
	printScenario(results.ConnectionRamp)

	fmt.Println("--- sustained publish ---")
	results.SustainedPublish = runSustainedPublish(*relayURL, *connections, *rate, *duration)
	printScenario(results.SustainedPublish)

	fmt.Println("--- live fanout ---")
	results.LiveFanout = runLiveFanout(*relayURL, *subscribers, *fanoutEvents)
	printScenario(results.LiveFanout)

	fmt.Println("--- negentropy full resync ---")
	results.Negentropy = runNegentropy(*relayURL, *negentropyItems)
	printScenario(results.Negentropy)

	fmt.Println("--- search (common / rare / miss, with concurrent publish) ---")
	results.SearchCommon, results.SearchRare, results.SearchMiss, results.PublishDuringSearch =
		runSearch(*relayURL, *searchSeed, *searchers, *searchDuration, *connections, *rate)
	printScenario(results.SearchCommon)
	printScenario(results.SearchRare)
	printScenario(results.SearchMiss)
	printScenario(results.PublishDuringSearch)

	if *dbPath != "" {
		results.DatabaseGrowthBytes = dbFootprintBytes(*dbPath) - dbSizeBefore
		fmt.Printf("--- database growth ---\n%d bytes (%s, including its .wal file)\n", results.DatabaseGrowthBytes, *dbPath)
	}

	if *outputJSON != "" {
		f, err := os.Create(*outputJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write JSON output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode JSON output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("results written to %s\n", *outputJSON)
	}
}

func printScenario(r ScenarioResult) {
	fmt.Printf("attempted=%d succeeded=%d failed=%d p50=%s p95=%s p99=%s max=%s throughput=%.1f/s\n",
		r.Attempted, r.Succeeded, r.Failed, r.P50, r.P95, r.P99, r.Max, r.ThroughputPerSec)
	if r.Notes != "" {
		fmt.Printf("  %s\n", r.Notes)
	}
}

// dbFootprintBytes sums the main DuckDB file and its .wal sidecar: DuckDB
// keeps recent writes in the WAL and only folds them into the main file on
// checkpoint, so measuring the main file alone reports ~0 growth for any
// run shorter than the relay's checkpoint interval (retention.
// purge_interval_seconds, an hour by default).
func dbFootprintBytes(dbPath string) int64 {
	if dbPath == "" {
		return 0
	}
	var total int64
	for _, p := range []string{dbPath, dbPath + ".wal"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

type Environment struct {
	GoVersion string    `json:"go_version"`
	GOOS      string    `json:"goos"`
	GOARCH    string    `json:"goarch"`
	NumCPU    int       `json:"num_cpu"`
	RelayURL  string    `json:"relay_url"`
	StartedAt time.Time `json:"started_at"`
}

type ScenarioResult struct {
	Name             string        `json:"name"`
	Attempted        int           `json:"attempted"`
	Succeeded        int           `json:"succeeded"`
	Failed           int           `json:"failed"`
	P50              time.Duration `json:"p50_ns"`
	P95              time.Duration `json:"p95_ns"`
	P99              time.Duration `json:"p99_ns"`
	Max              time.Duration `json:"max_ns"`
	ThroughputPerSec float64       `json:"throughput_per_sec,omitzero"`
	Notes            string        `json:"notes,omitzero"`
}

type Results struct {
	Environment         Environment    `json:"environment"`
	ConnectionRamp      ScenarioResult `json:"connection_ramp"`
	SustainedPublish    ScenarioResult `json:"sustained_publish"`
	LiveFanout          ScenarioResult `json:"live_fanout"`
	Negentropy          ScenarioResult `json:"negentropy"`
	SearchCommon        ScenarioResult `json:"search_common"`
	SearchRare          ScenarioResult `json:"search_rare"`
	SearchMiss          ScenarioResult `json:"search_miss"`
	PublishDuringSearch ScenarioResult `json:"publish_during_search"`
	DatabaseGrowthBytes int64          `json:"database_growth_bytes,omitzero"`
}
