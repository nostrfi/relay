package duckdb

import (
	"context"
	"fmt"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

// maxStatsKinds bounds the kind breakdown. Nothing validates the kind range
// on publish, so a relay can hold arbitrarily many distinct kinds and an
// unbounded GROUP BY would grow the response in proportion to what strangers
// have published. Everything past the cap is summed into OtherKinds, so the
// total still adds up.
const maxStatsKinds = 16

// EventStats counts events per period and per kind over a range.
//
// Both aggregations run inside one read transaction. Separately, an event
// committed between them would land in the kind breakdown but not in the
// periods, so the shares and the headline total would disagree by one and
// nothing would say why.
//
// They share statsConditions, so the counts obey exactly the exclusions a
// read does — an expired or banned event is no more counted than it is
// served (nostrfi/workspace#51). A chart that disagreed with the event
// browser about how many events exist would be worse than no chart.
func (r *Repository) EventStats(ctx context.Context, query domainevent.StatsQuery) (domainevent.Stats, error) {
	unit, err := statsUnit(query.Bucket)
	if err != nil {
		return domainevent.Stats{}, err
	}

	// A plain transaction, not a read-only one: DuckDB's driver rejects
	// sql.TxOptions{ReadOnly: true}. The snapshot is what matters here, and
	// nothing in this function writes.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domainevent.Stats{}, err
	}
	defer tx.Rollback()

	where, args := statsConditions(query)

	// The offset moves the instant before truncation and moves back after,
	// so a "day" is the operator's day rather than the server's.
	//
	// AT TIME ZONE 'UTC', not a cast to TIMESTAMP: the cast converts the
	// instant into the *database session's* local wall clock, so a relay
	// running with TZ=America/New_York would bucket 2026-03-11T00:30Z under
	// March 10 — the server's timezone silently added to the operator's
	// offset. Naming UTC makes the truncation independent of where the relay
	// happens to run.
	periodSQL := fmt.Sprintf(`
		SELECT CAST(epoch(date_trunc('%s', to_timestamp(e.created_at + ?) AT TIME ZONE 'UTC')) AS BIGINT) - ? AS period_start,
		       count(*) AS events
		FROM events e
		WHERE %s
		GROUP BY period_start
		ORDER BY period_start
	`, unit, where)

	periodArgs := append([]any{query.OffsetSeconds, query.OffsetSeconds}, args...)
	rows, err := tx.QueryContext(ctx, periodSQL, periodArgs...)
	if err != nil {
		return domainevent.Stats{}, err
	}
	defer rows.Close()

	stats := domainevent.Stats{}
	for rows.Next() {
		var period domainevent.StatsPeriod
		if err := rows.Scan(&period.Start, &period.Count); err != nil {
			return domainevent.Stats{}, err
		}
		stats.Periods = append(stats.Periods, period)
		stats.Total += period.Count
	}
	if err := rows.Err(); err != nil {
		return domainevent.Stats{}, err
	}

	kindSQL := fmt.Sprintf(`
		SELECT e.kind, count(*) AS events
		FROM events e
		WHERE %s
		GROUP BY e.kind
		ORDER BY events DESC, e.kind ASC
		LIMIT %d
	`, where, maxStatsKinds)

	kindRows, err := tx.QueryContext(ctx, kindSQL, args...)
	if err != nil {
		return domainevent.Stats{}, err
	}
	defer kindRows.Close()

	var counted int64
	for kindRows.Next() {
		var kind domainevent.KindCount
		if err := kindRows.Scan(&kind.Kind, &kind.Count); err != nil {
			return domainevent.Stats{}, err
		}
		stats.Kinds = append(stats.Kinds, kind)
		counted += kind.Count
	}
	if err := kindRows.Err(); err != nil {
		return domainevent.Stats{}, err
	}

	// Whatever the cap left out, so the breakdown still accounts for every
	// event the periods counted.
	stats.OtherKinds = stats.Total - counted

	return stats, tx.Commit()
}

// statsConditions is the range and the exclusions every statistics query
// shares, so the periods and the kinds can never count different rows.
func statsConditions(query domainevent.StatsQuery) (string, []any) {
	return `e.created_at >= ? AND e.created_at <= ?
			AND (e.expiration IS NULL OR e.expiration > ?)
			AND e.id NOT IN (SELECT event_id FROM banned_events)`,
		[]any{int64(query.Since), int64(query.Until), int64(nostr.Now())}
}

// statsUnit maps the granularity onto date_trunc's unit, refusing anything
// else: the unit is interpolated into SQL, so it may only ever be one of
// these four literals.
func statsUnit(bucket domainevent.StatsBucket) (string, error) {
	switch bucket {
	case domainevent.StatsBucketHour, domainevent.StatsBucketDay,
		domainevent.StatsBucketWeek, domainevent.StatsBucketMonth:
		return string(bucket), nil
	default:
		return "", fmt.Errorf("duckdb: unsupported stats bucket %q", bucket)
	}
}
