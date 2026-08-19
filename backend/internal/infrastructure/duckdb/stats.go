package duckdb

import (
	"context"
	"fmt"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

// EventStats counts events per period and per kind over a range.
//
// Two grouped queries rather than one: the periods and the kinds are
// different shapes, and a single query producing both would need a rollup
// whose rows the caller would have to sort back out again.
//
// Both share statsConditions, so the counts obey exactly the exclusions a
// read does — an expired or banned event is no more counted than it is
// served (nostrfi/workspace#51). A chart that disagreed with the event
// browser about how many events exist would be worse than no chart.
func (r *Repository) EventStats(ctx context.Context, query domainevent.StatsQuery) (domainevent.Stats, error) {
	unit, err := statsUnit(query.Bucket)
	if err != nil {
		return domainevent.Stats{}, err
	}

	where, args := statsConditions(query)

	// The offset moves the instant before truncation and moves back after,
	// so a "day" is the operator's day rather than the server's. Casting to
	// a naive TIMESTAMP first keeps date_trunc off the session timezone,
	// which would otherwise decide period boundaries invisibly.
	periodSQL := fmt.Sprintf(`
		SELECT CAST(epoch(date_trunc('%s', to_timestamp(e.created_at + ?)::TIMESTAMP)) AS BIGINT) - ? AS period_start,
		       count(*) AS events
		FROM events e
		WHERE %s
		GROUP BY period_start
		ORDER BY period_start
	`, unit, where)

	periodArgs := append([]any{query.OffsetSeconds, query.OffsetSeconds}, args...)
	rows, err := r.db.QueryContext(ctx, periodSQL, periodArgs...)
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
	`, where)

	kindRows, err := r.db.QueryContext(ctx, kindSQL, args...)
	if err != nil {
		return domainevent.Stats{}, err
	}
	defer kindRows.Close()

	for kindRows.Next() {
		var kind domainevent.KindCount
		if err := kindRows.Scan(&kind.Kind, &kind.Count); err != nil {
			return domainevent.Stats{}, err
		}
		stats.Kinds = append(stats.Kinds, kind)
	}
	return stats, kindRows.Err()
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
