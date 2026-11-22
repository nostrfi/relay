// Package duckdb is the DuckDB implementation of the domain repository
// ports (event.Repository, moderation.Repository): it converts explicitly
// between domain entities and DB rows/params at its exported methods, with
// the query-building and row-scanning logic beneath that boundary working
// in terms of the raw *nostr.Event/nostr.Filter types it always has.
package duckdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"runtime"
	"strings"
	"time"

	domainevent "relay/internal/domain/event"

	duckdbdriver "github.com/duckdb/duckdb-go/v2"
	"github.com/nbd-wtf/go-nostr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Repository is the DuckDB-backed implementation of both event.Repository
// and moderation.Repository.
//
// It holds two connection pools on one DuckDB database (nostrfi/relay#73).
// queryDB serves the long, scan-shaped queries a burst is made of — REQ,
// sync, the events API, stats — and is bounded. db, the control pool,
// serves everything else: saves and the publish path's ban check, the
// per-connection IP block check, readiness, moderation and admin calls,
// maintenance and migrations. Splitting them keeps a publish, a new
// connection or a readiness probe from queuing behind searches.
type Repository struct {
	db      *sql.DB
	queryDB *sql.DB
}

// queries returns the query pool. A Repository built directly around one
// *sql.DB, as package tests do, uses it for both.
func (r *Repository) queries() *sql.DB {
	if r.queryDB != nil {
		return r.queryDB
	}
	return r.db
}

// Options are the operator-tunable settings applied when the database is
// opened.
type Options struct {
	// MemoryLimit is DuckDB's memory_limit (for example "512MB"), the
	// ceiling on its buffer manager: cached table data and the intermediate
	// results it can spill to disk. It belongs to the database, so both
	// pools share it. It does not bound what queries allocate outside the
	// buffer manager, nor the Go side of each running query, which is what
	// the query pool's bound limits. Empty leaves DuckDB's default of 80%
	// of system RAM.
	MemoryLimit string
}

// The pool bounds, fixed rather than configurable (nostrfi/relay#73). See
// configurePools for the measurements behind them.
const (
	minPoolConns     = 4
	queryConnsPerCPU = 2
	maxConnIdleTime  = 5 * time.Minute
)

// maxQueryConns caps the query pool. DuckDB runs every query on one thread
// pool shared by the whole database (threads defaults to the core count),
// so connections beyond a small multiple of the cores queue inside DuckDB
// rather than add throughput — and each running query holds memory.
func maxQueryConns() int {
	return max(minPoolConns, queryConnsPerCPU*runtime.NumCPU())
}

// maxControlConns caps the control pool at one connection per core. Its
// queries are short point lookups and single-event writes, but every
// publish makes two of them, so too small a pool becomes the publish
// path's bottleneck: four connections left a burst's publishes close to
// a client's five-second acknowledgement window.
func maxControlConns() int {
	return max(minPoolConns, runtime.NumCPU())
}

// configurePools bounds both pools. Measured with the loadtest battery,
// whose NIP-50 search phase is the burst (100 concurrent searchers plus 50
// unthrottled publishers, 20,000 seeded events), on 16 CPUs, two runs per
// configuration; the PR has the full figures:
//
//   - Unbounded, one pool: up to 150 open connections, peak RSS 918–1,013
//     MiB, and database/sql's default of two idle connections closed and
//     reopened connections about 6,000 times per run.
//   - One pool capped at 32: peak RSS 433–539 MiB, but saves queued behind
//     searches holding connections for seconds, publishes overran the
//     loadtest's five-second acknowledgement window, and the search phase
//     aborted. Hence the separate control pool.
//   - Query pool 32, control pool 16 (these constants): peak RSS 601–606
//     MiB; publish p99 during the burst 1.9–2.4s, against 2.5–3.0s
//     unbounded; search p99 3.6–4.2s against 2.3–2.9s, with up to 1% of
//     searches answered CLOSED by the search work budget. Searches queue
//     for a connection instead of all running at once: the price of the
//     memory bound, paid by the heaviest query rather than by publishing.
//
// Idle connections are kept up to each bound, so a burst does not close
// and reopen connections as it ebbs and flows, and closed after
// maxConnIdleTime, so a quiet relay gives back what a burst opened. An
// in-process DuckDB connection never goes stale, so there is no lifetime
// cap. Waiting callers queue under their own context: a REQ stops waiting
// on disconnect, and a search's wait counts against its work budget.
func configurePools(control, query *sql.DB) {
	q := maxQueryConns()
	query.SetMaxOpenConns(q)
	query.SetMaxIdleConns(q)
	query.SetConnMaxIdleTime(maxConnIdleTime)

	c := maxControlConns()
	control.SetMaxOpenConns(c)
	control.SetMaxIdleConns(c)
	control.SetConnMaxIdleTime(maxConnIdleTime)
}

// dsn builds the DuckDB data source name: the database path, with any
// settings as query parameters, which duckdb-go applies as database
// configuration when it opens the file.
func dsn(path string, opts Options) string {
	if opts.MemoryLimit == "" {
		return path
	}
	return path + "?" + url.Values{"memory_limit": {opts.MemoryLimit}}.Encode()
}

// sharedConnector hands the query pool the control pool's connector without
// its Close: sql.DB.Close closes a connector that implements io.Closer, and
// closing the query pool must not close the database under the control
// pool. The control pool owns the database and closes it last.
type sharedConnector struct{ driver.Connector }

func NewRepository(path string) (*Repository, error) {
	return NewRepositoryWithOptions(path, Options{})
}

// NewRepositoryWithOptions opens the database at path with opts applied,
// opens its two bounded pools, and runs any pending migrations.
func NewRepositoryWithOptions(path string, opts Options) (*Repository, error) {
	connector, err := duckdbdriver.NewConnector(dsn(path, opts), nil)
	if err != nil {
		return nil, err
	}
	control := sql.OpenDB(connector)
	query := sql.OpenDB(sharedConnector{connector})
	configurePools(control, query)

	if err := RunMigrations(context.Background(), control); err != nil {
		query.Close()
		control.Close()
		return nil, err
	}

	return &Repository{db: control, queryDB: query}, nil
}

// StatsCollectors expose each pool's database/sql statistics as go_sql_*
// metrics, labelled db_name="duckdb_query" and db_name="duckdb_control":
// open, in-use and idle connections, how often and how long callers
// waited for one, and how many were closed for idling. They are how a
// pool bound is seen working — or seen starving callers — in production
// (nostrfi/relay#73).
func (r *Repository) StatsCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		collectors.NewDBStatsCollector(r.queries(), "duckdb_query"),
		collectors.NewDBStatsCollector(r.db, "duckdb_control"),
	}
}

// CountEvents returns how many events the database holds, expired and banned
// ones included: this is what is on disk, not what a query would serve.
//
// Used at startup so the relay says which database it opened and what is in
// it. An operator whose dashboard shows nothing needs to tell "the relay has
// no such events" apart from "the relay is reading a different file than the
// one I filled" — and nothing said which (nostrfi/workspace#49).
func (r *Repository) CountEvents(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// SaveEvent unwraps ev to the raw *nostr.Event the transactional save logic
// below operates on. That logic runs entirely inside one transaction: every
// branch that deletes or replaces an event also removes that event's tag
// rows in the same transaction, so a failure partway through never leaves
// orphaned tags or a half-applied replace/delete.
//
// Ephemeral events (NIP-01, kinds 20000–29999) are refused with
// domainevent.ErrEphemeral: the publish path broadcasts them without
// saving, and this guard keeps any other caller from persisting them.
func (r *Repository) SaveEvent(ctx context.Context, ev *domainevent.Event) (bool, error) {
	event := ev.Event
	if domainevent.IsEphemeral(event.Kind) {
		return false, domainevent.ErrEphemeral
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	saved, err := saveEventTx(ctx, tx, event)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return saved, nil
}

func saveEventTx(ctx context.Context, tx *sql.Tx, event *nostr.Event) (bool, error) {
	// Handle replaceable and addressable events
	if (event.Kind >= 10000 && event.Kind < 20000) || event.Kind == 0 || event.Kind == 3 {
		if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
			return false, err
		}

		var count int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
			event.PubKey, event.Kind, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	} else if event.Kind == 41 {
		// NIP-28: Kind 41 - Set channel metadata
		// "Only the most recent kind 41 per 'e' tag value MAY be available."
		eTag := ""
		for _, tag := range event.Tags {
			if len(tag) > 1 && tag[0] == "e" {
				eTag = tag[1]
				break
			}
		}

		if eTag != "" {
			if _, err := deleteMatchingEvents(ctx, tx, `
				kind = 41
				AND id IN (SELECT event_id FROM tags WHERE tag = 'e' AND value = ?)
				AND (created_at < ? OR (created_at = ? AND id > ?))
			`, eTag, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
				return false, err
			}

			var count int
			err := tx.QueryRowContext(ctx, `
				SELECT count(*) FROM events
				WHERE kind = 41
				AND id IN (SELECT event_id FROM tags WHERE tag = 'e' AND value = ?)
				AND (created_at > ? OR (created_at = ? AND id <= ?))
			`, eTag, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
			if err != nil {
				return false, err
			}
			if count > 0 {
				return true, nil
			}
		}
	} else if event.Kind >= 30000 && event.Kind < 40000 {
		dTag := ""
		for _, tag := range event.Tags {
			if len(tag) > 1 && tag[0] == "d" {
				dTag = tag[1]
				break
			}
		}
		if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND d_tag = ? AND (created_at < ? OR (created_at = ? AND id > ?))",
			event.PubKey, event.Kind, dTag, event.CreatedAt, event.CreatedAt, event.ID); err != nil {
			return false, err
		}

		var count int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM events WHERE pubkey = ? AND kind = ? AND d_tag = ? AND (created_at > ? OR (created_at = ? AND id <= ?))",
			event.PubKey, event.Kind, dTag, event.CreatedAt, event.CreatedAt, event.ID).Scan(&count)
		if err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}

	if event.Kind == 5 {
		for _, tag := range event.Tags {
			if len(tag) < 2 {
				continue
			}
			if tag[0] == "e" {
				targetID := tag[1]
				if _, err := deleteMatchingEvents(ctx, tx, "id = ? AND pubkey = ?", targetID, event.PubKey); err != nil {
					return false, fmt.Errorf("failed to delete event by e tag %q: %w", targetID, err)
				}
			} else if tag[0] == "a" {
				parts := strings.Split(tag[1], ":")
				if len(parts) >= 2 {
					kind := parts[0]
					pubkey := parts[1]
					dTag := ""
					if len(parts) >= 3 {
						dTag = parts[2]
					}

					if pubkey == event.PubKey {
						if dTag != "" {
							if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND d_tag = ? AND created_at <= ?",
								pubkey, kind, dTag, event.CreatedAt); err != nil {
								return false, fmt.Errorf("failed to delete event by a tag %q: %w", tag[1], err)
							}
						} else {
							if _, err := deleteMatchingEvents(ctx, tx, "pubkey = ? AND kind = ? AND created_at <= ?",
								pubkey, kind, event.CreatedAt); err != nil {
								return false, fmt.Errorf("failed to delete event by a tag %q: %w", tag[1], err)
							}
						}
					}
				}
			}
		}
	}

	dTag := sql.NullString{}
	expiration := sql.NullInt64{}
	for _, tag := range event.Tags {
		if len(tag) > 1 {
			if tag[0] == "d" {
				dTag.String = tag[1]
				dTag.Valid = true
			}
		}
	}
	expiration.Int64, expiration.Valid = domainevent.Expiration(event)

	// NIP-40: Relays SHOULD drop any events that are published to them if they are expired.
	if domainevent.ExpiredOnArrival(event) {
		return false, fmt.Errorf("event already expired")
	}

	tagsJSON, err := json.Marshal(event.Tags)
	if err != nil {
		return false, fmt.Errorf("failed to marshal tags: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, content, sig, d_tag, expiration, tags_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.PubKey, event.CreatedAt, event.Kind, event.Content, event.Sig, dTag, expiration, string(tagsJSON))
	if err != nil {
		return false, err
	}

	// A duplicate publish of an event already in storage is not an error —
	// report success as usual — but its tags index rows are already there
	// too, so inserting them again would duplicate them on every republish.
	inserted, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if inserted == 0 {
		return true, nil
	}

	// This index serves tag filters, which match on a tag's name and first
	// value alone — full tag fidelity for served events comes from
	// tags_json above, not from this table. It holds NIP-01's single-letter
	// tags (`#e`, `#p`, ...) plus the operator's allowlisted tags
	// (domainevent.IndexedTag decides which).
	for _, tag := range event.Tags {
		if err := insertTagRow(ctx, tx, event.ID, tag); err != nil {
			slog.Error("failed to insert tag", "event_id", event.ID, "tag", tag[0], "error", err)
		}
	}

	return true, nil
}

// insertTagRow indexes one tag of an event, when domainevent.IndexedTag
// says it is indexed. A value-less tag is stored with a NULL value: a
// presence filter finds it by name, and no value filter can ever match it.
func insertTagRow(ctx context.Context, tx *sql.Tx, eventID string, tag nostr.Tag) error {
	name, value, hasValue, ok := domainevent.IndexedTag(tag)
	if !ok {
		return nil
	}
	stored := sql.NullString{String: value, Valid: hasValue}
	_, err := tx.ExecContext(ctx, "INSERT INTO tags (event_id, tag, value) VALUES (?, ?, ?)", eventID, name, stored)
	return err
}

// deleteMatchingEvents deletes every event matching whereClause, along with
// its tag rows, in two IN-list statements rather than a subquery on tags
// nested inside a delete from tags (which would self-reference the table
// being deleted from). Returns the number of events deleted.
func deleteMatchingEvents(ctx context.Context, tx *sql.Tx, whereClause string, args ...any) (int64, error) {
	ids, err := selectEventIDs(ctx, tx, "SELECT id FROM events WHERE "+whereClause, args...)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}

	idArgs := make([]any, len(ids))
	for i, id := range ids {
		idArgs[i] = id
	}
	ph := placeholders(len(ids))

	if _, err := tx.ExecContext(ctx, "DELETE FROM tags WHERE event_id IN ("+ph+")", idArgs...); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE id IN ("+ph+")", idArgs...); err != nil {
		return 0, err
	}
	return int64(len(ids)), nil
}

func selectEventIDs(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *Repository) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*domainevent.Event, error) {
	events, err := r.queryEvents(ctx, domainevent.Query{Filter: filter})
	if err != nil {
		return nil, err
	}
	return wrapEvents(events), nil
}

// QuerySyncItems answers a NIP-77 reconciliation: the id and created_at of
// every stored event the filter matches, oldest first. Reconciliation
// needs nothing else, so content, sig and tags_json are never read and no
// tags are reconstructed — on a large relay, loading whole events here was
// a multi-gigabyte allocation per sync (nostrfi/relay#70). The conditions
// are the ones a REQ applies, from the same builder, so a sync and a REQ
// agree about which events a filter matches.
func (r *Repository) QuerySyncItems(ctx context.Context, filter nostr.Filter) ([]domainevent.SyncItem, error) {
	statement, args := syncQuery(filter)
	rows, err := r.queries().QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []domainevent.SyncItem
	for rows.Next() {
		var item domainevent.SyncItem
		if err := rows.Scan(&item.ID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	// As in queryEvents: a cancellation mid-iteration must surface rather
	// than hand back a truncated set as if it were the whole one — a peer
	// reconciling against a partial vector would be told it holds events
	// this relay lacks.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// syncQuery builds QuerySyncItems' statement. The select list is the whole
// point of the method, so it is built separately for a test to pin.
func syncQuery(filter nostr.Filter) (string, []any) {
	conditions, args, _ := eventConditions(domainevent.Query{Filter: filter}, true)
	// Negentropy reconciliation compares ordered vectors, so this ordering
	// is a wire requirement.
	statement := "SELECT e.id, e.created_at FROM events e WHERE " + strings.Join(conditions, " AND ") +
		" ORDER BY e.created_at ASC, e.id ASC"
	if filter.Limit > 0 {
		statement += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	return statement, args
}

func (r *Repository) QueryEventsMatching(ctx context.Context, query domainevent.Query) ([]*domainevent.Event, error) {
	events, err := r.queryEvents(ctx, query)
	if err != nil {
		return nil, err
	}
	return wrapEvents(events), nil
}

// wrapEvents converts raw, already-stored *nostr.Event rows into domain
// Events. A signature check is not repeated here: only an event that
// already passed domain/event.NewEvent's check at publish time is ever
// persisted.
func wrapEvents(events []*nostr.Event) []*domainevent.Event {
	wrapped := make([]*domainevent.Event, len(events))
	for i, ev := range events {
		wrapped[i] = &domainevent.Event{Event: ev}
	}
	return wrapped
}

func (r *Repository) queryEvents(ctx context.Context, query domainevent.Query) ([]*nostr.Event, error) {
	filter := query.Filter
	conditions, args, searchTerm := eventConditions(query, false)

	statement := "SELECT e.id, e.pubkey, e.created_at, e.kind, e.content, e.sig, e.tags_json FROM events e" +
		" WHERE " + strings.Join(conditions, " AND ")
	if searchTerm != "" {
		// NIP-50: "Results SHOULD be returned in descending order by
		// quality of search result... not by the usual .created_at", and
		// the limit applies after that sort — which it does, since the
		// LIMIT below is applied to this ordering.
		//
		// Quality here is deliberately modest, because an ILIKE scan
		// produces no relevance score to sort by: the earliest occurrence
		// first, then the shortest content, then the newest. A term in the
		// opening words of a short note is more likely to be its subject
		// than the same term buried in a four-thousand-character wall.
		// README.md states this in full; it is not BM25 and does not
		// pretend to be.
		statement += " ORDER BY strpos(lower(e.content), lower(?)) ASC, length(e.content) ASC, e.created_at DESC, e.id ASC"
		args = append(args, searchTerm)
	} else {
		statement += " ORDER BY e.created_at DESC, e.id ASC"
	}
	if filter.Limit > 0 {
		statement += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}

	rows, err := r.queries().QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Rows needing the legacy tag fallback are fetched after the scan, not
	// during it: rows holds a pooled connection until it is closed, so a
	// lookup inside the loop takes a second one. With the pool bounded
	// (NewRepository), concurrent REQs over legacy rows would each hold one
	// connection and wait forever for another (nostrfi/relay#73).
	var events, legacy []*nostr.Event
	for rows.Next() {
		var ev nostr.Event
		var tagsJSON sql.NullString
		err := rows.Scan(&ev.ID, &ev.PubKey, &ev.CreatedAt, &ev.Kind, &ev.Content, &ev.Sig, &tagsJSON)
		if err != nil {
			return nil, err
		}
		if tags, ok := decodeTags(ev.ID, tagsJSON); ok {
			ev.Tags = tags
		} else {
			legacy = append(legacy, &ev)
		}
		events = append(events, &ev)
	}
	// rows.Err carries a context cancellation or deadline that fired while
	// rows were being iterated — after QueryContext itself succeeded.
	// Swallowing it returned a silently truncated result set with a nil
	// error, which upstream answers with EOSE as if the query completed;
	// the search work budget (workspace #59) depends on the deadline
	// surfacing so the client gets CLOSED instead of a partial answer
	// presented as a full one.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, ev := range legacy {
		ev.Tags = r.getLegacyTags(ctx, ev.ID)
	}
	return events, nil
}

// eventConditions builds the WHERE conditions a filter implies, shared by
// queryEvents and syncQuery so a REQ and a sync cannot drift apart on
// which events a filter matches. It always includes the expiration and ban
// exclusions, so the list is never empty. searchTerm is the NIP-50 term
// the caller must order by, empty for a sync read or a filter without one.
func eventConditions(query domainevent.Query, forSync bool) (conditions []string, args []any, searchTerm string) {
	filter := query.Filter

	if len(filter.IDs) > 0 {
		cond, condArgs := prefixMatchCondition("e.id", filter.IDs)
		conditions = append(conditions, cond)
		args = append(args, condArgs...)
	}

	if len(filter.Authors) > 0 {
		cond, condArgs := prefixMatchCondition("e.pubkey", filter.Authors)
		conditions = append(conditions, cond)
		args = append(args, condArgs...)
	}

	if len(filter.Kinds) > 0 {
		conditions = append(conditions, fmt.Sprintf("e.kind IN (%s)", placeholders(len(filter.Kinds))))
		for _, kind := range filter.Kinds {
			args = append(args, kind)
		}
	}

	if filter.Since != nil {
		conditions = append(conditions, "e.created_at >= ?")
		args = append(args, *filter.Since)
	}

	if filter.Until != nil {
		conditions = append(conditions, "e.created_at <= ?")
		args = append(args, *filter.Until)
	}

	for tag, values := range filter.Tags {
		if len(values) == 0 {
			continue
		}
		// A protocol filter only ever matches NIP-01's single-letter tags.
		// The index now also holds the operator's multi-letter tags
		// (nostrfi/relay#45), and a public REQ for #client must keep
		// matching no stored event rather than start reading them.
		if !domainevent.IsSingleLetterTag(tag) {
			conditions = append(conditions, "FALSE")
			continue
		}
		conditions = append(conditions, fmt.Sprintf(`
			e.id IN (SELECT event_id FROM tags WHERE tag = ? AND value IN (%s))
		`, placeholders(len(values))))
		args = append(args, tag)
		for _, val := range values {
			args = append(args, val)
		}
	}

	// The operator's tag filter: every name must match, any of its values
	// may, and no values means the tag merely has to be there.
	for tag, values := range query.TagConditions {
		if len(values) == 0 {
			conditions = append(conditions, "e.id IN (SELECT event_id FROM tags WHERE tag = ?)")
			args = append(args, tag)
			continue
		}
		conditions = append(conditions, fmt.Sprintf(
			"e.id IN (SELECT event_id FROM tags WHERE tag = ? AND value IN (%s))", placeholders(len(values))))
		args = append(args, tag)
		for _, val := range values {
			args = append(args, val)
		}
	}

	if query.ContentContains != "" {
		// The only condition here with no index behind it: a scan bounded
		// by the filter's other conditions and its limit. Operator-only,
		// and documented as such in README.md.
		conditions = append(conditions, `e.content ILIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLikePattern(query.ContentContains)+"%")
	}

	// NIP-50. Same unindexed scan as the operator's content search above,
	// and the same escaping, but a different caller and — below — a
	// different order. The term arrives already stripped of the NIP's
	// key:value extensions; this layer matches what it is given.
	//
	// Not applied to a sync read. NEG-OPEN hands its filter from the wire
	// to QuerySyncItems without the REQ path's search parsing, so a term
	// would arrive there unparsed and unbounded. NIP-77 defines no search
	// semantics anyway, and quietly narrowing a reconciliation by a
	// substring would leave two peers disagreeing about what the other
	// holds.
	if !forSync {
		searchTerm = query.Filter.Search
	}
	if searchTerm != "" {
		conditions = append(conditions, `e.content ILIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLikePattern(searchTerm)+"%")
	}

	conditions = append(conditions, "(e.expiration IS NULL OR e.expiration > ?)")
	args = append(args, nostr.Now())
	conditions = append(conditions, "e.id NOT IN (SELECT event_id FROM banned_events)")
	return conditions, args, searchTerm
}

// decodeTags returns the event's tags with full fidelity when tagsJSON was
// populated at save time. ok is false when the caller must fall back to
// getLegacyTags: a row saved before the tags_json migration has tagsJSON
// NULL, and a corrupt value is logged and treated the same way. That
// fallback is the lossy two-field reconstruction the relay used
// previously, since the original tag fields were never stored and cannot
// be recovered.
func decodeTags(eventID string, tagsJSON sql.NullString) (tags nostr.Tags, ok bool) {
	if !tagsJSON.Valid {
		return nil, false
	}
	if err := json.Unmarshal([]byte(tagsJSON.String), &tags); err != nil {
		slog.Error("failed to unmarshal tags_json, falling back to legacy reconstruction", "event_id", eventID, "error", err)
		return nil, false
	}
	return tags, true
}

// escapeLikePattern neutralizes the wildcards in a caller-supplied
// substring, so a search for "100%" looks for that text rather than for
// "100" followed by anything. The pairing ESCAPE clause is written out at
// the call site rather than assumed: a default that differs between engines
// would fail silently, matching too much instead of erroring.
func escapeLikePattern(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)
	return replacer.Replace(value)
}

func placeholders(n int) string {
	ps := make([]string, n)
	for i := range n {
		ps[i] = "?"
	}
	return strings.Join(ps, ",")
}

// prefixMatchCondition builds an OR-combined WHERE fragment matching column
// against any of values. Per NIP-01, "ids" and "authors" filter values
// shorter than a full 64-character hex id/pubkey are prefix matches; a
// full-length value uses exact equality (equivalent to a 64-character
// prefix match, but index-friendly rather than a full scan).
func prefixMatchCondition(column string, values []string) (string, []any) {
	parts := make([]string, len(values))
	args := make([]any, len(values))
	for i, v := range values {
		if len(v) == 64 {
			parts[i] = column + " = ?"
		} else {
			parts[i] = "starts_with(" + column + ", ?)"
		}
		args[i] = v
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// Close closes the query pool, then the control pool, which owns the
// database (see sharedConnector).
func (r *Repository) Close() error {
	var err error
	if r.queryDB != nil {
		err = r.queryDB.Close()
	}
	if r.db != nil {
		err = errors.Join(err, r.db.Close())
	}
	return err
}

// getLegacyTags reconstructs an event's tags from the tags index table,
// which only ever recorded a tag's name and first value. It is the fallback
// path for events saved before the tags_json migration (see
// decodeTags); every event saved since then is reconstructed from its
// own tags_json column instead.
func (r *Repository) getLegacyTags(ctx context.Context, eventID string) nostr.Tags {
	rows, err := r.queries().QueryContext(ctx, "SELECT tag, value FROM tags WHERE event_id = ?", eventID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var tags nostr.Tags
	for rows.Next() {
		var tag string
		var value sql.NullString
		if err := rows.Scan(&tag, &value); err == nil {
			if value.Valid {
				tags = append(tags, []string{tag, value.String})
			} else {
				tags = append(tags, []string{tag})
			}
		}
	}
	return tags
}
