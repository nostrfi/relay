package event

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

// Query is a nostr.Filter plus the one dimension NIP-01 does not model: a
// substring of the event content.
//
// It exists so the operator event browser (nostrfi/workspace#36) can offer
// that search without it leaking into the protocol. Putting it in
// nostr.Filter's Search field would have been shorter and wrong: that field
// is NIP-50, the relay does not implement NIP-50, and the same filter type
// is built from whatever a REQ subscriber sends — so any client could then
// have used it, and the relay would be quietly answering a NIP it does not
// advertise.
type Query struct {
	Filter nostr.Filter
	// ContentContains matches case-insensitively anywhere in the content.
	// Empty means no content condition.
	ContentContains string
}

// StatsBucket is the granularity a statistics query groups by.
type StatsBucket string

const (
	StatsBucketHour  StatsBucket = "hour"
	StatsBucketDay   StatsBucket = "day"
	StatsBucketWeek  StatsBucket = "week"
	StatsBucketMonth StatsBucket = "month"
)

// StatsQuery asks how many events fall in each period of a range, and how
// they break down by kind — the counting the event browser cannot do, since
// it reads rows a page at a time (nostrfi/workspace#51).
type StatsQuery struct {
	Since nostr.Timestamp
	Until nostr.Timestamp
	// Bucket is the granularity to group by.
	Bucket StatsBucket
	// OffsetSeconds shifts period boundaries off UTC, so "a day" can mean
	// the operator's day rather than the server's.
	OffsetSeconds int
}

// StatsPeriod is one bucket: the unix second it starts at, and how many
// events fall in it. Periods with no events are absent — the caller fills
// the gaps, because only it knows the axis it is drawing.
type StatsPeriod struct {
	Start int64
	Count int64
}

// KindCount is one row of the kind breakdown, ordered by count descending.
type KindCount struct {
	Kind  int
	Count int64
}

// Stats is what EventStats returns: the periods, the kind breakdown, and the
// total across the range, which is the sum of the periods.
type Stats struct {
	Periods []StatsPeriod
	Kinds   []KindCount
	Total   int64
}

// Repository is the persistence port for events: implemented by the
// infrastructure layer, depended on by the application layer.
type Repository interface {
	SaveEvent(ctx context.Context, event *Event) (bool, error)
	QueryEvents(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*Event, error)
	// QueryEventsMatching is QueryEvents with Query's extra dimension, in
	// the same newest-first order.
	QueryEventsMatching(ctx context.Context, query Query) ([]*Event, error)
	// CountEvents is how many events are stored, including ones no query
	// would serve. It answers "is this the database I filled", which a
	// filtered count cannot.
	CountEvents(ctx context.Context) (int64, error)
	// EventStats counts events by period and by kind over a range, applying
	// the same exclusions as a read: an expired or banned event is no more
	// counted than it is served.
	EventStats(ctx context.Context, query StatsQuery) (Stats, error)
	PurgeExpired(ctx context.Context) (int64, error)
	Checkpoint(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error
}
