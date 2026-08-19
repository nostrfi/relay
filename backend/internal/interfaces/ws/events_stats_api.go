package ws

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"relay/internal/application"
	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

const (
	// maxStatsBodyBytes bounds a statistics request, which carries only a
	// range and a granularity.
	maxStatsBodyBytes = 4 << 10

	// maxStatsPeriods is the widest chart worth drawing. Past this the
	// periods are thinner than a pixel and the response is larger than the
	// answer, so the granularity is coarsened until it fits rather than the
	// request being refused — see coarsenToFit.
	maxStatsPeriods = 400

	// defaultStatsWindowSeconds is the range used when a request names
	// neither end: the last week, which is what a dashboard opens on.
	defaultStatsWindowSeconds = 7 * 24 * 60 * 60

	// maxStatsOffsetSeconds bounds the operator-clock offset to the real
	// range of UTC offsets (UTC-12 to UTC+14).
	maxStatsOffsetSeconds = 14 * 60 * 60
	minStatsOffsetSeconds = -12 * 60 * 60
)

// bucketSeconds is the nominal length of each granularity, used only to
// decide how many periods a range would produce. Months and weeks are not
// fixed lengths; the approximation is deliberate and only ever picks the
// granularity, never a boundary — those come from the database.
var bucketSeconds = map[domainevent.StatsBucket]int64{
	domainevent.StatsBucketHour:  3600,
	domainevent.StatsBucketDay:   86400,
	domainevent.StatsBucketWeek:  7 * 86400,
	domainevent.StatsBucketMonth: 30 * 86400,
}

// coarser is the ladder a too-fine granularity is walked up.
var coarser = map[domainevent.StatsBucket]domainevent.StatsBucket{
	domainevent.StatsBucketHour: domainevent.StatsBucketDay,
	domainevent.StatsBucketDay:  domainevent.StatsBucketWeek,
	domainevent.StatsBucketWeek: domainevent.StatsBucketMonth,
}

// errBadBucket names the four granularities, so a caller that sent a fifth
// learns what is on offer rather than only that it was wrong.
var errBadBucket = errors.New("bucket must be one of hour, day, week, month")

type eventStatsRequest struct {
	Since *nostr.Timestamp `json:"since"`
	Until *nostr.Timestamp `json:"until"`

	// Bucket is hour, day, week or month; empty means day.
	Bucket string `json:"bucket"`

	// UTCOffsetMinutes shifts period boundaries onto the operator's clock.
	// Absent means UTC, and the response says which was applied.
	UTCOffsetMinutes *int `json:"utc_offset_minutes"`
}

type statsPeriodView struct {
	Start int64 `json:"start"`
	Count int64 `json:"count"`
}

type statsKindView struct {
	Kind  int   `json:"kind"`
	Count int64 `json:"count"`
}

// eventStatsResponse reports the range and granularity actually applied, not
// the ones asked for: a coarsened request must not look like an honoured one,
// the same rule the browse endpoint follows with its limit.
type eventStatsResponse struct {
	Periods []statsPeriodView `json:"periods"`
	Kinds   []statsKindView   `json:"kinds"`

	// Total is the number of events in the range: the sum of the periods.
	Total int64 `json:"total"`

	// StoredTotal is every event on disk, expired and banned included. It
	// exists so an empty chart can say "the relay holds N events, none in
	// this range" rather than leaving an operator to guess which it is
	// (nostrfi/workspace#49).
	StoredTotal int64 `json:"stored_total"`

	Bucket           string `json:"bucket"`
	Since            int64  `json:"since"`
	Until            int64  `json:"until"`
	UTCOffsetMinutes int    `json:"utc_offset_minutes"`
}

// newEventStatsHandler serves event counts to the configured operator.
//
// The browse endpoint returns rows; this one returns counts. Counting a
// month of events through the browse endpoint would mean paging the whole
// table into a browser, which is why the aggregation belongs here
// (nostrfi/workspace#51).
func newEventStatsHandler(cfg Config, events application.EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxStatsBodyBytes))
		if err != nil {
			writeEventQueryError(w, http.StatusBadRequest, "could not read request body")
			return
		}

		if _, err := authorizeOperator(r, body, cfg.Moderation.AdminPubkey, cfg.Moderation.MaxEventAgeSeconds); err != nil {
			logRejectedOperatorRequest("events-stats", err)
			w.WriteHeader(http.StatusUnauthorized)

			refusal := map[string]string{"error": "unauthorized"}
			if reason := publicReasonFor(err); reason != "" {
				refusal["reason"] = reason
			}
			json.NewEncoder(w).Encode(refusal)
			return
		}

		var req eventStatsRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeEventQueryError(w, http.StatusBadRequest, "invalid JSON request body")
			return
		}

		bucket, err := parseStatsBucket(req.Bucket)
		if err != nil {
			writeEventQueryError(w, http.StatusBadRequest, err.Error())
			return
		}

		offsetSeconds := 0
		if req.UTCOffsetMinutes != nil {
			offsetSeconds = *req.UTCOffsetMinutes * 60
			if offsetSeconds < minStatsOffsetSeconds || offsetSeconds > maxStatsOffsetSeconds {
				writeEventQueryError(w, http.StatusBadRequest, "utc_offset_minutes is outside the range of real UTC offsets")
				return
			}
		}

		until := nostr.Now()
		if req.Until != nil {
			until = *req.Until
		}
		since := until - defaultStatsWindowSeconds
		if req.Since != nil {
			since = *req.Since
		}
		if since > until {
			writeEventQueryError(w, http.StatusBadRequest, "since is after until, so no period can exist")
			return
		}

		bucket = coarsenToFit(bucket, int64(until-since))

		stats, err := events.EventStats(r.Context(), domainevent.StatsQuery{
			Since:         since,
			Until:         until,
			Bucket:        bucket,
			OffsetSeconds: offsetSeconds,
		})
		if err != nil {
			slog.Error("operator event statistics failed", "error", err)
			writeEventQueryError(w, http.StatusInternalServerError, "internal error")
			return
		}

		response := eventStatsResponse{
			Periods:          make([]statsPeriodView, 0, len(stats.Periods)),
			Kinds:            make([]statsKindView, 0, len(stats.Kinds)),
			Total:            stats.Total,
			Bucket:           string(bucket),
			Since:            int64(since),
			Until:            int64(until),
			UTCOffsetMinutes: offsetSeconds / 60,
		}
		for _, period := range stats.Periods {
			response.Periods = append(response.Periods, statsPeriodView{Start: period.Start, Count: period.Count})
		}
		for _, kind := range stats.Kinds {
			response.Kinds = append(response.Kinds, statsKindView{Kind: kind.Kind, Count: kind.Count})
		}

		// Always, not only when empty as the browse endpoint does: a chart
		// showing a quiet week against a relay holding a million events
		// means something different from the same chart against an empty
		// one, and the page says so either way.
		if total, err := events.CountEvents(r.Context()); err == nil {
			response.StoredTotal = total
		}

		slog.Info("operator event statistics served",
			"periods", len(response.Periods),
			"total", response.Total,
			"stored_total", response.StoredTotal,
			"bucket", response.Bucket,
			"range_seconds", int64(until-since))

		json.NewEncoder(w).Encode(response)
	}
}

// parseStatsBucket accepts the four granularities, defaulting to day.
func parseStatsBucket(value string) (domainevent.StatsBucket, error) {
	switch value {
	case "":
		return domainevent.StatsBucketDay, nil
	case string(domainevent.StatsBucketHour), string(domainevent.StatsBucketDay),
		string(domainevent.StatsBucketWeek), string(domainevent.StatsBucketMonth):
		return domainevent.StatsBucket(value), nil
	default:
		return "", errBadBucket
	}
}

// coarsenToFit walks the granularity up until the range produces a drawable
// number of periods.
//
// Coarsened rather than refused, because a refusal makes the caller guess
// what would have been accepted — and a year of hourly periods is nearly
// always a range control left on a default, not a considered request. The
// response reports the granularity applied, so the axis can say so.
func coarsenToFit(bucket domainevent.StatsBucket, rangeSeconds int64) domainevent.StatsBucket {
	for {
		size, known := bucketSeconds[bucket]
		if !known || size <= 0 || rangeSeconds/size <= maxStatsPeriods {
			return bucket
		}
		next, coarsenable := coarser[bucket]
		if !coarsenable {
			return bucket
		}
		bucket = next
	}
}
