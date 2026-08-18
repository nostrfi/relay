package ws

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"unicode/utf8"

	"relay/internal/application"
	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

// maxEventsQueryBodyBytes bounds how much of a query body is read. A filter
// is small; this leaves room for a generous list of ids or authors without
// letting an unauthenticated caller push arbitrary bytes into memory before
// the signature check gets a look at them.
const maxEventsQueryBodyBytes = 16 << 10

const (
	// defaultEventQueryLimit is what a request that names no limit gets:
	// one screen of events, not one page of database.
	defaultEventQueryLimit = 100

	// fallbackMaxEventQueryLimit caps the limit when the relay advertises
	// no max_limit of its own, matching the value config.yaml ships.
	fallbackMaxEventQueryLimit = 500

	// minContentSearchRunes is the shortest content substring accepted.
	// The condition behind it is an unindexed scan, and a one-character
	// search is a full table read that returns nothing useful anyway.
	minContentSearchRunes = 3
)

// eventQueryRequest is the browse API's filter: NIP-01's dimensions, plus
// the content substring NIP-01 does not model.
//
// Deliberately not nostr.Filter itself. That type carries Search (NIP-50,
// which this relay does not implement) and the LimitZero subtlety, and it
// would tie the dashboard's request shape to a protocol type that changes
// for protocol reasons.
type eventQueryRequest struct {
	IDs     []string            `json:"ids"`
	Authors []string            `json:"authors"`
	Kinds   []int               `json:"kinds"`
	Tags    map[string][]string `json:"tags"`
	Since   *nostr.Timestamp    `json:"since"`
	Until   *nostr.Timestamp    `json:"until"`

	// ContentContains matches case-insensitively anywhere in the content.
	ContentContains string `json:"content_contains"`

	Limit int `json:"limit"`
}

// eventQueryResponse answers with the events, the limit actually applied —
// a clamped request must not look like it was honoured — and the cursor for
// the next page.
type eventQueryResponse struct {
	Events []*nostr.Event `json:"events"`
	Limit  int            `json:"limit"`

	// NextUntil is the oldest created_at in this page, to be sent back as
	// "until" for the next one. Absent when this page is the last.
	//
	// Cursor rather than offset: an offset re-scans everything it skips,
	// so paging degrades as the relay stores more. The cost is that events
	// sharing the boundary timestamp can appear on both pages, so callers
	// de-duplicate by id — which the dashboard does.
	NextUntil *nostr.Timestamp `json:"next_until,omitempty"`
}

// newEventsQueryHandler serves stored events to the configured operator.
//
// POST, like the configuration endpoint, so verifyNip98 applies unchanged:
// it requires the payload tag, which needs a body to hash. A GET with query
// parameters could not be signed the same way.
func newEventsQueryHandler(cfg Config, events application.EventService) http.HandlerFunc {
	maxLimit := fallbackMaxEventQueryLimit
	if cfg.RelayInfo.Limitation != nil && cfg.RelayInfo.Limitation.MaxLimit > 0 {
		maxLimit = cfg.RelayInfo.Limitation.MaxLimit
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxEventsQueryBodyBytes))
		if err != nil {
			writeEventQueryError(w, http.StatusBadRequest, "could not read request body")
			return
		}

		if _, err := authorizeOperator(r, body, cfg.Moderation.AdminPubkey, cfg.Moderation.MaxEventAgeSeconds); err != nil {
			logRejectedOperatorRequest("events", err)
			w.WriteHeader(http.StatusUnauthorized)

			refusal := map[string]string{"error": "unauthorized"}
			// A verification failure is safe to explain and expensive to
			// withhold; an identity failure is not. See authorizeOperator.
			if reason := publicReasonFor(err); reason != "" {
				refusal["reason"] = reason
			}
			json.NewEncoder(w).Encode(refusal)
			return
		}

		var req eventQueryRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeEventQueryError(w, http.StatusBadRequest, "invalid JSON request body")
			return
		}

		if req.ContentContains != "" && utf8.RuneCountInString(req.ContentContains) < minContentSearchRunes {
			writeEventQueryError(w, http.StatusBadRequest, "content_contains must be at least 3 characters")
			return
		}

		limit := req.Limit
		if limit <= 0 {
			limit = defaultEventQueryLimit
		}
		if limit > maxLimit {
			// Clamped rather than refused: the response reports the limit
			// applied, so a caller asking for too much still gets an answer
			// and can see what it was given.
			limit = maxLimit
		}

		query := domainevent.Query{
			Filter: nostr.Filter{
				IDs:     req.IDs,
				Authors: req.Authors,
				Kinds:   req.Kinds,
				Tags:    nostr.TagMap(req.Tags),
				Since:   req.Since,
				Until:   req.Until,
				Limit:   limit,
			},
			ContentContains: req.ContentContains,
		}

		stored, err := events.QueryEventsMatching(r.Context(), query)
		if err != nil {
			// Never the filter or anything it matched: event content stays
			// out of the logs (CODINGSTANDARDS.md, "Security guardrails").
			slog.Error("operator event query failed", "error", err)
			writeEventQueryError(w, http.StatusInternalServerError, "internal error")
			return
		}

		response := eventQueryResponse{Events: make([]*nostr.Event, 0, len(stored)), Limit: limit}
		for _, ev := range stored {
			response.Events = append(response.Events, ev.Event)
		}

		// A short page is the end of the results; a full one might not be.
		if len(response.Events) == limit && limit > 0 {
			oldest := response.Events[len(response.Events)-1].CreatedAt
			response.NextUntil = &oldest
		}

		json.NewEncoder(w).Encode(response)
	}
}

func writeEventQueryError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
