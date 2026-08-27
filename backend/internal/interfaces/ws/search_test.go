package ws

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseSearchTerm covers where NIP-50's ambiguity lives: which tokens
// are extensions to be ignored, and which are ordinary search text that a
// relay has no business deleting from the client's query.
func TestParseSearchTerm(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"plain term", "orange", "orange"},
		{"multiple words are kept in order", "best nostr apps", "best nostr apps"},
		{"surrounding whitespace collapses", "  orange \t juice \n", "orange juice"},
		{"named extension is dropped", "orange domain:example.com", "orange"},
		{"extension before the term", "language:en orange", "orange"},
		{"every named extension is dropped", "include:spam domain:x language:en sentiment:positive nsfw:false orange", "orange"},
		{"extension key is matched case-insensitively", "orange DOMAIN:example.com", "orange"},
		{"only extensions leaves nothing", "domain:example.com nsfw:true", ""},
		{"empty stays empty", "", ""},

		// The conservative half of the rule. A colon is ordinary text far
		// more often than it is a NIP-50 extension, and a relay that
		// quietly deleted these would answer a question nobody asked.
		{"a URL is search text", "https://example.com", "https://example.com"},
		{"a time is search text", "meeting at 18:30", "meeting at 18:30"},
		{"an unknown key is search text", "colour:orange", "colour:orange"},
		{"a bare colon is search text", "ratio 3:1", "ratio 3:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseSearchTerm(tt.raw))
		})
	}
}

// TestPrepareSearchFiltersLimits covers the guardrail that stops a search —
// the one query no index can answer — from running unbounded. queryEvents
// emits no SQL LIMIT unless the filter's limit is positive, so every
// non-positive value has to be normalized here or the whole matching set
// comes back.
func TestPrepareSearchFiltersLimits(t *testing.T) {
	limitation := &RelayLimitation{MaxLimit: 500}

	tests := []struct {
		name      string
		filter    nostr.Filter
		wantLimit int
	}{
		{"absent limit takes the default", nostr.Filter{Search: "orange"}, 500},
		{"negative limit takes the default", nostr.Filter{Search: "orange", Limit: -5}, 500},
		{"a positive limit is left alone", nostr.Filter{Search: "orange", Limit: 10}, 10},
		{
			// Not defaulted: handleReq answers this one with no stored
			// events at all, which is what the client asked for.
			"an explicit zero is left alone",
			nostr.Filter{Search: "orange", LimitZero: true},
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filters := []nostr.Filter{tt.filter}
			reason, ok := prepareSearchFilters(filters, limitation)
			require.True(t, ok, "expected the filter to be accepted, got %q", reason)
			assert.Equal(t, tt.wantLimit, filters[0].Limit)
		})
	}

	t.Run("a relay advertising no max_limit still bounds search", func(t *testing.T) {
		filters := []nostr.Filter{{Search: "orange"}}
		_, ok := prepareSearchFilters(filters, nil)
		require.True(t, ok)
		assert.Equal(t, fallbackSearchLimit, filters[0].Limit)
	})

	t.Run("a filter carrying no search is untouched", func(t *testing.T) {
		filters := []nostr.Filter{{Kinds: []int{1}}}
		_, ok := prepareSearchFilters(filters, limitation)
		require.True(t, ok)
		assert.Equal(t, 0, filters[0].Limit, "only search filters get a default limit")
	})

	t.Run("refusals", func(t *testing.T) {
		_, ok := prepareSearchFilters([]nostr.Filter{{Search: "ab"}}, limitation)
		assert.False(t, ok, "a term below the minimum is refused")

		_, ok = prepareSearchFilters([]nostr.Filter{{Search: "domain:example.com"}}, limitation)
		assert.False(t, ok, "a query that is nothing but extensions is refused")
	})
}
