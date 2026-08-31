package ws

import (
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
)

// TestMatchesFilterPrefixes pins live delivery to the stored side's NIP-01
// prefix semantics (prefixMatchCondition): exact at 64 characters, prefix
// below, nothing above — with the same edge readings the SQL takes. Each
// case that matches here is one the stored query would also have returned,
// which is the whole contract.
func TestMatchesFilterPrefixes(t *testing.T) {
	id := strings.Repeat("ab", 32)     // 64 chars
	author := strings.Repeat("cd", 32) // 64 chars
	ev := &nostr.Event{ID: id, PubKey: author, Kind: 1, Content: "hello"}
	noContent := func() string { return "" }

	almostID := id[:63] + "f"
	almostAuthor := author[:63] + "f"

	tests := []struct {
		name   string
		filter nostr.Filter
		want   bool
	}{
		{"short id prefix matches", nostr.Filter{IDs: []string{id[:10]}}, true},
		{"short author prefix matches", nostr.Filter{Authors: []string{author[:10]}}, true},
		{"full-length id matches exactly", nostr.Filter{IDs: []string{id}}, true},
		{"full-length author matches exactly", nostr.Filter{Authors: []string{author}}, true},
		{"full-length id differing in the last character does not match", nostr.Filter{IDs: []string{almostID}}, false},
		{"full-length author differing in the last character does not match", nostr.Filter{Authors: []string{almostAuthor}}, false},
		{"value longer than 64 characters matches nothing", nostr.Filter{IDs: []string{id + "ab"}}, false},
		{"non-matching prefix does not match", nostr.Filter{IDs: []string{"deadbeef"}}, false},
		{"one matching value among misses is enough", nostr.Filter{Authors: []string{"deadbeef", author[:8]}}, true},

		// The stored side's edge readings, mirrored deliberately.
		{"nil list is no constraint", nostr.Filter{}, true},
		{"non-nil empty list is no constraint, as in SQL", nostr.Filter{IDs: []string{}, Authors: []string{}}, true},
		{"empty-string value matches everything, as starts_with(x, '') does", nostr.Filter{IDs: []string{""}}, true},

		// The remaining dimensions still go through Filter.Matches.
		{"prefix match with a non-matching kind is still rejected", nostr.Filter{Authors: []string{author[:10]}, Kinds: []int{7}}, false},
		{"prefix match with the matching kind passes", nostr.Filter{Authors: []string{author[:10]}, Kinds: []int{1}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchesFilter(tt.filter, ev, noContent))
		})
	}
}
