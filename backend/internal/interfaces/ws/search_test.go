package ws

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
