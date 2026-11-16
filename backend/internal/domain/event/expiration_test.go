package event

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestExpiredOnArrival(t *testing.T) {
	const created = 1_000_000
	cases := []struct {
		name string
		tags nostr.Tags
		want bool
	}{
		{"no expiration tag", nil, false},
		{"expires before creation", nostr.Tags{{"expiration", "999940"}}, true},
		{"expires at creation", nostr.Tags{{"expiration", "1000000"}}, false},
		{"expires after creation", nostr.Tags{{"expiration", "1000060"}}, false},
		{"unparseable value ignored", nostr.Tags{{"expiration", "soon"}}, false},
		{"last parseable tag wins", nostr.Tags{{"expiration", "1000060"}, {"expiration", "999940"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &nostr.Event{CreatedAt: created, Tags: tc.tags}
			if got := ExpiredOnArrival(ev); got != tc.want {
				t.Errorf("ExpiredOnArrival = %v, want %v", got, tc.want)
			}
		})
	}
}
