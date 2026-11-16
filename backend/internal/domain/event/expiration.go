package event

import (
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

// Expiration returns the NIP-40 expiration timestamp carried by ev's tags,
// and whether it has one. A tag whose value is not an integer is ignored;
// if several are present the last parseable one wins, matching how the
// repository has always stored the expiration column.
func Expiration(ev *nostr.Event) (int64, bool) {
	var (
		ts    int64
		found bool
	)
	for _, tag := range ev.Tags {
		if len(tag) > 1 && tag[0] == "expiration" {
			var v int64
			if _, err := fmt.Sscanf(tag[1], "%d", &v); err == nil {
				ts, found = v, true
			}
		}
	}
	return ts, found
}

// ExpiredOnArrival reports whether ev expires before it was created — the
// NIP-40 "relays SHOULD drop any events that are published to them if they
// are expired" rule as this relay applies it on publish. It holds for
// every kind, so ephemeral events, which skip the repository, are checked
// against it before they are broadcast.
func ExpiredOnArrival(ev *nostr.Event) bool {
	exp, ok := Expiration(ev)
	return ok && exp < int64(ev.CreatedAt)
}
