package ws

import (
	"sync"
	"time"
)

// nip98ReplayGuard refuses a NIP-98 event that has already been used
// (nostrfi/relay#60).
//
// NIP-98's freshness window alone lets anyone who sees a signed request
// send it again, unchanged, for as long as it stays fresh. Each event ID is
// remembered here until it could no longer pass the freshness check anyway.
//
// Only events from keys that hold a role are recorded (see authorize).
// Anyone can sign valid events with a key of their own, so recording a
// stranger's would let them fill the record. A stranger's events are
// refused on identity anyway, replayed or not.
//
// A live record is never evicted: evicting it would let that event be used
// again. At capacity, new claims are refused until records expire. Since
// only the owner and administrators can add records, only they can reach
// that limit.
//
// Event IDs are trustworthy keys because domainevent.NewEvent checks that
// the ID is the hash of the content; a copy with an edited "id" is refused
// before it gets here.
//
// Held in process memory, like the NIP-42 challenges. A restart forgets it,
// which reopens replay only for events signed in the last freshness window.
type nip98ReplayGuard struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	maxSize   int
	lastPrune time.Time
	now       func() time.Time
}

// defaultNip98ReplayCapacity is far above what the owner and administrators
// send within one freshness window.
const defaultNip98ReplayCapacity = 100_000

type claimResult int

const (
	claimed claimResult = iota
	claimReplayed
	claimFull
)

func newNip98ReplayGuard(maxSize int) *nip98ReplayGuard {
	return &nip98ReplayGuard{seen: make(map[string]time.Time), maxSize: maxSize, now: time.Now}
}

// claim records id until expiresAt. Check and record are one step, so two
// copies of an event racing each other cannot both be admitted.
func (g *nip98ReplayGuard) claim(id string, expiresAt time.Time) claimResult {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if until, ok := g.seen[id]; ok && until.After(now) {
		return claimReplayed
	}

	if now.Sub(g.lastPrune) >= time.Second || len(g.seen) >= g.maxSize {
		g.prune(now)
		g.lastPrune = now
	}
	if len(g.seen) >= g.maxSize {
		return claimFull
	}
	g.seen[id] = expiresAt
	return claimed
}

func (g *nip98ReplayGuard) prune(now time.Time) {
	for id, until := range g.seen {
		if !until.After(now) {
			delete(g.seen, id)
		}
	}
}

// size is the number of remembered events; for tests.
func (g *nip98ReplayGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
