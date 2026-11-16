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
// It records every event that verifies, whoever signed it, not only those
// of the owner and administrators. If only role holders' events were
// recorded, "already used" would tell a stranger that the signer holds a
// role, the probe nostrfi/relay#60 describes.
//
// Held in process memory, like the NIP-42 challenges. A restart forgets it,
// which reopens replay only for events signed in the last freshness window.
type nip98ReplayGuard struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	order     []string
	maxSize   int
	lastPrune time.Time
	now       func() time.Time
}

// defaultNip98ReplayCapacity bounds memory against a flood of valid
// signatures, which anyone can make with their own key. Reaching it evicts
// the oldest entries. Replaying an evicted event needs a flood this large
// within one freshness window, and a fresh signature from a real operator
// for this relay's own origin.
const defaultNip98ReplayCapacity = 100_000

func newNip98ReplayGuard(maxSize int) *nip98ReplayGuard {
	return &nip98ReplayGuard{seen: make(map[string]time.Time), maxSize: maxSize, now: time.Now}
}

// claim records id until expiresAt and reports whether this is its first
// use. Check and record are one step, so two copies of an event racing
// each other cannot both be admitted.
func (g *nip98ReplayGuard) claim(id string, expiresAt time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	if now.Sub(g.lastPrune) >= time.Second {
		g.prune(now)
		g.lastPrune = now
	}

	if until, ok := g.seen[id]; ok {
		if until.After(now) {
			return false
		}
		// Expired but not yet pruned: it is already in order.
		g.seen[id] = expiresAt
		return true
	}

	for len(g.seen) >= g.maxSize && len(g.order) > 0 {
		oldest := g.order[0]
		g.order = g.order[1:]
		delete(g.seen, oldest)
	}
	g.seen[id] = expiresAt
	g.order = append(g.order, id)
	return true
}

// prune drops expired entries. order keeps insertion order, which is not
// expiry order (created_at can sit either side of now), so it is rebuilt
// from what remains.
func (g *nip98ReplayGuard) prune(now time.Time) {
	kept := g.order[:0]
	for _, id := range g.order {
		until, ok := g.seen[id]
		if !ok {
			continue
		}
		if !until.After(now) {
			delete(g.seen, id)
			continue
		}
		kept = append(kept, id)
	}
	g.order = kept
}

// size is the number of remembered events; for tests.
func (g *nip98ReplayGuard) size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
