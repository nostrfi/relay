package ws

import (
	"context"
	"net"
	"sync/atomic"

	"relay/internal/application"
	"relay/internal/domain/moderation"
)

// blocklist is an immutable, pre-parsed snapshot of the blocked-IP list.
// gen is the cache generation it was loaded under; a snapshot whose gen is
// behind the cache's current generation is stale and never consulted.
type blocklist struct {
	gen   uint64
	exact map[string]struct{}
	nets  []*net.IPNet
}

func newBlocklist(gen uint64, entries []moderation.ModerationEntry) *blocklist {
	b := &blocklist{gen: gen, exact: make(map[string]struct{}, len(entries))}
	for _, entry := range entries {
		b.exact[entry.Value] = struct{}{}
		if _, ipNet, err := net.ParseCIDR(entry.Value); err == nil {
			b.nets = append(b.nets, ipNet)
		}
	}
	return b
}

// contains applies the matching rule isConnectionSourceBlocked has always
// used: the stored value equals the connection's host string exactly, or it
// parses as a CIDR containing the address. Values are deliberately not
// canonicalised, so the cache matches exactly the entries a fresh query
// would have.
func (b *blocklist) contains(host string, ip net.IP) bool {
	if _, ok := b.exact[host]; ok {
		return true
	}
	for _, ipNet := range b.nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// blocklistCache holds the blocked-IP list between connection upgrades, so
// an upgrade no longer queries DuckDB and re-parses every CIDR. It is
// correct only while every write to the list goes through this handler's
// blockip/unblockip, which call invalidate — true today, since one relay
// process owns the database and the dashboard reaches it via NIP-86. Any
// new writer must invalidate it too.
//
// Invalidation bumps the generation instead of clearing the snapshot: a
// load that read the list before a write and stores its snapshot after
// would otherwise re-install the pre-write list for good. A snapshot tagged
// with an old generation is simply reloaded.
type blocklistCache struct {
	gen  atomic.Uint64
	snap atomic.Pointer[blocklist]
}

func (c *blocklistCache) get(ctx context.Context, svc application.ModerationService) (*blocklist, error) {
	gen := c.gen.Load()
	if b := c.snap.Load(); b != nil && b.gen == gen {
		return b, nil
	}
	entries, err := svc.ListBlockedIPs(ctx)
	if err != nil {
		return nil, err
	}
	b := newBlocklist(gen, entries)
	c.snap.Store(b)
	return b, nil
}

func (c *blocklistCache) invalidate() {
	c.gen.Add(1)
}
