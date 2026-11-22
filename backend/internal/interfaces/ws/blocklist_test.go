package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"relay/internal/domain/moderation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingModerationService serves a mutable blocked-IP list and counts
// how often it is read, so the tests can tell a cache hit from a reload.
type countingModerationService struct {
	stubModerationService
	entries []moderation.ModerationEntry
	listErr error
	lists   atomic.Int64
}

func (s *countingModerationService) ListBlockedIPs(context.Context) ([]moderation.ModerationEntry, error) {
	s.lists.Add(1)
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.entries, nil
}

func (s *countingModerationService) BlockIP(_ context.Context, value, _ string) error {
	s.entries = append(s.entries, moderation.ModerationEntry{Value: value})
	return nil
}

func (s *countingModerationService) UnblockIP(_ context.Context, value string) error {
	s.entries = removeEntry(s.entries, value)
	return nil
}

func removeEntry(entries []moderation.ModerationEntry, value string) []moderation.ModerationEntry {
	out := entries[:0:0]
	for _, e := range entries {
		if e.Value != value {
			out = append(out, e)
		}
	}
	return out
}

func newBlocklistTestHandler(svc *countingModerationService) *RelayHandler {
	return NewRelayHandlerFull(&stubEventService{}, svc, RelayInfo{}, ResourceLimits{}, AuthConfig{}, ModerationConfig{}, WebsocketConfig{}, "test")
}

func rawParams(t *testing.T, values ...string) []json.RawMessage {
	t.Helper()
	params := make([]json.RawMessage, 0, len(values))
	for _, v := range values {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		params = append(params, b)
	}
	return params
}

func isBlocked(t *testing.T, h *RelayHandler, remoteAddr string) bool {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	blocked, err := h.isConnectionSourceBlocked(req)
	require.NoError(t, err)
	return blocked
}

func TestBlocklistMatching(t *testing.T) {
	svc := &countingModerationService{entries: []moderation.ModerationEntry{
		{Value: "203.0.113.5"},
		{Value: "198.51.100.0/24"},
		{Value: "2001:db8::/32"},
		{Value: "not-an-address"},
	}}
	h := newBlocklistTestHandler(svc)

	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{"exact ip", "203.0.113.5:4000", true},
		{"neighbour of exact ip", "203.0.113.6:4000", false},
		{"inside ipv4 cidr", "198.51.100.77:4000", true},
		{"outside ipv4 cidr", "198.51.101.1:4000", false},
		{"inside ipv6 cidr", "[2001:db8::1]:4000", true},
		{"outside ipv6 cidr", "[2001:db9::1]:4000", false},
		{"remote addr without port", "203.0.113.5", true},
		{"unparseable remote addr", "garbage", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isBlocked(t, h, tt.remoteAddr))
		})
	}
}

func TestBlocklistIsLoadedOnceAcrossUpgrades(t *testing.T) {
	svc := &countingModerationService{entries: []moderation.ModerationEntry{{Value: "198.51.100.0/24"}}}
	h := newBlocklistTestHandler(svc)

	for range 50 {
		assert.False(t, isBlocked(t, h, "203.0.113.5:4000"))
		assert.True(t, isBlocked(t, h, "198.51.100.9:4000"))
	}
	assert.Equal(t, int64(1), svc.lists.Load())
}

func TestBlocklistReloadsAfterBlockAndUnblock(t *testing.T) {
	svc := &countingModerationService{}
	h := newBlocklistTestHandler(svc)
	ctx := t.Context()

	assert.False(t, isBlocked(t, h, "203.0.113.5:4000"))

	_, err := h.dispatchManagementMethod(ctx, managementCaller{}, "blockip", rawParams(t, "203.0.113.5", "abuse"))
	require.NoError(t, err)
	assert.True(t, isBlocked(t, h, "203.0.113.5:4000"), "a block must apply to the next connection")

	_, err = h.dispatchManagementMethod(ctx, managementCaller{}, "unblockip", rawParams(t, "203.0.113.5"))
	require.NoError(t, err)
	assert.False(t, isBlocked(t, h, "203.0.113.5:4000"), "an unblock must apply to the next connection")

	assert.Equal(t, int64(3), svc.lists.Load())
}

// A load that read the list before a block and stores its snapshot after
// the block's invalidation must not leave the pre-block list in place.
func TestBlocklistSnapshotFromBeforeInvalidationIsNotReused(t *testing.T) {
	svc := &countingModerationService{}
	h := newBlocklistTestHandler(svc)

	stale := newBlocklist(h.blockedIPs.gen.Load(), nil)
	h.blockedIPs.invalidate()
	h.blockedIPs.snap.Store(stale)
	svc.entries = []moderation.ModerationEntry{{Value: "203.0.113.5"}}

	assert.True(t, isBlocked(t, h, "203.0.113.5:4000"))
	assert.Equal(t, int64(1), svc.lists.Load())
}

func TestBlocklistLoadFailureIsRetried(t *testing.T) {
	svc := &countingModerationService{listErr: errors.New("db down")}
	h := newBlocklistTestHandler(svc)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:4000"
	_, err := h.isConnectionSourceBlocked(req)
	require.Error(t, err, "a failed load must still fail the upgrade")

	svc.listErr = nil
	svc.entries = []moderation.ModerationEntry{{Value: "203.0.113.5"}}
	assert.True(t, isBlocked(t, h, "203.0.113.5:4000"))
	assert.Equal(t, int64(2), svc.lists.Load())
}
