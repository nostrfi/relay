package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
)

// fakeRepository implements repository.Repository with instrumented,
// no-op maintenance calls so the ticker loop can be tested without a real
// database.
type fakeRepository struct {
	purgeCalls      atomic.Int64
	checkpointCalls atomic.Int64
}

func (f *fakeRepository) SaveEvent(ctx context.Context, event *nostr.Event) (bool, error) {
	return true, nil
}
func (f *fakeRepository) QueryEvents(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return nil, nil
}
func (f *fakeRepository) QueryEventsSorted(ctx context.Context, filter nostr.Filter) ([]*nostr.Event, error) {
	return nil, nil
}
func (f *fakeRepository) PurgeExpired(ctx context.Context) (int64, error) {
	f.purgeCalls.Add(1)
	return 0, nil
}
func (f *fakeRepository) Checkpoint(ctx context.Context) error {
	f.checkpointCalls.Add(1)
	return nil
}
func (f *fakeRepository) Close() error { return nil }

func TestMaintenanceServiceRunsOnInterval(t *testing.T) {
	repo := &fakeRepository{}
	m := NewMaintenanceService(repo, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()

	m.Run(ctx)

	assert.GreaterOrEqual(t, repo.purgeCalls.Load(), int64(2), "expected at least two sweeps in the given window")
	assert.Equal(t, repo.purgeCalls.Load(), repo.checkpointCalls.Load(), "every purge should be followed by a checkpoint")
}

func TestMaintenanceServiceDisabledWithNonPositiveInterval(t *testing.T) {
	repo := &fakeRepository{}
	m := NewMaintenanceService(repo, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	m.Run(ctx)

	assert.Equal(t, int64(0), repo.purgeCalls.Load(), "a non-positive interval must disable the worker")
}

func TestMaintenanceServiceStopsOnContextCancel(t *testing.T) {
	repo := &fakeRepository{}
	m := NewMaintenanceService(repo, 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()

	time.Sleep(15 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return promptly after context cancellation")
	}
}
