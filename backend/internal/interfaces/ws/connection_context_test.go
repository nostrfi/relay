package ws

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"relay/internal/application"
	"relay/internal/domain/event"
	"relay/internal/domain/moderation"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the connection-scoped context contract
// (nostrfi/workspace#56): a disconnect cancels queries running on the
// connection's behalf, does NOT cancel an accepted event's save, and the
// per-connection worker preserves message order. They live in the ws
// package, not tests/, because they need service stubs that observe the
// exact context each call receives — something the end-to-end harness's
// real DuckDB store cannot show.

// stubModerationService answers every call with zero values; a test that
// needs to observe the context a ban check receives sets isPubkeyBanned.
type stubModerationService struct {
	isPubkeyBanned func(ctx context.Context, pubkey string) (bool, error)
}

func (stubModerationService) BanPubkey(context.Context, string, string) error { return nil }
func (stubModerationService) UnbanPubkey(context.Context, string) error       { return nil }
func (s stubModerationService) IsPubkeyBanned(ctx context.Context, pubkey string) (bool, error) {
	if s.isPubkeyBanned != nil {
		return s.isPubkeyBanned(ctx, pubkey)
	}
	return false, nil
}
func (stubModerationService) ListBannedPubkeys(context.Context) ([]moderation.ModerationEntry, error) {
	return nil, nil
}
func (stubModerationService) BanEvent(context.Context, string, string) error { return nil }
func (stubModerationService) AllowEvent(context.Context, string) error       { return nil }
func (stubModerationService) ListBannedEvents(context.Context) ([]moderation.ModerationEntry, error) {
	return nil, nil
}
func (stubModerationService) BlockIP(context.Context, string, string) error { return nil }
func (stubModerationService) UnblockIP(context.Context, string) error       { return nil }
func (stubModerationService) ListBlockedIPs(context.Context) ([]moderation.ModerationEntry, error) {
	return nil, nil
}

// stubEventService lets each test decide what a call does with the context
// it was handed; unset hooks answer immediately with zero values.
type stubEventService struct {
	saveEvent   func(ctx context.Context, ev *event.Event) (bool, error)
	queryEvents func(ctx context.Context, f nostr.Filter) ([]*event.Event, error)
}

func (s *stubEventService) SaveEvent(ctx context.Context, ev *event.Event) (bool, error) {
	if s.saveEvent != nil {
		return s.saveEvent(ctx, ev)
	}
	return true, nil
}

func (s *stubEventService) QueryEvents(ctx context.Context, f nostr.Filter) ([]*event.Event, error) {
	if s.queryEvents != nil {
		return s.queryEvents(ctx, f)
	}
	return nil, nil
}

func (s *stubEventService) QueryEventsSorted(ctx context.Context, f nostr.Filter) ([]*event.Event, error) {
	return nil, nil
}

func (s *stubEventService) QueryEventsMatching(context.Context, event.Query) ([]*event.Event, error) {
	return nil, nil
}

func (s *stubEventService) CountEvents(context.Context) (int64, error) { return 0, nil }

func (s *stubEventService) EventStats(context.Context, event.StatsQuery) (event.Stats, error) {
	return event.Stats{}, nil
}

func dialStubRelay(t *testing.T, events application.EventService) *websocket.Conn {
	t.Helper()
	return dialStubRelayFull(t, events, stubModerationService{})
}

func dialStubRelayFull(t *testing.T, events application.EventService, moderation application.ModerationService) *websocket.Conn {
	t.Helper()
	handler := NewRelayHandlerFull(events, moderation, RelayInfo{}, ResourceLimits{}, AuthConfig{}, ModerationConfig{}, WebsocketConfig{}, "test")
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err, "dial failed")
	return conn
}

func signTestEvent(t *testing.T) nostr.Event {
	t.Helper()
	ev := nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   "connection context test",
		Tags:      nostr.Tags{},
	}
	require.NoError(t, ev.Sign(nostr.GeneratePrivateKey()))
	return ev
}

// TestDisconnectCancelsInFlightQuery is the acceptance criterion of
// workspace#56: a client that hangs up mid-REQ must have its query
// cancelled promptly, not run to completion for nobody. It fails by
// timeout under the old synchronous shape, where dispatch inline in the
// read loop meant the disconnect could not even be observed until the
// query had already finished.
func TestDisconnectCancelsInFlightQuery(t *testing.T) {
	queryStarted := make(chan struct{}, 1)
	queryCancelled := make(chan error, 1)
	events := &stubEventService{
		queryEvents: func(ctx context.Context, _ nostr.Filter) ([]*event.Event, error) {
			queryStarted <- struct{}{}
			<-ctx.Done()
			queryCancelled <- ctx.Err()
			return nil, ctx.Err()
		},
	}

	conn := dialStubRelay(t, events)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["REQ","sub1",{"kinds":[1]}]`)))

	select {
	case <-queryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("QueryEvents was never called")
	}

	require.NoError(t, conn.Close())

	select {
	case err := <-queryCancelled:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not cancel the in-flight query")
	}
}

// TestDisconnectDoesNotCancelSave pins the durability half of the design:
// once an event is validated and accepted, its save survives the author's
// disconnect (context.WithoutCancel). Losing an accepted event because the
// socket dropped before the OK went out would just force a re-publish of
// data the relay already had in hand.
func TestDisconnectDoesNotCancelSave(t *testing.T) {
	saveStarted := make(chan struct{}, 1)
	saveOutcome := make(chan error, 1)
	events := &stubEventService{
		saveEvent: func(ctx context.Context, _ *event.Event) (bool, error) {
			saveStarted <- struct{}{}
			// The pump observes the disconnect and cancels the connection
			// context while this save is still in flight. A context derived
			// with WithoutCancel never fires Done, so only the timer path
			// can win; under a revert to the plain connection context the
			// Done path wins almost immediately.
			select {
			case <-ctx.Done():
				saveOutcome <- ctx.Err()
			case <-time.After(500 * time.Millisecond):
				saveOutcome <- nil
			}
			return true, nil
		},
	}

	conn := dialStubRelay(t, events)
	ev := signTestEvent(t)
	payload, err := ev.MarshalJSON()
	require.NoError(t, err)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["EVENT",`+string(payload)+`]`)))

	select {
	case <-saveStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("SaveEvent was never called")
	}

	require.NoError(t, conn.Close())

	select {
	case err := <-saveOutcome:
		assert.NoError(t, err, "an accepted event's save must survive the author's disconnect")
	case <-time.After(2 * time.Second):
		t.Fatal("SaveEvent never resolved")
	}
}

// TestDisconnectDoesNotCancelBanCheck pins the other half of the
// acceptance path: clients publish fire-and-forget, so the disconnect
// often lands while the ban check — the gate in front of the save — is
// still running. Cancelling it rejects the event before SaveEvent is ever
// reached, losing the publish exactly as surely as a cancelled save would
// (this was caught live: a publish-then-hang-up probe lost its event to
// "moderation check failed: context canceled" when only the save was
// disconnect-proof).
func TestDisconnectDoesNotCancelBanCheck(t *testing.T) {
	checkStarted := make(chan struct{}, 1)
	checkOutcome := make(chan error, 1)
	moderation := stubModerationService{
		isPubkeyBanned: func(ctx context.Context, _ string) (bool, error) {
			checkStarted <- struct{}{}
			select {
			case <-ctx.Done():
				checkOutcome <- ctx.Err()
			case <-time.After(500 * time.Millisecond):
				checkOutcome <- nil
			}
			return false, nil
		},
	}

	conn := dialStubRelayFull(t, &stubEventService{}, moderation)
	ev := signTestEvent(t)
	payload, err := ev.MarshalJSON()
	require.NoError(t, err)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["EVENT",`+string(payload)+`]`)))

	select {
	case <-checkStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("IsPubkeyBanned was never called")
	}

	require.NoError(t, conn.Close())

	select {
	case err := <-checkOutcome:
		assert.NoError(t, err, "the ban check gating an accepted publish must survive the author's disconnect")
	case <-time.After(2 * time.Second):
		t.Fatal("IsPubkeyBanned never resolved")
	}
}

// TestQueueOverflowDisconnectsAndCancels pins the pump's never-block
// contract: with the worker stuck in a slow query, a client flooding the
// connection must not wedge the pump behind a full queue — where a
// disconnect would go unobserved and cancellation would be unreachable.
// Instead, overrunning the queue's byte budget tears the connection down,
// which cancels the in-flight query, with no client-side disconnect
// involved at all.
func TestQueueOverflowDisconnectsAndCancels(t *testing.T) {
	queryStarted := make(chan struct{}, 1)
	queryCancelled := make(chan error, 1)
	events := &stubEventService{
		queryEvents: func(ctx context.Context, _ nostr.Filter) ([]*event.Event, error) {
			queryStarted <- struct{}{}
			<-ctx.Done()
			queryCancelled <- ctx.Err()
			return nil, ctx.Err()
		},
	}

	conn := dialStubRelay(t, events)
	defer conn.Close()
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["REQ","sub1",{"kinds":[1]}]`)))

	select {
	case <-queryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("QueryEvents was never called")
	}

	// Flood past the byte budget while the worker is stuck. Writes may
	// start failing once the relay drops the connection — that is the
	// expected outcome, not a test failure.
	filler := strings.Repeat("x", 8<<10)
	for i := 0; i < 2*connQueueMaxBytes/len(filler); i++ {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(filler)); err != nil {
			break
		}
	}

	select {
	case err := <-queryCancelled:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("queue overflow did not tear down the connection and cancel the query")
	}
}

// TestEmptyFrameFloodStillOverflows pins the per-item overhead charge:
// zero-length frames add no payload bytes, so without a per-item cost the
// byte budget would never arm against them and the queue's slot count
// would grow without bound while the worker is busy.
func TestEmptyFrameFloodStillOverflows(t *testing.T) {
	queryStarted := make(chan struct{}, 1)
	queryCancelled := make(chan error, 1)
	events := &stubEventService{
		queryEvents: func(ctx context.Context, _ nostr.Filter) ([]*event.Event, error) {
			queryStarted <- struct{}{}
			<-ctx.Done()
			queryCancelled <- ctx.Err()
			return nil, ctx.Err()
		},
	}

	conn := dialStubRelay(t, events)
	defer conn.Close()
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["REQ","sub1",{"kinds":[1]}]`)))

	select {
	case <-queryStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("QueryEvents was never called")
	}

	for i := 0; i < 2*connQueueMaxBytes/connQueueItemOverhead; i++ {
		if err := conn.WriteMessage(websocket.TextMessage, nil); err != nil {
			break
		}
	}

	select {
	case err := <-queryCancelled:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("empty-frame flood did not overflow the queue")
	}
}

// TestTeardownDiscardsQueuedMessages pins queue.close's discard
// semantics: once a connection is being torn down, only the worker's
// in-flight message finishes — the buffered backlog never runs. Draining
// it would hold the connection slot hostage to attacker-queued work,
// EVENTs especially, whose acceptance path deliberately ignores
// cancellation.
func TestTeardownDiscardsQueuedMessages(t *testing.T) {
	var saveCalls atomic.Int32
	firstSaveStarted := make(chan struct{}, 1)
	releaseFirstSave := make(chan struct{})
	events := &stubEventService{
		saveEvent: func(context.Context, *event.Event) (bool, error) {
			if saveCalls.Add(1) == 1 {
				firstSaveStarted <- struct{}{}
				<-releaseFirstSave
			}
			return true, nil
		},
	}

	conn := dialStubRelay(t, events)
	for i := 0; i < 3; i++ {
		ev := signTestEvent(t)
		payload, err := ev.MarshalJSON()
		require.NoError(t, err)
		require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["EVENT",`+string(payload)+`]`)))
	}

	select {
	case <-firstSaveStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("SaveEvent was never called")
	}

	// The worker is inside save #1; events #2 and #3 sit in the queue.
	// Disconnect, let teardown reach queue.close, then release the save.
	require.NoError(t, conn.Close())
	time.Sleep(200 * time.Millisecond)
	close(releaseFirstSave)
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(1), saveCalls.Load(),
		"teardown must discard the queued backlog, not drain it through the worker")
}

// TestMessagesHandledInOrder pins the single-worker guarantee: the pump
// hands messages to one worker, so back-to-back messages from a client are
// handled strictly in arrival order. The slow save would lose the race
// against the immediate query under any concurrent-dispatch regression.
func TestMessagesHandledInOrder(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, step)
	}

	events := &stubEventService{
		saveEvent: func(context.Context, *event.Event) (bool, error) {
			time.Sleep(50 * time.Millisecond)
			record("save")
			return true, nil
		},
		queryEvents: func(context.Context, nostr.Filter) ([]*event.Event, error) {
			record("query")
			return nil, nil
		},
	}

	conn := dialStubRelay(t, events)
	defer conn.Close()

	ev := signTestEvent(t)
	payload, err := ev.MarshalJSON()
	require.NoError(t, err)
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["EVENT",`+string(payload)+`]`)))
	require.NoError(t, conn.WriteMessage(websocket.TextMessage, []byte(`["REQ","sub1",{"kinds":[1]}]`)))

	// EOSE for the REQ means both messages have been fully handled — the
	// worker cannot have reached the query before finishing the save.
	deadline := time.Now().Add(5 * time.Second)
	for {
		require.NoError(t, conn.SetReadDeadline(deadline))
		_, msg, err := conn.ReadMessage()
		require.NoError(t, err, "connection closed before EOSE arrived")
		if strings.HasPrefix(string(msg), `["EOSE"`) {
			break
		}
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"save", "query"}, order)
}
