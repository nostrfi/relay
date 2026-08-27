package ws

import "sync"

// connQueueMaxBytes bounds the per-connection message queue by payload
// bytes, not slots. A slot cap alone multiplies badly: 32 slots at the
// shipped 64 KiB max_message_length is ~2 MiB per connection, which at
// the shipped 1,000-connection cap lets unauthenticated clients pin ~2 GiB
// of heap just by keeping their workers busy. 256 KiB holds four maximum-
// size messages, or a deep burst of ordinary ones, and caps the same
// worst case at ~256 MiB reachable only if every connection attacks at
// once. Overflow is not backpressure — the pump must never block, or it
// stops observing disconnects — it disconnects the client instead.
const connQueueMaxBytes = 256 << 10

// connQueueItemOverhead charges every queued message for the bookkeeping
// heap it occupies regardless of payload — its slice header in items plus
// allocator rounding — so zero-length frames cannot ride a zero payload
// charge to unbounded slot growth: 256 KiB / 64 B caps even an
// empty-frame flood at ~4096 queued items.
const connQueueItemOverhead = 64

// messageQueue is the hand-off between a connection's read pump and its
// worker: unbounded in slots, bounded in bytes, and non-blocking for the
// producer, because the pump has to stay parked at ReadMessage for
// disconnects to be observed at all.
type messageQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  [][]byte
	bytes  int
	closed bool
}

func newMessageQueue() *messageQueue {
	q := &messageQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push appends a message without ever blocking. It reports false when the
// byte budget is exhausted — the caller's cue to drop the connection, not
// the message: silently losing one message would desynchronize the
// client's view of its own subscriptions. An oversized message is still
// accepted when the queue is empty, so an operator who configures
// max_message_length above the budget gets a queue that holds one message
// at a time rather than a relay that refuses every large frame.
func (q *messageQueue) push(msg []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return true // teardown is already underway; the message is moot
	}
	cost := len(msg) + connQueueItemOverhead
	if q.bytes > 0 && q.bytes+cost > connQueueMaxBytes {
		return false
	}
	q.items = append(q.items, msg)
	q.bytes += cost
	q.cond.Signal()
	return true
}

// pop blocks until a message is available or the queue is closed and
// drained, reporting false only in the latter case.
func (q *messageQueue) pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return nil, false
	}
	msg := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	q.bytes -= len(msg) + connQueueItemOverhead
	if len(q.items) == 0 {
		q.items = nil // release the drained backing array
	}
	return msg, true
}

// close wakes the consumer; pop drains whatever is queued, then reports
// exhaustion.
func (q *messageQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
}
