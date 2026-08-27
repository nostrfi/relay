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

// connQueueItemOverhead charges every queued item for the bookkeeping
// heap it occupies regardless of payload — its entry in items plus
// allocator rounding — so zero-length frames cannot ride a zero payload
// charge to unbounded slot growth: 256 KiB / 64 B caps even an
// empty-frame flood at ~4096 queued items.
const connQueueItemOverhead = 64

// queueItem is one unit of worker work: a client message to handle, or —
// when notice is non-empty — a NOTICE for the worker to write. Notices
// ride the queue because the pump must never touch the connection's
// write path: a write serializes on c.mu behind a possibly stalled worker
// write and spends a write deadline of its own, and spawning goroutines
// for them instead lets a stalled peer accumulate one blocked goroutine
// per notice. The worker already owns ordered writes; notices simply
// take their place in that order.
type queueItem struct {
	msg    []byte
	notice string
}

// messageQueue is the hand-off between a connection's read pump and its
// worker: unbounded in slots, bounded in bytes, and non-blocking for the
// producer, because the pump has to stay parked at ReadMessage for
// disconnects to be observed at all.
type messageQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []queueItem
	bytes  int
	closed bool
}

func newMessageQueue() *messageQueue {
	q := &messageQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func itemCost(item queueItem) int {
	return len(item.msg) + len(item.notice) + connQueueItemOverhead
}

// push appends a client message without ever blocking. It reports false
// when the byte budget is exhausted — the caller's cue to drop the
// connection, not the message: silently losing one message would
// desynchronize the client's view of its own subscriptions. An oversized
// message is still accepted when the queue is empty, so an operator who
// configures max_message_length above the budget gets a queue that holds
// one message at a time rather than a relay that refuses every large
// frame.
func (q *messageQueue) push(msg []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return true // teardown is already underway; the message is moot
	}
	item := queueItem{msg: msg}
	if q.bytes > 0 && q.bytes+itemCost(item) > connQueueMaxBytes {
		return false
	}
	q.append(item)
	return true
}

// pushNotice queues a NOTICE for the worker to write. Unlike a client
// message, a notice is droppable courtesy: when the budget has no room it
// is discarded rather than costing the client its connection.
func (q *messageQueue) pushNotice(text string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	item := queueItem{notice: text}
	if q.bytes > 0 && q.bytes+itemCost(item) > connQueueMaxBytes {
		return
	}
	q.append(item)
}

func (q *messageQueue) append(item queueItem) {
	q.items = append(q.items, item)
	q.bytes += itemCost(item)
	q.cond.Signal()
}

// pop blocks until an item is available or the queue is closed, reporting
// false only in the latter case.
func (q *messageQueue) pop() (queueItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return queueItem{}, false
	}
	item := q.items[0]
	q.items[0] = queueItem{}
	q.items = q.items[1:]
	q.bytes -= itemCost(item)
	if len(q.items) == 0 {
		q.items = nil // release the drained backing array
	}
	return item, true
}

// close wakes the consumer and discards whatever is still queued.
// Teardown is the only caller, and by then the client is gone or being
// dropped: draining a dead connection's backlog — up to thousands of
// frames, some of them EVENTs whose acceptance path deliberately ignores
// cancellation — would hold the connection slot and conn.Close hostage
// to work the client queued on purpose. The item the worker already
// holds finishes; the rest never run.
func (q *messageQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.items = nil
	q.bytes = 0
	q.cond.Broadcast()
}
