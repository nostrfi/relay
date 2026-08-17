package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
)

// dialAndSkipAuth connects and reads past the relay's initial NIP-42 AUTH
// challenge, which every connection receives immediately on upgrade.
func dialAndSkipAuth(relayURL string) (*websocket.Conn, error) {
	c, _, err := websocket.DefaultDialer.Dial(relayURL, nil)
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.ReadMessage()
	c.SetReadDeadline(time.Time{})
	return c, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// publishOutcome classifies a relay response to a published EVENT. The
// relay has two independent rate limiters (messages_per_second, checked
// before a message is even parsed, which replies with a NOTICE; and
// events_per_second, checked inside EVENT handling, which replies with
// OK false) — both must be recognized as rate-limited, not as a hard
// rejection or an ordinary success.
type publishOutcome int

const (
	outcomeUnrelated publishOutcome = iota
	outcomeAccepted
	outcomeRateLimited
	outcomeRejected
)

func classifyPublishResponse(raw []byte) (publishOutcome, string) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return outcomeUnrelated, ""
	}
	var msgType string
	json.Unmarshal(arr[0], &msgType)

	switch msgType {
	case "OK":
		var ok bool
		var reason string
		if len(arr) > 2 {
			json.Unmarshal(arr[2], &ok)
		}
		if len(arr) > 3 {
			json.Unmarshal(arr[3], &reason)
		}
		if ok {
			return outcomeAccepted, ""
		}
		if strings.HasPrefix(reason, "rate-limited") {
			return outcomeRateLimited, reason
		}
		return outcomeRejected, reason
	case "NOTICE":
		var notice string
		if len(arr) > 1 {
			json.Unmarshal(arr[1], &notice)
		}
		if strings.HasPrefix(notice, "rate-limited") {
			return outcomeRateLimited, notice
		}
		return outcomeRejected, notice
	default:
		return outcomeUnrelated, ""
	}
}

// publishUntilAccepted writes ev on c and retries on a rate-limited
// response (with a short backoff) until the relay accepts it, rejects it
// for a non-rate-limit reason, or a read/write error occurs. It returns the
// time the relay's OK arrived, for scenarios that need N events reliably
// stored rather than measuring raw publish throughput (which
// runSustainedPublish does separately, without retrying).
func publishUntilAccepted(c *websocket.Conn, ev nostr.Event) (time.Time, error) {
	msg, err := json.Marshal([]any{"EVENT", ev})
	if err != nil {
		return time.Time{}, err
	}
	for attempt := 0; attempt < 100; attempt++ {
		if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
			return time.Time{}, err
		}
		for {
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, raw, err := c.ReadMessage()
			c.SetReadDeadline(time.Time{})
			if err != nil {
				return time.Time{}, err
			}
			outcome, reason := classifyPublishResponse(raw)
			switch outcome {
			case outcomeAccepted:
				return time.Now(), nil
			case outcomeRateLimited:
				time.Sleep(100 * time.Millisecond)
				goto retry
			case outcomeRejected:
				return time.Time{}, fmt.Errorf("event rejected: %s", reason)
			default:
				continue // unrelated message on this connection; keep waiting
			}
		}
	retry:
	}
	return time.Time{}, fmt.Errorf("gave up after repeated rate-limit retries")
}

// summarize computes latency percentiles over a set of samples. Percentiles
// are 0 when no samples succeeded.
func summarize(name string, attempted, succeeded, failed int, latencies []time.Duration) ScenarioResult {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(p * float64(len(latencies)-1))
		return latencies[idx]
	}
	var max time.Duration
	if len(latencies) > 0 {
		max = latencies[len(latencies)-1]
	}
	return ScenarioResult{
		Name:      name,
		Attempted: attempted,
		Succeeded: succeeded,
		Failed:    failed,
		P50:       pct(0.50),
		P95:       pct(0.95),
		P99:       pct(0.99),
		Max:       max,
	}
}

// runConnectionRamp opens n connections concurrently and measures the time
// from dial to receiving the initial AUTH challenge (a connection is not
// meaningfully "up" until it has).
func runConnectionRamp(relayURL string, n int) ScenarioResult {
	var wg sync.WaitGroup
	latencies := make([]time.Duration, n)
	ok := make([]bool, n)
	conns := make([]*websocket.Conn, n)

	start := time.Now()
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t0 := time.Now()
			c, err := dialAndSkipAuth(relayURL)
			if err != nil {
				return
			}
			latencies[i] = time.Since(t0)
			ok[i] = true
			conns[i] = c
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}

	var valid []time.Duration
	succeeded := 0
	for i, v := range ok {
		if v {
			succeeded++
			valid = append(valid, latencies[i])
		}
	}
	res := summarize("connection_ramp", n, succeeded, n-succeeded, valid)
	res.ThroughputPerSec = float64(succeeded) / elapsed.Seconds()
	return res
}

// runSustainedPublish holds n connections open, each publishing at
// ratePerConn events/sec for duration, and measures the
// write-EVENT-to-receive-response round-trip latency of each publish.
// Unlike publishUntilAccepted, this does not retry on rate-limiting: a
// rate-limited response is exactly what this scenario measures capacity
// against, so it counts as a failure rather than being absorbed.
func runSustainedPublish(relayURL string, n int, ratePerConn float64, duration time.Duration) ScenarioResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var latencies []time.Duration
	var succeeded, failed, rateLimited atomic.Int64

	interval := time.Duration(float64(time.Second) / ratePerConn)

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := dialAndSkipAuth(relayURL)
			if err != nil {
				failed.Add(1)
				return
			}
			defer c.Close()

			sk := nostr.GeneratePrivateKey()
			pk, _ := nostr.GetPublicKey(sk)

			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			deadline := time.Now().Add(duration)
			for time.Now().Before(deadline) {
				<-ticker.C
				ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "loadtest sustained publish"}
				ev.Sign(sk)
				msg, _ := json.Marshal([]any{"EVENT", ev})

				t0 := time.Now()
				if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
					failed.Add(1)
					continue
				}
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, raw, err := c.ReadMessage()
				c.SetReadDeadline(time.Time{})
				if err != nil {
					failed.Add(1)
					continue
				}
				lat := time.Since(t0)

				switch outcome, _ := classifyPublishResponse(raw); outcome {
				case outcomeAccepted:
					succeeded.Add(1)
					mu.Lock()
					latencies = append(latencies, lat)
					mu.Unlock()
				case outcomeRateLimited:
					rateLimited.Add(1)
					failed.Add(1)
				default:
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	total := int(succeeded.Load() + failed.Load())
	res := summarize("sustained_publish", total, int(succeeded.Load()), int(failed.Load()), latencies)
	res.ThroughputPerSec = float64(succeeded.Load()) / duration.Seconds()
	if rateLimited.Load() > 0 {
		res.Notes = fmt.Sprintf("%d of %d failures were rate-limited (resource_limits.events_per_second / messages_per_second)", rateLimited.Load(), failed.Load())
	}
	return res
}

// runLiveFanout opens `subscribers` connections subscribed to a filter
// unique to this run, then reliably publishes fanoutEvents from a separate
// connection (retrying through rate limits via publishUntilAccepted, since
// this scenario measures fanout delivery, not publish throughput),
// measuring publish-acceptance-to-delivery latency for every subscriber
// that receives every event.
func runLiveFanout(relayURL string, subscribers, fanoutEvents int) ScenarioResult {
	marker := randomHex(8)

	subConns := make([]*websocket.Conn, 0, subscribers)
	for range subscribers {
		c, err := dialAndSkipAuth(relayURL)
		if err != nil {
			continue
		}
		req, _ := json.Marshal([]any{"REQ", "loadtest_" + marker, nostr.Filter{Tags: nostr.TagMap{"loadtest": {marker}}}})
		c.WriteMessage(websocket.TextMessage, req)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				break
			}
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				continue
			}
			var msgType string
			json.Unmarshal(arr[0], &msgType)
			if msgType == "EOSE" {
				break
			}
		}
		c.SetReadDeadline(time.Time{})
		subConns = append(subConns, c)
	}
	defer func() {
		for _, c := range subConns {
			c.Close()
		}
	}()

	var publishTimesMu sync.Mutex
	publishTimes := make(map[string]time.Time, fanoutEvents)

	var latenciesMu sync.Mutex
	var latencies []time.Duration
	var received atomic.Int64

	var readerWg sync.WaitGroup
	for _, c := range subConns {
		readerWg.Add(1)
		go func(c *websocket.Conn) {
			defer readerWg.Done()
			for {
				_, raw, err := c.ReadMessage()
				if err != nil {
					return
				}
				var arr []json.RawMessage
				if err := json.Unmarshal(raw, &arr); err != nil {
					continue
				}
				var msgType string
				json.Unmarshal(arr[0], &msgType)
				if msgType != "EVENT" {
					continue
				}
				var ev nostr.Event
				json.Unmarshal(arr[2], &ev)

				publishTimesMu.Lock()
				t0, ok := publishTimes[ev.ID]
				publishTimesMu.Unlock()
				if ok {
					latenciesMu.Lock()
					latencies = append(latencies, time.Since(t0))
					latenciesMu.Unlock()
				}
				received.Add(1)
			}
		}(c)
	}

	published := 0
	pubConn, err := dialAndSkipAuth(relayURL)
	if err == nil {
		sk := nostr.GeneratePrivateKey()
		pk, _ := nostr.GetPublicKey(sk)
		for range fanoutEvents {
			ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "loadtest fanout", Tags: nostr.Tags{{"loadtest", marker}}}
			ev.Sign(sk)

			acceptedAt, err := publishUntilAccepted(pubConn, ev)
			if err != nil {
				break
			}
			published++
			publishTimesMu.Lock()
			publishTimes[ev.ID] = acceptedAt
			publishTimesMu.Unlock()
		}
		pubConn.Close()
	}

	// Give in-flight fanout deliveries time to arrive, then force every
	// reader goroutine to exit by setting an already-past deadline.
	time.Sleep(2 * time.Second)
	for _, c := range subConns {
		c.SetReadDeadline(time.Now())
	}
	readerWg.Wait()

	expected := published * len(subConns)
	res := summarize("live_fanout", expected, int(received.Load()), expected-int(received.Load()), latencies)
	res.Notes = fmt.Sprintf("%d subscriber connections, %d/%d events published (rate-limit retries absorbed)", len(subConns), published, fanoutEvents)
	return res
}

// runNegentropy reliably seeds seedCount events from one author (retrying
// through rate limits via publishUntilAccepted, since this scenario
// measures reconciliation, not publish throughput), then reconciles an
// entirely empty client vector against them in a single NEG-OPEN/NEG-MSG
// session — the worst case for a client with no local overlap. This
// measures one full reconciliation pass, not percentiles over repeated
// trials, so P50/P95/P99/Max all report the same total elapsed time.
func runNegentropy(relayURL string, seedCount int) ScenarioResult {
	pubConn, err := dialAndSkipAuth(relayURL)
	if err != nil {
		return ScenarioResult{Name: "negentropy_full_resync", Notes: fmt.Sprintf("dial failed: %v", err)}
	}
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	now := nostr.Now()
	seeded := 0
	for i := range seedCount {
		ev := nostr.Event{PubKey: pk, CreatedAt: now + nostr.Timestamp(i), Kind: 1, Content: "loadtest negentropy seed"}
		ev.Sign(sk)
		if _, err := publishUntilAccepted(pubConn, ev); err != nil {
			break
		}
		seeded++
	}
	pubConn.Close()

	negConn, err := dialAndSkipAuth(relayURL)
	if err != nil {
		return ScenarioResult{Name: "negentropy_full_resync", Notes: fmt.Sprintf("dial failed: %v", err)}
	}
	defer negConn.Close()

	items := negentropy.NewVector()
	items.Seal()
	clientNeg, err := negentropy.NewNegentropy(items, 0)
	if err != nil {
		return ScenarioResult{Name: "negentropy_full_resync", Notes: fmt.Sprintf("negentropy init failed: %v", err)}
	}

	subID := "loadtest_neg_" + randomHex(4)
	initialMsg, err := clientNeg.Initiate()
	if err != nil {
		return ScenarioResult{Name: "negentropy_full_resync", Notes: fmt.Sprintf("negentropy initiate failed: %v", err)}
	}
	filter := nostr.Filter{Authors: []string{pk}}
	req, _ := json.Marshal([]any{"NEG-OPEN", subID, filter, hex.EncodeToString(initialMsg)})

	start := time.Now()
	negConn.WriteMessage(websocket.TextMessage, req)

	var haveIDs, needIDs []string
	rounds := 0
	negConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	for range 50 {
		_, msg, err := negConn.ReadMessage()
		if err != nil {
			break
		}
		var raw []json.RawMessage
		if err := json.Unmarshal(msg, &raw); err != nil {
			continue
		}
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType != "NEG-MSG" {
			continue
		}
		rounds++
		var msgHex string
		json.Unmarshal(raw[2], &msgHex)
		negMsg, err := hex.DecodeString(msgHex)
		if err != nil {
			break
		}
		queryResp, err := clientNeg.ReconcileWithIDs(negMsg, &haveIDs, &needIDs)
		if err != nil || len(queryResp) == 0 {
			break
		}
		reply, _ := json.Marshal([]any{"NEG-MSG", subID, hex.EncodeToString(queryResp)})
		negConn.WriteMessage(websocket.TextMessage, reply)
	}
	elapsed := time.Since(start)

	return ScenarioResult{
		Name:      "negentropy_full_resync",
		Attempted: seeded,
		Succeeded: len(needIDs),
		Failed:    seeded - len(needIDs),
		P50:       elapsed,
		P95:       elapsed,
		P99:       elapsed,
		Max:       elapsed,
		Notes:     fmt.Sprintf("%d round trips to reconcile an empty client against %d successfully seeded events (%d requested)", rounds, seeded, seedCount),
	}
}
