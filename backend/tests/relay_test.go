package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"relay/internal/application"
	"relay/internal/infrastructure/duckdb"
	"relay/internal/interfaces/ws"
	"relay/pkg/metrics"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestRelay(t *testing.T) (*httptest.Server, *duckdb.Repository, func()) {
	t.Helper()
	return startTestRelayWithLimits(t, ws.RelayInfo{}, ws.ResourceLimits{})
}

func startTestRelayWithLimits(t *testing.T, info ws.RelayInfo, limits ws.ResourceLimits) (*httptest.Server, *duckdb.Repository, func()) {
	t.Helper()
	return startTestRelayFull(t, info, limits, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
}

func startTestRelayFull(t *testing.T, info ws.RelayInfo, limits ws.ResourceLimits, auth ws.AuthConfig, moderation ws.ModerationConfig, wsCfg ws.WebsocketConfig) (*httptest.Server, *duckdb.Repository, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "relay-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := duckdb.NewRepository(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open repository: %v", err)
	}

	eventService := application.NewEventService(repo)
	moderationService := application.NewModerationService(repo)
	h := ws.NewRelayHandlerFull(eventService, moderationService, info, limits, auth, moderation, wsCfg, "test")
	server := httptest.NewServer(h)

	cleanup := func() {
		server.Close()
		repo.Close()
		os.RemoveAll(tmpDir)
	}

	return server, repo, cleanup
}

func (c *testClient) readOK(t *testing.T) []any {
	t.Helper()
	return c.readMessageType(t, "OK")
}

func (c *testClient) readClosed(t *testing.T) []any {
	t.Helper()
	return c.readMessageType(t, "CLOSED")
}

func (c *testClient) readNotice(t *testing.T) []any {
	t.Helper()
	return c.readMessageType(t, "NOTICE")
}

// readMessageAny reads and decodes the next message without filtering by
// type. Unlike readMessageType it does not skip AUTH, since callers use it
// after the initial challenge has already been consumed by connectTestRelay.
func (c *testClient) readMessageAny(t *testing.T) []any {
	t.Helper()
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw []any
	if err := json.Unmarshal(msg, &raw); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	return raw
}

// readMessageType reads until it sees a message of the requested type,
// skipping the initial AUTH challenge (and other message types) along the way.
func (c *testClient) readMessageType(t *testing.T, want string) []any {
	t.Helper()
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw []any
		if err := json.Unmarshal(msg, &raw); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if raw[0] == want {
			return raw
		}
		if raw[0] == "AUTH" {
			continue // skip initial AUTH challenge if we are not expecting it
		}
	}
}

type testClient struct {
	*websocket.Conn
}

func connectTestRelay(t *testing.T, server *httptest.Server) *testClient {
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	dialer := websocket.Dialer{}
	c, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Skip initial AUTH
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	c.ReadMessage()
	c.SetReadDeadline(time.Time{})
	return &testClient{c}
}

func TestNip01(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	// 1. Create and sign a NIP-01 event
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nil,
		Content:   "Hello, Nostr!",
	}
	ev.Sign(sk)

	// 2. Publish the event
	msg, _ := json.Marshal([]any{"EVENT", ev})
	err := c.WriteMessage(websocket.TextMessage, msg)
	if err != nil {
		t.Fatalf("write EVENT: %v", err)
	}

	// 3. Receive OK
	okMsg := c.readOK(t)
	if okMsg[2] != true {
		t.Fatalf("expected positive OK, got %v", okMsg)
	}

	// 4. Subscribe to the author
	subID := "test_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{Authors: []string{pk}}})
	err = c.WriteMessage(websocket.TextMessage, req)
	if err != nil {
		t.Fatalf("write REQ: %v", err)
	}

	// 5. Expect EVENT then EOSE
	foundEvent := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read EVENT/EOSE: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var evReceived nostr.Event
			json.Unmarshal(raw[2], &evReceived)
			if evReceived.ID == ev.ID {
				foundEvent = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if !foundEvent {
		t.Fatal("expected to find published event in subscription")
	}
}

// TestNip01PrefixFilter exercises NIP-01 prefix matching on "ids" and
// "authors" end to end over the wire: a filter value shorter than the full
// 64-character hex id/pubkey must match any event whose id/pubkey starts
// with it, and a value that matches no stored event's prefix must return
// nothing.
func TestNip01PrefixFilter(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "prefix filter check"}
	ev.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	okMsg := c.readOK(t)
	if okMsg[2] != true {
		t.Fatalf("expected positive OK, got %v", okMsg)
	}

	drainToEOSE := func(subID string, filter nostr.Filter) bool {
		req, _ := json.Marshal([]any{"REQ", subID, filter})
		c.WriteMessage(websocket.TextMessage, req)
		found := false
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var arr []json.RawMessage
			json.Unmarshal(raw, &arr)
			var msgType string
			json.Unmarshal(arr[0], &msgType)
			if msgType == "EVENT" {
				var evReceived nostr.Event
				json.Unmarshal(arr[2], &evReceived)
				if evReceived.ID == ev.ID {
					found = true
				}
			} else if msgType == "EOSE" {
				break
			}
		}
		return found
	}

	assert.True(t, drainToEOSE("prefix_id_sub", nostr.Filter{IDs: []string{ev.ID[:10]}}), "a short id prefix must match the event")
	assert.True(t, drainToEOSE("prefix_author_sub", nostr.Filter{Authors: []string{pk[:10]}}), "a short author prefix must match the event")
	assert.False(t, drainToEOSE("prefix_mismatch_sub", nostr.Filter{IDs: []string{"deadbeef"}}), "a non-matching prefix must match nothing")
}

// TestTagFidelity exercises full tag round-trip fidelity end to end over the
// wire: a multi-field tag (relay hint + marker), a multi-letter tag name,
// and a single-element tag (e.g. NIP-36's bare "content-warning") must all
// come back from a REQ exactly as published, not truncated to a two-field
// approximation.
func TestTagFidelity(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	tags := nostr.Tags{
		{"e", "0000000000000000000000000000000000000000000000000000000000000001", "wss://relay.example/", "reply"},
		{"published_at", "1700000000"},
		{"content-warning"},
		{"t", "one"},
	}
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      tags,
		Content:   "tag fidelity check",
	}
	ev.Sign(sk)

	msg, _ := json.Marshal([]any{"EVENT", ev})
	if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatalf("write EVENT: %v", err)
	}
	okMsg := c.readOK(t)
	if okMsg[2] != true {
		t.Fatalf("expected positive OK, got %v", okMsg)
	}

	subID := "tag_fidelity_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{IDs: []string{ev.ID}}})
	if err := c.WriteMessage(websocket.TextMessage, req); err != nil {
		t.Fatalf("write REQ: %v", err)
	}

	var received *nostr.Event
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read EVENT/EOSE: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var evReceived nostr.Event
			json.Unmarshal(raw[2], &evReceived)
			if evReceived.ID == ev.ID {
				received = &evReceived
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if received == nil {
		t.Fatal("expected to find published event in subscription")
	}
	assert.Equal(t, tags, received.Tags, "served event tags must match the published tags exactly, including multi-field, multi-letter, and single-element tags")
}

// TestNip01MalformedMessages documents current behavior for syntactically or
// structurally invalid client messages: each must produce a graceful NOTICE
// rejection rather than a dropped connection, silent hang, or panic.
func TestNip01MalformedMessages(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	cases := []struct {
		name    string
		payload string
	}{
		{"not JSON at all", `not json`},
		{"JSON object instead of array", `{"type":"EVENT"}`},
		{"JSON string instead of array", `"EVENT"`},
		{"JSON number instead of array", `42`},
		{"empty array", `[]`},
		{"single-element array", `["EVENT"]`},
		{"non-string message type", `[1, "sub"]`},
		{"EVENT with non-object payload", `["EVENT", "not-an-event"]`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := connectTestRelay(t, server)
			defer c.Close()

			if err := c.WriteMessage(websocket.TextMessage, []byte(tc.payload)); err != nil {
				t.Fatalf("write: %v", err)
			}

			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			raw := c.readMessageAny(t)
			c.SetReadDeadline(time.Time{})

			msgType, _ := raw[0].(string)
			assert.Contains(t, []string{"NOTICE", "OK"}, msgType, "a malformed message must produce a graceful rejection, not silence")
		})
	}
}

// assertNoResponseWithinDeadline confirms the server neither sends a message
// nor proactively closes the connection: the read must fail with a genuine
// deadline-exceeded error, not a close/EOF, which would indicate the server
// dropped the connection instead of silently ignoring the input. A gorilla
// websocket connection is not usable for further reads once a deadline
// fires, so callers must treat c as spent after this call.
func assertNoResponseWithinDeadline(t *testing.T, c *testClient, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	_, _, err := c.ReadMessage()
	require.Error(t, err, "expected no response")
	netErr, ok := err.(net.Error)
	require.Truef(t, ok, "expected a timeout error, got %T: %v", err, err)
	assert.True(t, netErr.Timeout(), "expected the server to silently ignore the input rather than close the connection, got: %v", err)
}

// TestNip01UnknownMessageTypeIsIgnored asserts that a message type outside
// the relay's known vocabulary is silently ignored (per NIP-01, relays MAY
// ignore messages they don't understand) rather than closing the connection.
func TestNip01UnknownMessageTypeIsIgnored(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	unknown, _ := json.Marshal([]any{"FROB", "whatever"})
	if err := c.WriteMessage(websocket.TextMessage, unknown); err != nil {
		t.Fatalf("write: %v", err)
	}

	assertNoResponseWithinDeadline(t, c, 200*time.Millisecond)
}

// TestNip01CloseUnknownSubscription asserts that CLOSE for a subscription ID
// the relay never opened is a silent no-op, not an error or a dropped
// connection.
func TestNip01CloseUnknownSubscription(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	closeMsg, _ := json.Marshal([]any{"CLOSE", "never-opened-sub"})
	if err := c.WriteMessage(websocket.TextMessage, closeMsg); err != nil {
		t.Fatalf("write CLOSE: %v", err)
	}

	assertNoResponseWithinDeadline(t, c, 200*time.Millisecond)
}

// TestNip01ExtraArrayElementsIgnored asserts that trailing elements beyond
// what a message type consumes (e.g. a third element on an EVENT message)
// are ignored rather than rejected.
func TestNip01ExtraArrayElementsIgnored(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "extra trailing element"}
	ev.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", ev, "unexpected-extra-element"})
	if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatalf("write EVENT: %v", err)
	}
	okMsg := c.readOK(t)
	if okMsg[2] != true {
		t.Fatalf("expected positive OK despite a trailing extra array element, got %v", okMsg)
	}
}

// TestNip01ReqWithNoFilters documents current behavior for a REQ carrying no
// filter objects at all: it matches nothing (only EOSE, no stored or live
// events), distinct from a REQ with a single empty filter object `{}`, which
// NIP-01 defines as matching everything.
func TestNip01ReqWithNoFilters(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now() - 5, Kind: 1, Content: "pre-existing event"}
	ev.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	c.readOK(t)

	subID := "no_filters_sub"
	req, _ := json.Marshal([]any{"REQ", subID})
	if err := c.WriteMessage(websocket.TextMessage, req); err != nil {
		t.Fatalf("write REQ: %v", err)
	}

	sawEvent := false
	for {
		_, raw, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var arr []json.RawMessage
		json.Unmarshal(raw, &arr)
		var msgType string
		json.Unmarshal(arr[0], &msgType)
		if msgType == "EVENT" {
			sawEvent = true
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.False(t, sawEvent, "a REQ with zero filter objects must not match any stored event")
}

// TestNip01DuplicateEventSuppression asserts that republishing the exact
// same signed event (identical ID) is idempotent from the client's
// perspective: both publishes report success, and a subscription matching
// the event delivers it exactly once, never twice.
func TestNip01DuplicateEventSuppression(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Content: "publish me twice", Tags: nostr.Tags{{"t", "dup-check"}}}
	ev.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", ev})

	if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatalf("write EVENT (first): %v", err)
	}
	firstOK := c.readOK(t)
	if firstOK[2] != true {
		t.Fatalf("expected positive OK on first publish, got %v", firstOK)
	}

	if err := c.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatalf("write EVENT (duplicate): %v", err)
	}
	secondOK := c.readOK(t)
	if secondOK[2] != true {
		t.Fatalf("expected positive OK on duplicate publish (idempotent), got %v", secondOK)
	}

	subID := "dup_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{IDs: []string{ev.ID}}})
	if err := c.WriteMessage(websocket.TextMessage, req); err != nil {
		t.Fatalf("write REQ: %v", err)
	}

	seen := 0
	for {
		_, raw, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var arr []json.RawMessage
		json.Unmarshal(raw, &arr)
		var msgType string
		json.Unmarshal(arr[0], &msgType)
		if msgType == "EVENT" {
			seen++
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.Equal(t, 1, seen, "a duplicate publish must not cause the event to be delivered more than once")
}

func TestNip02(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish Kind 3 (Follow List) - version 1
	ev1 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 10,
		Kind:      3,
		Tags:      nostr.Tags{{"p", pk}},
		Content:   "",
	}
	ev1.Sign(sk)

	t.Logf("Publishing ev1: %s", ev1.ID)
	msg1, _ := json.Marshal([]any{"EVENT", ev1})
	c.WriteMessage(websocket.TextMessage, msg1)

	// Wait for OK
	resp1 := c.readOK(t)
	t.Logf("OK 1: %v", resp1)

	// 2. Publish Kind 3 (Follow List) - version 2 (newer)
	ev2 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      3,
		Tags:      nostr.Tags{{"p", pk}, {"p", "0000000000000000000000000000000000000000000000000000000000000001"}},
		Content:   "",
	}
	ev2.Sign(sk)

	t.Logf("Publishing ev2: %s", ev2.ID)
	msg2, _ := json.Marshal([]any{"EVENT", ev2})
	c.WriteMessage(websocket.TextMessage, msg2)

	// Wait for OK
	resp2 := c.readOK(t)
	t.Logf("OK 2: %v", resp2)

	// 3. Query Kind 3 for this pubkey
	subID := "nip02_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{Authors: []string{pk}, Kinds: []int{3}}})
	c.WriteMessage(websocket.TextMessage, req)

	// 4. Expect ONLY ev2
	gotEv2 := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var incomingSubID string
			json.Unmarshal(raw[1], &incomingSubID)
			if incomingSubID != subID {
				continue
			}

			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			t.Logf("Received event: %s", ev.ID)
			if ev.ID == ev1.ID {
				t.Fatalf("FAILED: Received old event %s that should have been replaced", ev1.ID)
			}
			if ev.ID == ev2.ID {
				gotEv2 = true
			}
		} else if msgType == "EOSE" {
			var incomingSubID string
			json.Unmarshal(raw[1], &incomingSubID)
			if incomingSubID != subID {
				continue
			}
			break
		}
	}

	if !gotEv2 {
		t.Fatal("FAILED: Did not receive latest event")
	}
}

func TestConfig(t *testing.T) {
	// 1. Create a temporary config file
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
relay_info:
  name: "Config Test Relay"
  description: "Testing YAML config"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// 2. Set up viper to read from this temp directory
	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	cfg, err := ws.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	assert.Equal(t, "Config Test Relay", cfg.RelayInfo.Name)
	assert.Equal(t, "Testing YAML config", cfg.RelayInfo.Description)
	// Version is not configurable via YAML — it comes from the binary
	assert.Equal(t, "", cfg.RelayInfo.Version)
}

func TestPlainBrowserRequest(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	client := server.Client()
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// Simulate a regular browser request (no WebSocket headers, no nostr+json accept).
	// The relay no longer renders an HTML landing page itself — see
	// nostrfi/workspace#28 — it points such requests at the admin dashboard.
	req.Header.Set("Accept", "text/html")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")

	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	body = body[:n]

	assert.Contains(t, string(body), "Nostrfi Relay")
	assert.Contains(t, string(body), "/admin")
	assert.Contains(t, string(body), "application/nostr+json")
}

func TestNip11(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	client := server.Client()
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/nostr+json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/nostr+json", resp.Header.Get("Content-Type"))
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))

	var info ws.RelayInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	assert.Equal(t, "Nostrfi Relay", info.Name)
	assert.Equal(t, "test", info.Version) // build version injected via NewRelayHandler
	assert.Contains(t, info.SupportedNips, 11)
	assert.Contains(t, info.SupportedNips, 17)
	assert.Contains(t, info.SupportedNips, 22)
}

func TestNip22(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish a root event (e.g. kind 1 note)
	rootEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 60,
		Kind:      1,
		Tags:      nil,
		Content:   "Root post",
	}
	rootEv.Sign(sk)
	msgRoot, _ := json.Marshal([]any{"EVENT", rootEv})
	c.WriteMessage(websocket.TextMessage, msgRoot)
	respRoot := c.readOK(t)
	t.Logf("Root OK: %v", respRoot)

	// 2. Publish a comment (Kind 1111) on that root
	commentEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1111,
		Tags: nostr.Tags{
			{"E", rootEv.ID, "", pk},
			{"K", "1"},
			{"P", pk},
			{"e", rootEv.ID, "", pk},
			{"k", "1"},
			{"p", pk},
		},
		Content: "Nice root post!",
	}
	commentEv.Sign(sk)
	msgComment, _ := json.Marshal([]any{"EVENT", commentEv})
	c.WriteMessage(websocket.TextMessage, msgComment)
	respComment := c.readOK(t)
	t.Logf("Comment OK: %v", respComment)

	// 3. Query for the comment by root ID (using uppercase "E" tag)
	subID := "nip22_sub_E"
	filter := nostr.Filter{
		Kinds: []int{1111},
		Tags:  nostr.TagMap{"E": []string{rootEv.ID}},
	}
	req, _ := json.Marshal([]any{"REQ", subID, filter})
	c.WriteMessage(websocket.TextMessage, req)

	foundCommentE := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == commentEv.ID {
				foundCommentE = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if !foundCommentE {
		t.Errorf("FAILED: Comment %s was not found by its 'E' tag", commentEv.ID)
	}

	// 4. Query for the comment by parent ID (using lowercase "e" tag)
	subID2 := "nip22_sub_e"
	filter2 := nostr.Filter{
		Kinds: []int{1111},
		Tags:  nostr.TagMap{"e": []string{rootEv.ID}},
	}
	req2, _ := json.Marshal([]any{"REQ", subID2, filter2})
	c.WriteMessage(websocket.TextMessage, req2)

	foundComment_e := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == commentEv.ID {
				foundComment_e = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if !foundComment_e {
		t.Errorf("FAILED: Comment %s was not found by its 'e' tag", commentEv.ID)
	}
}

func TestNip28(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Kind 40: Create channel
	ev40 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 100,
		Kind:      40,
		Content:   `{"name": "NIP-28 Test Channel", "about": "Testing NIP-28 public chat."}`,
		Tags:      nil,
	}
	ev40.Sign(sk)
	msg40, _ := json.Marshal([]any{"EVENT", ev40})
	c.WriteMessage(websocket.TextMessage, msg40)
	resp40 := c.readOK(t)
	t.Logf("Kind 40 OK: %v", resp40)

	// 2. Kind 41: Set channel metadata (version 1)
	ev41_1 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 50,
		Kind:      41,
		Content:   `{"name": "Updated Name v1"}`,
		Tags:      nostr.Tags{{"e", ev40.ID, "", "root"}},
	}
	ev41_1.Sign(sk)
	msg41_1, _ := json.Marshal([]any{"EVENT", ev41_1})
	c.WriteMessage(websocket.TextMessage, msg41_1)
	resp41_1 := c.readOK(t)
	t.Logf("Kind 41 v1 OK: %v", resp41_1)

	// 3. Kind 41: Set channel metadata (version 2 - newer)
	ev41_2 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      41,
		Content:   `{"name": "Updated Name v2"}`,
		Tags:      nostr.Tags{{"e", ev40.ID, "", "root"}},
	}
	ev41_2.Sign(sk)
	msg41_2, _ := json.Marshal([]any{"EVENT", ev41_2})
	c.WriteMessage(websocket.TextMessage, msg41_2)
	resp41_2 := c.readOK(t)
	t.Logf("Kind 41 v2 OK: %v", resp41_2)

	// 4. Kind 42: Channel message
	ev42 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      42,
		Content:   "Hello NIP-28!",
		Tags:      nostr.Tags{{"e", ev40.ID, "", "root"}},
	}
	ev42.Sign(sk)
	msg42, _ := json.Marshal([]any{"EVENT", ev42})
	c.WriteMessage(websocket.TextMessage, msg42)
	resp42 := c.readOK(t)
	t.Logf("Kind 42 OK: %v", resp42)

	// 5. Kind 43: Hide message
	ev43 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      43,
		Content:   `{"reason": "spam"}`,
		Tags:      nostr.Tags{{"e", ev42.ID}},
	}
	ev43.Sign(sk)
	msg43, _ := json.Marshal([]any{"EVENT", ev43})
	c.WriteMessage(websocket.TextMessage, msg43)
	resp43 := c.readOK(t)
	t.Logf("Kind 43 OK: %v", resp43)

	// 6. Kind 44: Mute user
	ev44 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      44,
		Content:   `{"reason": "too loud"}`,
		Tags:      nostr.Tags{{"p", pk}},
	}
	ev44.Sign(sk)
	msg44, _ := json.Marshal([]any{"EVENT", ev44})
	c.WriteMessage(websocket.TextMessage, msg44)
	resp44 := c.readOK(t)
	t.Logf("Kind 44 OK: %v", resp44)

	// 7. Verify Kind 41 replacement: Only ev41_2 should be returned for Kind 41 with that e tag
	subID := "nip28_sub"
	filter := nostr.Filter{
		Kinds: []int{41},
		Tags:  nostr.TagMap{"e": []string{ev40.ID}},
	}
	req, _ := json.Marshal([]any{"REQ", subID, filter})
	c.WriteMessage(websocket.TextMessage, req)

	gotEv41_2 := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == ev41_1.ID {
				t.Errorf("FAILED: Received old Kind 41 event %s that should have been replaced", ev41_1.ID)
			}
			if ev.ID == ev41_2.ID {
				gotEv41_2 = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if !gotEv41_2 {
		t.Error("FAILED: Latest Kind 41 event was not found")
	}

	// 8. Verify other events are also stored
	subID2 := "nip28_all"
	filter2 := nostr.Filter{
		Kinds: []int{40, 42, 43, 44},
	}
	req2, _ := json.Marshal([]any{"REQ", subID2, filter2})
	c.WriteMessage(websocket.TextMessage, req2)

	foundKinds := make(map[int]bool)
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			foundKinds[ev.Kind] = true
		} else if msgType == "EOSE" {
			break
		}
	}

	assert.True(t, foundKinds[40], "Kind 40 not found")
	assert.True(t, foundKinds[42], "Kind 42 not found")
	assert.True(t, foundKinds[43], "Kind 43 not found")
	assert.True(t, foundKinds[44], "Kind 44 not found")
}

func TestNip09(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish a regular event
	ev1 := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 60,
		Kind:      1,
		Tags:      nil,
		Content:   "To be deleted",
	}
	ev1.Sign(sk)
	msg1, _ := json.Marshal([]any{"EVENT", ev1})
	c.WriteMessage(websocket.TextMessage, msg1)
	resp1 := c.readOK(t)
	t.Logf("OK 1: %v", resp1)

	// 2. Publish a deletion request (Kind 5)
	evDel := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      5,
		Tags:      nostr.Tags{{"e", ev1.ID}},
		Content:   "Deletion request",
	}
	evDel.Sign(sk)
	msgDel, _ := json.Marshal([]any{"EVENT", evDel})
	c.WriteMessage(websocket.TextMessage, msgDel)
	respDel := c.readOK(t)
	t.Logf("OK Del: %v", respDel)

	// 3. Query for the deleted event
	subID := "nip09_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{IDs: []string{ev1.ID}}})
	c.WriteMessage(websocket.TextMessage, req)

	// 4. Expect ONLY EOSE (no EVENT)
	foundDeleted := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == ev1.ID {
				foundDeleted = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if foundDeleted {
		t.Errorf("FAILED: Event %s was found but should have been deleted", ev1.ID)
	}

	// 5. Query for the deletion request itself (it SHOULD still be there)
	subID2 := "nip09_sub2"
	req2, _ := json.Marshal([]any{"REQ", subID2, nostr.Filter{IDs: []string{evDel.ID}}})
	c.WriteMessage(websocket.TextMessage, req2)

	foundDelReq := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == evDel.ID {
				foundDelReq = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}

	if !foundDelReq {
		t.Error("FAILED: Deletion request event should be kept indefinitely")
	}

	// 6. Test 'a' tag deletion (replaceable event)
	evReplaceable := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now() - 30,
		Kind:      30023,
		Tags:      nostr.Tags{{"d", "test-replaceable"}},
		Content:   "Replaceable event to be deleted",
	}
	evReplaceable.Sign(sk)
	msgR, _ := json.Marshal([]any{"EVENT", evReplaceable})
	c.WriteMessage(websocket.TextMessage, msgR)
	c.ReadMessage() // OK

	evDelA := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      5,
		Tags:      nostr.Tags{{"a", fmt.Sprintf("30023:%s:test-replaceable", pk)}},
		Content:   "Deletion request for 'a' tag",
	}
	evDelA.Sign(sk)
	msgDelA, _ := json.Marshal([]any{"EVENT", evDelA})
	c.WriteMessage(websocket.TextMessage, msgDelA)
	c.ReadMessage() // OK

	// Query for the replaceable event
	subID3 := "nip09_sub3"
	req3, _ := json.Marshal([]any{"REQ", subID3, nostr.Filter{Kinds: []int{30023}, Authors: []string{pk}}})
	c.WriteMessage(websocket.TextMessage, req3)

	foundReplaceable := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		if msgType == "EVENT" {
			foundReplaceable = true
		} else if msgType == "EOSE" {
			break
		}
	}

	if foundReplaceable {
		t.Error("FAILED: Replaceable event should have been deleted by 'a' tag")
	}
}

func TestNip40(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish an event that is already expired
	evExpired := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{{"expiration", fmt.Sprintf("%d", nostr.Now()-10)}},
		Content:   "Already expired",
	}
	evExpired.Sign(sk)
	msgExpired, _ := json.Marshal([]any{"EVENT", evExpired})
	c.WriteMessage(websocket.TextMessage, msgExpired)

	respExpired := c.readOK(t)
	t.Logf("Expired OK: %v", respExpired)
	if respExpired[2] == true {
		t.Errorf("FAILED: Expected event to be rejected as already expired")
	}

	// 2. Publish an event that will expire in the future
	evWillExpire := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{{"expiration", fmt.Sprintf("%d", nostr.Now()+2)}},
		Content:   "Will expire soon",
	}
	evWillExpire.Sign(sk)
	msgWillExpire, _ := json.Marshal([]any{"EVENT", evWillExpire})
	c.WriteMessage(websocket.TextMessage, msgWillExpire)
	respWillExpire := c.readOK(t)
	t.Logf("WillExpire OK: %v", respWillExpire)

	// 3. Query for it immediately - should be found
	subID := "nip40_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{IDs: []string{evWillExpire.ID}}})
	c.WriteMessage(websocket.TextMessage, req)

	found := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			found = true
		} else if msgType == "EOSE" {
			break
		}
	}
	if !found {
		t.Errorf("FAILED: Event %s should be found before expiration", evWillExpire.ID)
	}

	// 4. Wait for it to expire
	time.Sleep(3 * time.Second)

	// 5. Query for it again - should NOT be found
	subID2 := "nip40_sub2"
	req2, _ := json.Marshal([]any{"REQ", subID2, nostr.Filter{IDs: []string{evWillExpire.ID}}})
	c.WriteMessage(websocket.TextMessage, req2)

	foundAfter := false
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			foundAfter = true
		} else if msgType == "EOSE" {
			break
		}
	}
	if foundAfter {
		t.Errorf("FAILED: Event %s should NOT be found after expiration", evWillExpire.ID)
	}
}

func TestNip71(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish a Normal Video Event (Kind 21)
	videoEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      21,
		Tags: nostr.Tags{
			{"title", "Test Video"},
			{"imeta", "url https://example.com/video.mp4", "m video/mp4"},
		},
		Content: "A test video description",
	}
	videoEv.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", videoEv})
	c.WriteMessage(websocket.TextMessage, msg)
	resp := c.readOK(t)
	t.Logf("Video OK: %v", resp)

	// 2. Publish an Addressable Normal Video Event (Kind 34235)
	addrVideoEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      34235,
		Tags: nostr.Tags{
			{"d", "test-video-1"},
			{"title", "Test Addressable Video"},
			{"imeta", "url https://example.com/video_addr.mp4", "m video/mp4"},
		},
		Content: "An addressable test video description",
	}
	addrVideoEv.Sign(sk)
	msgAddr, _ := json.Marshal([]any{"EVENT", addrVideoEv})
	c.WriteMessage(websocket.TextMessage, msgAddr)
	respAddr := c.readOK(t)
	t.Logf("Addr Video OK: %v", respAddr)

	// 3. Query for Kind 21
	subID := "sub_kind_21"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{Kinds: []int{21}}})
	c.WriteMessage(websocket.TextMessage, req)

	found21 := false
	for {
		_, msg, _ := c.ReadMessage()
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == videoEv.ID {
				found21 = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.True(t, found21, "Kind 21 video event not found")

	// 4. Query for Kind 34235 by d-tag
	subID2 := "sub_kind_34235"
	req2, _ := json.Marshal([]any{"REQ", subID2, nostr.Filter{Kinds: []int{34235}, Tags: nostr.TagMap{"d": []string{"test-video-1"}}}})
	c.WriteMessage(websocket.TextMessage, req2)

	found34235 := false
	for {
		_, msg, _ := c.ReadMessage()
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == addrVideoEv.ID {
				found34235 = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.True(t, found34235, "Kind 34235 addressable video event not found")
}

func TestNip42And70(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	dialer := websocket.Dialer{}
	c, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// 1. Receive AUTH challenge
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read AUTH: %v", err)
	}
	var authMsg []any
	json.Unmarshal(msg, &authMsg)
	assert.Equal(t, "AUTH", authMsg[0])
	challenge := authMsg[1].(string)

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 2. Publish protected event WITHOUT authentication
	protectedEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{{"-"}},
		Content:   "Protected content",
	}
	protectedEv.Sign(sk)

	msgEv, _ := json.Marshal([]any{"EVENT", protectedEv})
	c.WriteMessage(websocket.TextMessage, msgEv)

	_, resp, _ := c.ReadMessage()
	var okMsg []any
	json.Unmarshal(resp, &okMsg)
	assert.Equal(t, "OK", okMsg[0])
	assert.Equal(t, false, okMsg[2])
	assert.Contains(t, okMsg[3].(string), "auth-required")

	// 3. Authenticate
	authEv := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      22242,
		Tags: nostr.Tags{
			{"challenge", challenge},
			{"relay", server.URL},
		},
		Content: "",
	}
	authEv.Sign(sk)
	msgAuth, _ := json.Marshal([]any{"AUTH", authEv})
	c.WriteMessage(websocket.TextMessage, msgAuth)
	// No response for AUTH message in this implementation except slog,
	// but we can try to publish the event again.

	// 4. Publish protected event WITH authentication
	c.WriteMessage(websocket.TextMessage, msgEv)
	_, resp2, _ := c.ReadMessage()
	json.Unmarshal(resp2, &okMsg)
	assert.Equal(t, "OK", okMsg[0])
	assert.Equal(t, true, okMsg[2], "Protected event should be accepted after AUTH")

	// 5. Try to publish another person's protected event
	sk2 := nostr.GeneratePrivateKey()
	pk2, _ := nostr.GetPublicKey(sk2)
	protectedEv2 := nostr.Event{
		PubKey:    pk2,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{{"-"}},
		Content:   "Someone else's protected content",
	}
	protectedEv2.Sign(sk2)
	msgEv2, _ := json.Marshal([]any{"EVENT", protectedEv2})
	c.WriteMessage(websocket.TextMessage, msgEv2)

	_, resp3, _ := c.ReadMessage()
	json.Unmarshal(resp3, &okMsg)
	assert.Equal(t, "OK", okMsg[0])
	assert.Equal(t, false, okMsg[2], "Should reject someone else's protected event")
	assert.Contains(t, okMsg[3].(string), "restricted")
}

func TestNip77(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	// 1. Publish some events to sync
	var events []nostr.Event
	now := nostr.Now()
	for i := 0; i < 5; i++ {
		ev := nostr.Event{
			PubKey:    pk,
			CreatedAt: now + nostr.Timestamp(i),
			Kind:      1,
			Content:   fmt.Sprintf("Event %d", i),
		}
		ev.Sign(sk)
		events = append(events, ev)
		msg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, msg)
		c.readOK(t)
	}

	// 2. Prepare local items for Negentropy (simulate client side)
	// We'll simulate having 3 of the 5 events
	clientItems := negentropy.NewVector()
	for i := 0; i < 3; i++ {
		idBytes, _ := hex.DecodeString(events[i].ID)
		clientItems.Insert(uint64(events[i].CreatedAt), idBytes)
	}
	clientItems.Seal()
	clientNeg, _ := negentropy.NewNegentropy(clientItems, 0)

	// 3. Start NEG-OPEN
	subID := "neg_sync_1"
	initialMsg, err := clientNeg.Initiate()
	assert.NoError(t, err)
	assert.NotEmpty(t, initialMsg, "Initial message should not be empty")
	filter := nostr.Filter{Authors: []string{pk}}
	req, _ := json.Marshal([]any{"NEG-OPEN", subID, filter, hex.EncodeToString(initialMsg)})
	c.WriteMessage(websocket.TextMessage, req)

	// 4. Handle NEG-MSG exchange
	maxIters := 10
	var haveIDs, needIDs []string
	finished := false
	for i := 0; i < maxIters && !finished; i++ {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read iter %d: %v", i, err)
		}

		var raw []json.RawMessage
		if err := json.Unmarshal(msg, &raw); err != nil {
			t.Fatalf("unmarshal raw iter %d: %v", i, err)
		}
		var msgType string
		json.Unmarshal(raw[0], &msgType)

		switch msgType {
		case "AUTH":
			continue // skip unsolicited AUTH
		case "NEG-ERR":
			var reason string
			json.Unmarshal(raw[2], &reason)
			t.Fatalf("NEG-ERR iter %d: %s", i, reason)
		case "NEG-MSG":
			var respSubID string
			json.Unmarshal(raw[1], &respSubID)
			assert.Equal(t, subID, respSubID)

			var msgHex string
			json.Unmarshal(raw[2], &msgHex)
			negMsg, _ := hex.DecodeString(msgHex)
			queryResp, err := clientNeg.ReconcileWithIDs(negMsg, &haveIDs, &needIDs)
			if err != nil {
				t.Fatalf("Reconcile error iter %d: %v", i, err)
			}

			if len(queryResp) == 0 {
				finished = true
			} else {
				// Send back
				reply, _ := json.Marshal([]any{"NEG-MSG", subID, hex.EncodeToString(queryResp)})
				c.WriteMessage(websocket.TextMessage, reply)
			}
		}
	}

	// 5. Verify results
	// We simulated having 3 events (0, 1, 2) out of 5 (0, 1, 2, 3, 4)
	// So the client should "need" IDs 3 and 4
	assert.Equal(t, 2, len(needIDs), "Client should need 2 events")

	found3 := false
	found4 := false
	for _, id := range needIDs {
		hexID := hex.EncodeToString([]byte(id))
		if hexID == events[3].ID {
			found3 = true
		}
		if hexID == events[4].ID {
			found4 = true
		}
	}
	assert.True(t, found3, "Event 3 ID should be in needIDs")
	assert.True(t, found4, "Event 4 ID should be in needIDs")
}

func TestNip17(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	// Bob (receiver)
	skBob := nostr.GeneratePrivateKey()
	pkBob, _ := nostr.GetPublicKey(skBob)

	// 1. Publish Bob's DM Relay List (Kind 10050)
	cBob := connectTestRelay(t, server)
	defer cBob.Close()

	ev10050 := nostr.Event{
		PubKey:    pkBob,
		CreatedAt: nostr.Now(),
		Kind:      10050,
		Tags:      nostr.Tags{{"relay", "ws://localhost:8080"}},
		Content:   "",
	}
	ev10050.Sign(skBob)
	msg10050, _ := json.Marshal([]any{"EVENT", ev10050})
	cBob.WriteMessage(websocket.TextMessage, msg10050)
	cBob.readOK(t)

	// 2. Alice publishes a Gift Wrap (Kind 1059) for Bob
	cAlice := connectTestRelay(t, server)
	defer cAlice.Close()

	giftWrap := nostr.Event{
		PubKey:    nostr.GeneratePrivateKey()[:32], // random pubkey as per NIP-59
		CreatedAt: nostr.Now(),
		Kind:      1059,
		Tags:      nostr.Tags{{"p", pkBob}},
		Content:   "encrypted_content",
	}
	// We use a random key to sign the gift wrap
	skRandom := nostr.GeneratePrivateKey()
	giftWrap.PubKey, _ = nostr.GetPublicKey(skRandom)
	giftWrap.Sign(skRandom)

	msgGift, _ := json.Marshal([]any{"EVENT", giftWrap})
	cAlice.WriteMessage(websocket.TextMessage, msgGift)
	cAlice.readOK(t)

	// 3. Eve tries to find the Gift Wrap (should NOT see it because she is not authenticated)
	cEve := connectTestRelay(t, server)
	defer cEve.Close()

	subID := "eve_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{Kinds: []int{1059}, Tags: nostr.TagMap{"p": []string{pkBob}}}})
	cEve.WriteMessage(websocket.TextMessage, req)

	foundEve := false
	for {
		_, msg, _ := cEve.ReadMessage()
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			foundEve = true
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.False(t, foundEve, "Eve should NOT see Bob's gift wrap when unauthenticated")

	// 4. Bob authenticates and tries to find the Gift Wrap (SHOULD see it)
	// Bob is already connected as cBob, but we need to authenticate him
	// read initial challenge
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	cBob2, _, _ := websocket.DefaultDialer.Dial(u.String(), nil)
	defer cBob2.Close()

	var authChallenge string
	for {
		_, msg, _ := cBob2.ReadMessage()
		var raw []any
		json.Unmarshal(msg, &raw)
		if raw[0] == "AUTH" {
			authChallenge = raw[1].(string)
			break
		}
	}

	authEv := nostr.Event{
		PubKey:    pkBob,
		CreatedAt: nostr.Now(),
		Kind:      22242,
		Tags:      nostr.Tags{{"challenge", authChallenge}, {"relay", server.URL}},
		Content:   "",
	}
	authEv.Sign(skBob)
	authMsg, _ := json.Marshal([]any{"AUTH", authEv})
	cBob2.WriteMessage(websocket.TextMessage, authMsg)
	// No response for AUTH unless we try to do something

	// Now Bob requests his gift wraps
	subIDBob := "bob_sub"
	reqBob, _ := json.Marshal([]any{"REQ", subIDBob, nostr.Filter{Kinds: []int{1059}, Tags: nostr.TagMap{"p": []string{pkBob}}}})
	cBob2.WriteMessage(websocket.TextMessage, reqBob)

	foundBob := false
	for {
		_, msg, _ := cBob2.ReadMessage()
		var raw []json.RawMessage
		json.Unmarshal(msg, &raw)
		var msgType string
		json.Unmarshal(raw[0], &msgType)
		if msgType == "EVENT" {
			var ev nostr.Event
			json.Unmarshal(raw[2], &ev)
			if ev.ID == giftWrap.ID {
				foundBob = true
			}
		} else if msgType == "EOSE" {
			break
		}
	}
	assert.True(t, foundBob, "Bob SHOULD see his own gift wrap after authentication")
}

func signedEvent(t *testing.T, kind int, content string, tags nostr.Tags) nostr.Event {
	t.Helper()
	sk := nostr.GeneratePrivateKey()
	return signedEventWithKey(t, sk, kind, content, tags)
}

func signedEventWithKey(t *testing.T, sk string, kind int, content string, tags nostr.Tags) nostr.Event {
	t.Helper()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      kind,
		Tags:      tags,
		Content:   content,
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return ev
}

// connectTestRelayWithChallenge dials the relay and returns the connection
// along with the initial NIP-42 AUTH challenge, without discarding it.
func connectTestRelayWithChallenge(t *testing.T, server *httptest.Server) (*testClient, string) {
	t.Helper()
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	dialer := websocket.Dialer{}
	c, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read AUTH challenge: %v", err)
	}
	var raw []any
	if err := json.Unmarshal(msg, &raw); err != nil {
		t.Fatalf("unmarshal AUTH challenge: %v", err)
	}
	if raw[0] != "AUTH" {
		t.Fatalf("expected initial AUTH challenge, got %v", raw)
	}
	return &testClient{c}, raw[1].(string)
}

func buildAuthEvent(t *testing.T, sk, challenge, relayTag string, createdAt nostr.Timestamp) nostr.Event {
	t.Helper()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: createdAt,
		Kind:      22242,
		Tags: nostr.Tags{
			{"challenge", challenge},
			{"relay", relayTag},
		},
	}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign AUTH event: %v", err)
	}
	return ev
}

func TestResourceLimitsContentLength(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxContentLength: 10}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	t.Run("at the boundary is accepted", func(t *testing.T) {
		c := connectTestRelay(t, server)
		defer c.Close()

		ev := signedEvent(t, 1, "1234567890", nil) // exactly 10 characters
		msg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, msg)

		okMsg := c.readOK(t)
		assert.Equal(t, true, okMsg[2])
	})

	t.Run("over the boundary is rejected", func(t *testing.T) {
		c := connectTestRelay(t, server)
		defer c.Close()

		ev := signedEvent(t, 1, "this content is far longer than ten characters", nil)
		msg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, msg)

		okMsg := c.readOK(t)
		assert.Equal(t, false, okMsg[2])
		assert.Equal(t, "invalid: content longer than 10 characters", okMsg[3])
	})
}

func TestResourceLimitsEventTags(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxEventTags: 2}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	tags := nostr.Tags{{"t", "one"}, {"t", "two"}, {"t", "three"}}
	ev := signedEvent(t, 1, "hi", tags)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)

	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "invalid: more than 2 tags", okMsg[3])
}

func TestResourceLimitsTimestampBounds(t *testing.T) {
	limitation := &ws.RelayLimitation{CreatedAtUpperLimit: 60, CreatedAtLowerLimit: 60}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	future := nostr.Event{PubKey: pk, CreatedAt: nostr.Now() + 3600, Kind: 1, Content: "future"}
	future.Sign(sk)
	msg, _ := json.Marshal([]any{"EVENT", future})
	c.WriteMessage(websocket.TextMessage, msg)
	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "invalid: created_at is more than 60 seconds in the future", okMsg[3])

	past := nostr.Event{PubKey: pk, CreatedAt: nostr.Now() - 3600, Kind: 1, Content: "past"}
	past.Sign(sk)
	msg2, _ := json.Marshal([]any{"EVENT", past})
	c.WriteMessage(websocket.TextMessage, msg2)
	okMsg2 := c.readOK(t)
	assert.Equal(t, false, okMsg2[2])
	assert.Equal(t, "invalid: created_at is more than 60 seconds in the past", okMsg2[3])
}

func TestResourceLimitsProofOfWork(t *testing.T) {
	limitation := &ws.RelayLimitation{MinPowDifficulty: 8}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	// An ordinary, unmined event essentially never satisfies an 8-bit
	// difficulty requirement.
	ev := signedEvent(t, 1, "no pow here", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)

	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Contains(t, okMsg[3], "pow: insufficient proof of work")
}

func TestResourceLimitsAuthRequired(t *testing.T) {
	limitation := &ws.RelayLimitation{AuthRequired: true}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	ev := signedEvent(t, 1, "hi", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)

	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "auth-required: this relay requires authentication to publish", okMsg[3])
}

func TestResourceLimitsFilterCount(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxFilters: 1}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	req, _ := json.Marshal([]any{"REQ", "too_many", nostr.Filter{Kinds: []int{1}}, nostr.Filter{Kinds: []int{2}}})
	c.WriteMessage(websocket.TextMessage, req)

	closedMsg := c.readClosed(t)
	assert.Equal(t, "too_many", closedMsg[1])
	assert.Equal(t, "restricted: too many filters, max 1", closedMsg[2])
}

func TestResourceLimitsSubscriptionCount(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxSubscriptions: 1}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	req1, _ := json.Marshal([]any{"REQ", "sub_one", nostr.Filter{Kinds: []int{1}}})
	c.WriteMessage(websocket.TextMessage, req1)
	// Drain EOSE for sub_one before moving on.
	for {
		_, msg, _ := c.ReadMessage()
		var raw []any
		json.Unmarshal(msg, &raw)
		if raw[0] == "EOSE" {
			break
		}
	}

	// Re-issuing the same subscription id must not be rejected: it replaces
	// the existing subscription rather than adding a new one.
	c.WriteMessage(websocket.TextMessage, req1)
	for {
		_, msg, _ := c.ReadMessage()
		var raw []any
		json.Unmarshal(msg, &raw)
		if raw[0] == "EOSE" {
			break
		}
		if raw[0] == "CLOSED" {
			t.Fatalf("re-subscribing the same subscription id should not be rejected: %v", raw)
		}
	}

	// A second, distinct subscription id must be rejected.
	req2, _ := json.Marshal([]any{"REQ", "sub_two", nostr.Filter{Kinds: []int{1}}})
	c.WriteMessage(websocket.TextMessage, req2)
	closedMsg := c.readClosed(t)
	assert.Equal(t, "sub_two", closedMsg[1])
	assert.Equal(t, "restricted: too many subscriptions, max 1", closedMsg[2])
}

func TestResourceLimitsSubidLength(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxSubidLength: 5}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	req, _ := json.Marshal([]any{"REQ", "too-long-a-subscription-id", nostr.Filter{Kinds: []int{1}}})
	c.WriteMessage(websocket.TextMessage, req)

	closedMsg := c.readClosed(t)
	assert.Equal(t, "too-long-a-subscription-id", closedMsg[1])
	assert.Equal(t, "invalid: subscription id longer than 5 characters", closedMsg[2])
}

func TestResourceLimitsMaxLimitClamp(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxLimit: 2}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	for i := range 3 {
		ev := nostr.Event{PubKey: pk, CreatedAt: nostr.Now() - nostr.Timestamp(i), Kind: 1, Content: fmt.Sprintf("event %d", i)}
		ev.Sign(sk)
		msg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, msg)
		c.readOK(t)
	}

	req, _ := json.Marshal([]any{"REQ", "clamp_sub", nostr.Filter{Authors: []string{pk}, Limit: 10}})
	c.WriteMessage(websocket.TextMessage, req)

	received := 0
	for {
		_, msg, _ := c.ReadMessage()
		var raw []any
		json.Unmarshal(msg, &raw)
		if raw[0] == "EVENT" {
			received++
		} else if raw[0] == "EOSE" {
			break
		}
	}
	assert.Equal(t, 2, received, "requested limit should be clamped to MaxLimit, not rejected")
}

func TestResourceLimitsMessageSize(t *testing.T) {
	limitation := &ws.RelayLimitation{MaxMessageLength: 100}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	oversized := make([]byte, 500)
	for i := range oversized {
		oversized[i] = 'a'
	}
	// Wrap as a JSON string array so it is at least well-formed framing;
	// gorilla's read limit closes the connection before content matters.
	msg, _ := json.Marshal([]any{"EVENT", string(oversized)})
	c.WriteMessage(websocket.TextMessage, msg)

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := c.ReadMessage()
	assert.Error(t, err, "server should close the connection when the read limit is exceeded")
}

func TestResourceLimitsRateLimiting(t *testing.T) {
	limits := ws.ResourceLimits{MessagesPerSecond: 2}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{}, limits)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	rateLimited := false
	for range 6 {
		closeMsg, _ := json.Marshal([]any{"CLOSE", "no_such_sub"})
		c.WriteMessage(websocket.TextMessage, closeMsg)
	}

	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	for range 6 {
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		var raw []any
		if err := json.Unmarshal(msg, &raw); err != nil {
			continue
		}
		if raw[0] == "NOTICE" && strings.Contains(fmt.Sprint(raw[1]), "rate-limited") {
			rateLimited = true
			break
		}
	}
	assert.True(t, rateLimited, "expected at least one rate-limited NOTICE once the burst is exhausted")
}

func TestResourceLimitsNoInternalErrorLeak(t *testing.T) {
	server, repo, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	// Force every DB-backed check to fail by closing the repository out from
	// under the running relay, then confirm the client sees only a generic
	// message. The moderation ban check runs first and hits this before
	// SaveEvent would, so it's what actually produces the response here.
	repo.Close()

	ev := signedEvent(t, 1, "hi", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)

	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "error: failed to process event", okMsg[3])
}

func TestResourceLimitsMaxConnectionsConcurrent(t *testing.T) {
	limits := ws.ResourceLimits{MaxConnections: 5}
	server, _, cleanup := startTestRelayWithLimits(t, ws.RelayInfo{}, limits)
	defer cleanup()

	const attempts = 15
	var wg sync.WaitGroup
	var accepted, rejected atomic.Int64

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, _ := url.Parse(server.URL)
			u.Scheme = "ws"
			dialer := websocket.Dialer{}
			c, resp, err := dialer.Dial(u.String(), nil)
			if err != nil {
				if resp != nil && resp.StatusCode == http.StatusServiceUnavailable {
					rejected.Add(1)
					return
				}
				rejected.Add(1)
				return
			}
			accepted.Add(1)
			// Hold the connection open briefly so concurrent dials genuinely
			// race against the connection cap instead of finishing serially.
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}()
	}
	wg.Wait()

	assert.LessOrEqual(t, accepted.Load(), int64(5), "accepted connections must never exceed max_connections")
	assert.Greater(t, rejected.Load(), int64(0), "some concurrent connections beyond the cap should have been rejected")
	assert.Equal(t, int64(attempts), accepted.Load()+rejected.Load())
}

// TestConcurrentSubscriptionsNoCrossTalk exercises live-fanout broadcast
// under concurrency: three authors each publish from their own connection
// at the same time, into three disjoint per-author subscriptions plus one
// subscription matching all three. Every subscriber must receive exactly
// the events its filter matches — no cross-talk, no missed live event —
// which requires no coordination beyond what the relay's own broadcast
// logic (internal/interfaces/ws/subscription.go) provides.
func TestConcurrentSubscriptionsNoCrossTalk(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	const eventsPerAuthor = 5

	type author struct {
		name string
		sk   string
		pk   string
	}
	authors := make([]author, 3)
	for i := range authors {
		sk := nostr.GeneratePrivateKey()
		pk, _ := nostr.GetPublicKey(sk)
		authors[i] = author{name: fmt.Sprintf("author%d", i), sk: sk, pk: pk}
	}
	allPks := []string{authors[0].pk, authors[1].pk, authors[2].pk}

	// Establish every connection up front, on the main test goroutine:
	// connectTestRelay calls t.Fatalf on failure, which must not run on a
	// spawned goroutine.
	subConns := map[string]*testClient{}
	for _, a := range authors {
		subConns[a.name] = connectTestRelay(t, server)
	}
	subConns["all"] = connectTestRelay(t, server)
	pubConns := make([]*testClient, len(authors))
	for i := range authors {
		pubConns[i] = connectTestRelay(t, server)
	}
	defer func() {
		for _, c := range subConns {
			c.Close()
		}
		for _, c := range pubConns {
			c.Close()
		}
	}()

	for _, a := range authors {
		req, _ := json.Marshal([]any{"REQ", "sub_" + a.name, nostr.Filter{Authors: []string{a.pk}}})
		require.NoError(t, subConns[a.name].WriteMessage(websocket.TextMessage, req))
		subConns[a.name].readMessageType(t, "EOSE")
	}
	reqAll, _ := json.Marshal([]any{"REQ", "sub_all", nostr.Filter{Authors: allPks}})
	require.NoError(t, subConns["all"].WriteMessage(websocket.TextMessage, reqAll))
	subConns["all"].readMessageType(t, "EOSE")

	received := map[string][]nostr.Event{}
	var mu sync.Mutex
	var readerWg sync.WaitGroup
	for key, c := range subConns {
		readerWg.Add(1)
		go func(key string, c *testClient) {
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
				mu.Lock()
				received[key] = append(received[key], ev)
				mu.Unlock()
			}
		}(key, c)
	}

	// Errors from the publisher goroutines are reported via t.Errorf (safe
	// from any goroutine), never t.Fatalf/require (main-goroutine only).
	var pubWg sync.WaitGroup
	for i, a := range authors {
		pubWg.Add(1)
		go func(a author, pc *testClient) {
			defer pubWg.Done()
			for i := range eventsPerAuthor {
				ev := nostr.Event{PubKey: a.pk, CreatedAt: nostr.Now(), Kind: 1, Content: fmt.Sprintf("%s-%d", a.name, i)}
				ev.Sign(a.sk)
				msg, _ := json.Marshal([]any{"EVENT", ev})
				if err := pc.WriteMessage(websocket.TextMessage, msg); err != nil {
					t.Errorf("publish write failed for %s: %v", a.name, err)
					return
				}
				for {
					_, raw, err := pc.ReadMessage()
					if err != nil {
						t.Errorf("publish read failed for %s: %v", a.name, err)
						return
					}
					var arr []json.RawMessage
					if err := json.Unmarshal(raw, &arr); err != nil {
						continue
					}
					var msgType string
					json.Unmarshal(arr[0], &msgType)
					if msgType == "OK" {
						break
					}
				}
			}
		}(a, pubConns[i])
	}
	pubWg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(received["all"])
		mu.Unlock()
		if n >= eventsPerAuthor*len(authors) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, c := range subConns {
		c.Close()
	}
	readerWg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for _, a := range authors {
		got := received[a.name]
		assert.Len(t, got, eventsPerAuthor, "author %s subscriber should receive exactly its own events", a.name)
		for _, ev := range got {
			assert.Equal(t, a.pk, ev.PubKey, "no cross-talk: subscriber for author %s must not receive another author's event", a.name)
		}
	}
	assert.Len(t, received["all"], eventsPerAuthor*len(authors), "the multi-author subscriber must receive every author's events exactly once")
}

func TestConfigPaymentRequiredRejected(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
relay_info:
  name: "Payment Test Relay"
  limitation:
    payment_required: true
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	_, err = ws.LoadConfig()
	assert.Error(t, err, "loading a config with payment_required: true should fail since no payment mechanism exists")
}

func TestNip42EndpointBinding(t *testing.T) {
	const canonicalURL = "wss://relay.test.local"
	auth := ws.AuthConfig{RelayURL: canonicalURL}
	limitation := &ws.RelayLimitation{RestrictedWrites: true}
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{}, auth, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	publishAndExpect := func(t *testing.T, c *testClient, sk string, wantOK bool) {
		t.Helper()
		ev := signedEventWithKey(t, sk, 1, "hi", nil)
		msg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, msg)
		okMsg := c.readOK(t)
		assert.Equal(t, wantOK, okMsg[2])
	}

	t.Run("matching relay tag authenticates and unlocks publishing", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, canonicalURL, nostr.Now())
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		publishAndExpect(t, c, sk, true)
	})

	t.Run("trailing slash difference does not block authentication", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, canonicalURL+"/", nostr.Now())
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		publishAndExpect(t, c, sk, true)
	})

	t.Run("mismatched relay tag is rejected", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, "wss://different-relay.example", nostr.Now())
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "restricted")
		assert.Contains(t, notice[1], "does not match")

		publishAndExpect(t, c, sk, false)
	})

	t.Run("missing relay tag is rejected", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		pk, _ := nostr.GetPublicKey(sk)
		authEv := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 22242, Tags: nostr.Tags{{"challenge", challenge}}}
		if err := authEv.Sign(sk); err != nil {
			t.Fatalf("sign: %v", err)
		}
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "invalid")
	})

	t.Run("mismatched challenge is rejected", func(t *testing.T) {
		c, _ := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, "not-the-real-challenge", canonicalURL, nostr.Now())
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "invalid")
	})

	t.Run("malformed AUTH event kind is rejected", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		pk, _ := nostr.GetPublicKey(sk)
		authEv := nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Tags: nostr.Tags{{"challenge", challenge}, {"relay", canonicalURL}}}
		if err := authEv.Sign(sk); err != nil {
			t.Fatalf("sign: %v", err)
		}
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "invalid")
	})
}

func TestNip42AuthFreshness(t *testing.T) {
	const canonicalURL = "wss://relay.test.local"
	auth := ws.AuthConfig{RelayURL: canonicalURL, MaxEventAgeSeconds: 600}
	limitation := &ws.RelayLimitation{RestrictedWrites: true}
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Limitation: limitation}, ws.ResourceLimits{}, auth, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	t.Run("fresh event authenticates", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, canonicalURL, nostr.Now())
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		ev := signedEventWithKey(t, sk, 1, "hi", nil)
		pubMsg, _ := json.Marshal([]any{"EVENT", ev})
		c.WriteMessage(websocket.TextMessage, pubMsg)
		okMsg := c.readOK(t)
		assert.Equal(t, true, okMsg[2])
	})

	t.Run("stale event is rejected", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, canonicalURL, nostr.Now()-3600)
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "invalid")
		assert.Contains(t, notice[1], "created_at")
	})

	t.Run("future event is rejected", func(t *testing.T) {
		c, challenge := connectTestRelayWithChallenge(t, server)
		defer c.Close()

		sk := nostr.GeneratePrivateKey()
		authEv := buildAuthEvent(t, sk, challenge, canonicalURL, nostr.Now()+3600)
		msg, _ := json.Marshal([]any{"AUTH", authEv})
		c.WriteMessage(websocket.TextMessage, msg)

		notice := c.readNotice(t)
		assert.Contains(t, notice[1], "invalid")
		assert.Contains(t, notice[1], "created_at")
	})
}

func dialWithOrigin(t *testing.T, server *httptest.Server, origin string, wantAllowed bool) {
	t.Helper()
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	header := http.Header{}
	if origin != "" {
		header.Set("Origin", origin)
	}
	dialer := websocket.Dialer{}
	c, resp, err := dialer.Dial(u.String(), header)
	if wantAllowed {
		if err != nil {
			t.Fatalf("expected dial to succeed for origin %q: %v", origin, err)
		}
		c.Close()
		return
	}
	if err == nil {
		c.Close()
		t.Fatalf("expected dial to be rejected for origin %q", origin)
	}
	if resp != nil {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestWebsocketOriginPolicy(t *testing.T) {
	t.Run("development mode allows any origin", func(t *testing.T) {
		server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{Mode: "development"})
		defer cleanup()
		dialWithOrigin(t, server, "https://anything.example", true)
	})

	t.Run("production mode allows a configured origin", func(t *testing.T) {
		wsCfg := ws.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, wsCfg)
		defer cleanup()
		dialWithOrigin(t, server, "https://allowed.example", true)
	})

	t.Run("production mode denies an unlisted origin", func(t *testing.T) {
		wsCfg := ws.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, wsCfg)
		defer cleanup()
		dialWithOrigin(t, server, "https://denied.example", false)
	})

	t.Run("production mode denies an absent origin", func(t *testing.T) {
		wsCfg := ws.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, wsCfg)
		defer cleanup()
		dialWithOrigin(t, server, "", false)
	})

	t.Run("production mode denies a malformed origin", func(t *testing.T) {
		wsCfg := ws.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, wsCfg)
		defer cleanup()
		dialWithOrigin(t, server, "not a url", false)
	})
}

func TestNip42NoChallengeOrPayloadInLogs(t *testing.T) {
	var buf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prevLogger)

	const canonicalURL = "wss://relay.test.local"
	auth := ws.AuthConfig{RelayURL: canonicalURL}
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{}, ws.ResourceLimits{}, auth, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	// Successful AUTH: block until a follow-up publish confirms it landed,
	// so the "Client authenticated" log line has already been written.
	c, challenge := connectTestRelayWithChallenge(t, server)
	defer c.Close()
	sk := nostr.GeneratePrivateKey()
	authEv := buildAuthEvent(t, sk, challenge, canonicalURL, nostr.Now())
	msg, _ := json.Marshal([]any{"AUTH", authEv})
	c.WriteMessage(websocket.TextMessage, msg)
	ev := signedEventWithKey(t, sk, 1, "hi", nil)
	pubMsg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, pubMsg)
	c.readOK(t)

	// Failed AUTH on a second connection, to exercise the reject path too.
	c2, challenge2 := connectTestRelayWithChallenge(t, server)
	defer c2.Close()
	sk2 := nostr.GeneratePrivateKey()
	badAuthEv := buildAuthEvent(t, sk2, challenge2, "wss://different.example", nostr.Now())
	msg2, _ := json.Marshal([]any{"AUTH", badAuthEv})
	c2.WriteMessage(websocket.TextMessage, msg2)
	c2.readNotice(t)

	logged := buf.String()
	assert.NotContains(t, logged, challenge, "AUTH challenge must never be logged")
	assert.NotContains(t, logged, challenge2, "AUTH challenge must never be logged")
	assert.NotContains(t, logged, authEv.Sig, "AUTH event payload must never be logged")
	assert.NotContains(t, logged, badAuthEv.Sig, "AUTH event payload must never be logged")
}

func TestConfigWebsocketProductionRequiresOrigins(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
websocket:
  mode: production
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	_, err = ws.LoadConfig()
	assert.Error(t, err, "production mode with no allowed_origins should fail to load")
}

func TestConfigWebsocketProductionWithOriginsSucceeds(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
websocket:
  mode: production
  allowed_origins:
    - "https://client.example"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	cfg, err := ws.LoadConfig()
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	assert.Equal(t, "production", cfg.Websocket.Mode)
	assert.Equal(t, []string{"https://client.example"}, cfg.Websocket.AllowedOrigins)
	assert.Equal(t, 600, cfg.Auth.MaxEventAgeSeconds, "default freshness window should apply")
}

func TestConfigServerStorageDefaults(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("relay_info:\n  name: \"Defaults Test Relay\"\n"), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	cfg, err := ws.LoadConfig()
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	assert.Equal(t, ":8080", cfg.Server.ListenAddr, "unset listen_addr should default to the historical hardcoded value")
	assert.Equal(t, 5, cfg.Server.ShutdownTimeoutSeconds, "unset shutdown timeout should default to the historical hardcoded value")
	assert.Equal(t, "db/relay.db", cfg.Storage.DBPath, "unset db_path should default to the historical hardcoded value")
}

func TestConfigServerStorageOverrides(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "relay-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
server:
  listen_addr: "127.0.0.1:9090"
  shutdown_timeout_seconds: 15
storage:
  db_path: "/var/lib/relay/custom.db"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	viper.Reset()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(tmpDir)

	cfg, err := ws.LoadConfig()
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	assert.Equal(t, "127.0.0.1:9090", cfg.Server.ListenAddr)
	assert.Equal(t, 15, cfg.Server.ShutdownTimeoutSeconds)
	assert.Equal(t, "/var/lib/relay/custom.db", cfg.Storage.DBPath)
}

func TestHealthz(t *testing.T) {
	mux := ws.NewMux(ws.NewRelayHandler(nil, nil, ws.RelayInfo{}, "test"), func(context.Context) error { return nil })
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestReadyz(t *testing.T) {
	t.Run("ready when the dependency check succeeds", func(t *testing.T) {
		mux := ws.NewMux(ws.NewRelayHandler(nil, nil, ws.RelayInfo{}, "test"), func(context.Context) error { return nil })
		server := httptest.NewServer(mux)
		defer server.Close()

		resp, err := http.Get(server.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("not ready when the dependency check fails", func(t *testing.T) {
		mux := ws.NewMux(ws.NewRelayHandler(nil, nil, ws.RelayInfo{}, "test"), func(context.Context) error {
			return fmt.Errorf("database unreachable")
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		resp, err := http.Get(server.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestReadyzWithRealRepositoryClosed(t *testing.T) {
	_, repo, cleanup := startTestRelay(t)
	defer cleanup()

	// Prove readyz reflects a genuinely unreachable database, not just a
	// stubbed failure.
	repo.Close()

	mux := ws.NewMux(ws.NewRelayHandler(nil, nil, ws.RelayInfo{}, "test"), repo.Ping)
	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// startTestMuxServer starts a full server (repository, RelayHandler, and the
// production NewMux routing) so metrics tests exercise the exact same
// wiring used by cmd/relay/main.go, including /metrics.
func startTestMuxServer(t *testing.T) (*httptest.Server, *duckdb.Repository, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "relay-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := duckdb.NewRepository(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open repository: %v", err)
	}
	eventService := application.NewEventService(repo)
	moderationService := application.NewModerationService(repo)
	relayHandler := ws.NewRelayHandler(eventService, moderationService, ws.RelayInfo{}, "test")
	server := httptest.NewServer(ws.NewMux(relayHandler, repo.Ping))
	cleanup := func() {
		server.Close()
		repo.Close()
		os.RemoveAll(tmpDir)
	}
	return server, repo, cleanup
}

func scrapeMetrics(t *testing.T, server *httptest.Server) string {
	t.Helper()
	resp, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	return string(body)
}

func TestMetricsExposition(t *testing.T) {
	server, _, cleanup := startTestMuxServer(t)
	defer cleanup()

	// Exercise a representative set of flows so every metric family has
	// something to report, then confirm each is present in the scrape.
	c := connectTestRelay(t, server)
	ev := signedEvent(t, 1, "hi", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	c.readOK(t)

	subID := "metrics_sub"
	req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{Kinds: []int{1}}})
	c.WriteMessage(websocket.TextMessage, req)
	for {
		_, m, _ := c.ReadMessage()
		var raw []any
		json.Unmarshal(m, &raw)
		if raw[0] == "EOSE" {
			break
		}
	}

	// Trigger a rejection (malformed EVENT payload).
	c.WriteMessage(websocket.TextMessage, []byte(`["EVENT", "not-an-event"]`))
	c.readOK(t)

	c.Close()
	time.Sleep(20 * time.Millisecond) // let the disconnect defer run before scraping

	body := scrapeMetrics(t, server)
	for _, name := range []string{
		"relay_connections_active",
		"relay_messages_total",
		"relay_rejections_total",
		"relay_subscriptions_active",
		"relay_query_duration_seconds",
		"relay_events_stored_total",
		"relay_save_failures_total",
	} {
		assert.Contains(t, body, name, "expected metric %q to appear in /metrics output", name)
	}
}

func TestMetricsConnectionsActiveDelta(t *testing.T) {
	server, _, cleanup := startTestMuxServer(t)
	defer cleanup()

	before := testutil.ToFloat64(metrics.ConnectionsActive)

	c := connectTestRelay(t, server)
	during := testutil.ToFloat64(metrics.ConnectionsActive)
	assert.Equal(t, before+1, during, "connecting should increment the active-connections gauge")

	c.Close()
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.ConnectionsActive) == before
	}, time.Second, 5*time.Millisecond, "disconnecting should decrement the active-connections gauge back down")
}

func TestMetricsEventsStoredDelta(t *testing.T) {
	server, _, cleanup := startTestMuxServer(t)
	defer cleanup()

	before := testutil.ToFloat64(metrics.EventsStoredTotal)

	c := connectTestRelay(t, server)
	defer c.Close()
	ev := signedEvent(t, 1, "hi", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	c.readOK(t)

	after := testutil.ToFloat64(metrics.EventsStoredTotal)
	assert.Equal(t, before+1, after, "a successful publish should increment the events-stored counter")
}

func TestNegentropyNoPayloadInLogs(t *testing.T) {
	var buf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prevLogger)

	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	subID := "neg_log_test"
	openMsg, _ := json.Marshal([]any{"NEG-OPEN", subID, nostr.Filter{}, "6100000000"})
	c.WriteMessage(websocket.TextMessage, openMsg)

	// Drain until we see a NEG-MSG (or NEG-ERR) reply, confirming the server
	// has processed NEG-OPEN and logged whatever it's going to log for it.
	for {
		_, m, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw []any
		if err := json.Unmarshal(m, &raw); err != nil {
			continue
		}
		if raw[0] == "NEG-MSG" || raw[0] == "NEG-ERR" {
			break
		}
	}

	logged := buf.String()
	assert.NotContains(t, logged, "6100000000", "the raw Negentropy hex payload must never be logged")
	assert.Contains(t, logged, subID, "the subscription ID may still be logged")
}

// nip98AuthHeader signs a NIP-98 kind-27235 event authorizing a POST to url
// with the given body, and returns the resulting Authorization header
// value ("Nostr <base64>").
func nip98AuthHeader(t *testing.T, sk, rawURL string, body []byte) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	require.NoError(t, err)
	sum := sha256.Sum256(body)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      27235,
		Tags: nostr.Tags{
			{"u", rawURL},
			{"method", http.MethodPost},
			{"payload", hex.EncodeToString(sum[:])},
		},
		Content: "",
	}
	require.NoError(t, ev.Sign(sk))
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	return "Nostr " + base64.StdEncoding.EncodeToString(raw)
}

// callManagement issues a NIP-86 management request against server, signed
// by sk (or unsigned, if sk is empty), and returns the decoded JSON
// response body and HTTP status code.
func callManagement(t *testing.T, server *httptest.Server, sk, method string, params []any) (map[string]any, int) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"method": method, "params": params})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/nostr+json+rpc")
	if sk != "" {
		req.Header.Set("Authorization", nip98AuthHeader(t, sk, server.URL, body))
	}

	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out, resp.StatusCode
}

func TestModerationBanPubkeyRejectsPublish(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	authorSk := nostr.GeneratePrivateKey()
	authorPk, _ := nostr.GetPublicKey(authorSk)

	out, status := callManagement(t, server, operatorSk, "banpubkey", []any{authorPk, "spam"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	c := connectTestRelay(t, server)
	defer c.Close()
	ev := signedEventWithKey(t, authorSk, 1, "should be blocked", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "blocked: this pubkey is not permitted to publish to this relay", okMsg[3])

	out, status = callManagement(t, server, operatorSk, "unbanpubkey", []any{authorPk})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	ev2 := signedEventWithKey(t, authorSk, 1, "should succeed now", nil)
	msg2, _ := json.Marshal([]any{"EVENT", ev2})
	c.WriteMessage(websocket.TextMessage, msg2)
	okMsg2 := c.readOK(t)
	assert.Equal(t, true, okMsg2[2], "unbanning must restore the pubkey's ability to publish")
}

func TestModerationBanEventExcludesFromReq(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	c := connectTestRelay(t, server)
	defer c.Close()

	ev := signedEvent(t, 1, "hide me", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)
	c.readOK(t)

	findEvent := func() bool {
		subID := "mod_req_" + ev.ID[:8]
		req, _ := json.Marshal([]any{"REQ", subID, nostr.Filter{IDs: []string{ev.ID}}})
		c.WriteMessage(websocket.TextMessage, req)
		found := false
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var arr []json.RawMessage
			json.Unmarshal(raw, &arr)
			var msgType string
			json.Unmarshal(arr[0], &msgType)
			if msgType == "EVENT" {
				found = true
			} else if msgType == "EOSE" {
				break
			}
		}
		return found
	}

	require.True(t, findEvent(), "event must be visible before it's banned")

	out, status := callManagement(t, server, operatorSk, "banevent", []any{ev.ID, "reported"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	assert.False(t, findEvent(), "a banned event must not be served, independent of NIP-09")

	out, status = callManagement(t, server, operatorSk, "allowevent", []any{ev.ID})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	assert.True(t, findEvent(), "allowevent must restore visibility")
}

func TestModerationBlockIPRejectsConnection(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	// A connection succeeds before any block is applied.
	c := connectTestRelay(t, server)
	c.Close()

	out, status := callManagement(t, server, operatorSk, "blockip", []any{"127.0.0.1", "abuse"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	require.Error(t, err, "a blocked IP must not be able to open a WebSocket connection")
	if resp != nil {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	out, status = callManagement(t, server, operatorSk, "unblockip", []any{"127.0.0.1"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	c2 := connectTestRelay(t, server)
	defer c2.Close()
}

func TestModerationBlockIPCIDR(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	out, status := callManagement(t, server, operatorSk, "blockip", []any{"127.0.0.0/8", "range block"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"])

	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"
	_, resp, err := websocket.DefaultDialer.Dial(u.String(), nil)
	require.Error(t, err, "a CIDR block must reject an address it contains")
	if resp != nil {
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}
}

func TestNip86SupportedMethods(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	out, status := callManagement(t, server, operatorSk, "supportedmethods", []any{})
	require.Equal(t, http.StatusOK, status)
	methods, ok := out["result"].([]any)
	require.True(t, ok)
	assert.Contains(t, methods, "banpubkey")
	assert.Contains(t, methods, "banevent")
	assert.Contains(t, methods, "blockip")
	assert.NotContains(t, methods, "allowpubkey", "the allow-list methods are intentionally unsupported: no admission allow-list model")
}

func TestNip86ListMethodsReportReason(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	targetSk := nostr.GeneratePrivateKey()
	targetPk, _ := nostr.GetPublicKey(targetSk)
	callManagement(t, server, operatorSk, "banpubkey", []any{targetPk, "spam"})

	out, status := callManagement(t, server, operatorSk, "listbannedpubkeys", []any{})
	require.Equal(t, http.StatusOK, status)
	entries, ok := out["result"].([]any)
	require.True(t, ok)
	require.Len(t, entries, 1)
	entry := entries[0].(map[string]any)
	assert.Equal(t, targetPk, entry["pubkey"])
	assert.Equal(t, "spam", entry["reason"])
}

func TestNip86Unauthorized(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	someoneElseSk := nostr.GeneratePrivateKey()
	targetPk := operatorPk

	t.Run("missing Authorization header", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"method": "supportedmethods", "params": []any{}})
		req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/nostr+json+rpc")
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("signed by a non-operator pubkey", func(t *testing.T) {
		_, status := callManagement(t, server, someoneElseSk, "banpubkey", []any{targetPk, ""})
		assert.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("stale created_at", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"method": "supportedmethods", "params": []any{}})
		sum := sha256.Sum256(body)
		pk, _ := nostr.GetPublicKey(operatorSk)
		ev := nostr.Event{
			PubKey:    pk,
			CreatedAt: nostr.Now() - 3600,
			Kind:      27235,
			Tags: nostr.Tags{
				{"u", server.URL},
				{"method", http.MethodPost},
				{"payload", hex.EncodeToString(sum[:])},
			},
		}
		require.NoError(t, ev.Sign(operatorSk))
		raw, _ := json.Marshal(ev)

		req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/nostr+json+rpc")
		req.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(raw))
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("tampered payload hash", func(t *testing.T) {
		realBody, _ := json.Marshal(map[string]any{"method": "supportedmethods", "params": []any{}})
		authHeader := nip98AuthHeader(t, operatorSk, server.URL, realBody)

		tamperedBody, _ := json.Marshal(map[string]any{"method": "banpubkey", "params": []any{operatorPk, ""}})
		req, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(tamperedBody))
		req.Header.Set("Content-Type", "application/nostr+json+rpc")
		req.Header.Set("Authorization", authHeader)
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a payload hash that doesn't match the actual body must be rejected")
	})
}

// TestNip86RejectsMalformedValues covers the validation added for
// nostrfi/workspace#37. Before it, every one of these calls returned
// {"result": true} and stored a row that could never match a real pubkey,
// event, or connecting address — the operator believed a ban was in force
// while nothing was enforced.
func TestNip86RejectsMalformedValues(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	validHex := strings.Repeat("a", 64)

	cases := []struct {
		name    string
		method  string
		params  []any
		wantErr string
	}{
		{"pubkey too short", "banpubkey", []any{"abc123", "spam"}, "hex characters"},
		{"pubkey not hex", "banpubkey", []any{strings.Repeat("z", 64), "spam"}, "lowercase hex"},
		{"pubkey uppercase hex", "banpubkey", []any{strings.Repeat("A", 64), "spam"}, "lowercase hex"},
		{"pubkey in npub form", "banpubkey", []any{"npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "spam"}, "hex characters"},
		{"unban pubkey malformed", "unbanpubkey", []any{"nope"}, "hex characters"},
		{"event id malformed", "banevent", []any{"not-an-id", "reported"}, "hex characters"},
		{"allow event malformed", "allowevent", []any{"not-an-id"}, "hex characters"},
		{"ip not an address", "blockip", []any{"banana", "abuse"}, "not a valid IP address"},
		{"ip with stray space", "blockip", []any{"127.0.0.1 ", "abuse"}, "not a valid IP address"},
		{"cidr malformed", "blockip", []any{"10.0.0.0/99", "abuse"}, "not a valid IP address"},
		{"unblock ip malformed", "unblockip", []any{"banana"}, "not a valid IP address"},
		{"pubkey too long", "banpubkey", []any{strings.Repeat("a", 65), "spam"}, "hex characters"},
		{"event id too long", "banevent", []any{strings.Repeat("a", 65), "reported"}, "hex characters"},
		{"event id uppercase hex", "banevent", []any{strings.Repeat("A", 64), "reported"}, "lowercase hex"},
		{"allow event uppercase hex", "allowevent", []any{strings.Repeat("A", 64)}, "lowercase hex"},
		{"unban pubkey uppercase hex", "unbanpubkey", []any{strings.Repeat("A", 64)}, "lowercase hex"},
		{"ipv6 with a zone", "blockip", []any{"fe80::1%eth0", "abuse"}, "not a valid IP address"},
		{"cidr without an address", "blockip", []any{"/24", "abuse"}, "not a valid IP address"},

		// The reason rules apply wherever a reason is stored, not just to
		// banpubkey.
		{"reason too long", "banpubkey", []any{validHex, strings.Repeat("x", 501)}, "characters or fewer"},
		{"reason too long on banevent", "banevent", []any{validHex, strings.Repeat("x", 501)}, "characters or fewer"},
		{"reason too long on blockip", "blockip", []any{"198.51.100.7", strings.Repeat("x", 501)}, "characters or fewer"},
		{"reason only whitespace", "banpubkey", []any{validHex, "   "}, "only whitespace"},
		{"reason only whitespace on banevent", "banevent", []any{validHex, "\t\n"}, "only whitespace"},
		{"reason only whitespace on blockip", "blockip", []any{"198.51.100.7", " "}, "only whitespace"},

		// parseValueReasonParams' own guards, which the validation runs after.
		{"no parameters at all", "banpubkey", []any{}, "missing required first parameter"},
		{"empty value", "banpubkey", []any{""}, "non-empty string"},
		{"value is not a string", "banpubkey", []any{42}, "non-empty string"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, status := callManagement(t, server, operatorSk, tc.method, tc.params)

			// NIP-86 method-level failures use the response envelope, not an
			// HTTP error status: only auth failures are a 401.
			require.Equal(t, http.StatusOK, status)
			errMsg, ok := out["error"].(string)
			require.True(t, ok, "expected an error envelope, got %v", out)
			assert.Contains(t, errMsg, tc.wantErr)
			assert.Nil(t, out["result"])
		})
	}
}

// TestNip86RejectedValuesAreNotStored proves the rejection happens before
// the write, so a malformed call cannot leave a row behind.
func TestNip86RejectedValuesAreNotStored(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	_, status := callManagement(t, server, operatorSk, "blockip", []any{"banana", "abuse"})
	require.Equal(t, http.StatusOK, status)

	out, status := callManagement(t, server, operatorSk, "listblockedips", []any{})
	require.Equal(t, http.StatusOK, status)
	blocked, _ := out["result"].([]any)
	assert.Empty(t, blocked, "a rejected blockip must not store a row")

	_, status = callManagement(t, server, operatorSk, "banpubkey", []any{"not-a-pubkey", "spam"})
	require.Equal(t, http.StatusOK, status)

	out, status = callManagement(t, server, operatorSk, "listbannedpubkeys", []any{})
	require.Equal(t, http.StatusOK, status)
	banned, _ := out["result"].([]any)
	assert.Empty(t, banned, "a rejected banpubkey must not store a row")

	_, status = callManagement(t, server, operatorSk, "banevent", []any{"not-an-event", "reported"})
	require.Equal(t, http.StatusOK, status)

	out, status = callManagement(t, server, operatorSk, "listbannedevents", []any{})
	require.Equal(t, http.StatusOK, status)
	bannedEvents, _ := out["result"].([]any)
	assert.Empty(t, bannedEvents, "a rejected banevent must not store a row")
}

// TestNip86ReasonLimitCountsCharactersNotBytes pins the limit to runes. With
// a byte count, a reason written in a language that does not fit in ASCII
// would be refused well before 500 characters — and the dashboard, which
// counts characters, would have accepted it before asking the operator to
// sign.
func TestNip86ReasonLimitCountsCharactersNotBytes(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	targetSk := nostr.GeneratePrivateKey()
	targetPk, _ := nostr.GetPublicKey(targetSk)

	// 400 characters, 800 bytes: comfortably inside the limit as characters,
	// well over it as bytes.
	multibyte := strings.Repeat("é", 400)
	require.Greater(t, len(multibyte), 500, "the fixture must exceed the limit when counted as bytes")

	out, status := callManagement(t, server, operatorSk, "banpubkey", []any{targetPk, multibyte})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, out["result"], "a 400-character reason must be accepted, got %v", out)

	// And the limit still bites at 501 characters.
	out, status = callManagement(t, server, operatorSk, "banpubkey", []any{targetPk, strings.Repeat("é", 501)})
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, out["error"], "characters or fewer")
}

// TestNip86AcceptsValidValues guards against the validation being too
// strict: the forms operators actually use must still work.
func TestNip86AcceptsValidValues(t *testing.T) {
	operatorSk := nostr.GeneratePrivateKey()
	operatorPk, _ := nostr.GetPublicKey(operatorSk)
	server, _, cleanup := startTestRelayFull(t, ws.RelayInfo{Pubkey: operatorPk}, ws.ResourceLimits{}, ws.AuthConfig{}, ws.ModerationConfig{}, ws.WebsocketConfig{})
	defer cleanup()

	targetSk := nostr.GeneratePrivateKey()
	targetPk, _ := nostr.GetPublicKey(targetSk)

	accepted := []struct {
		method string
		params []any
	}{
		{"banpubkey", []any{targetPk, "spam"}},
		{"banpubkey", []any{targetPk, ""}}, // an empty reason stays optional
		{"banevent", []any{strings.Repeat("f", 64), "reported"}},
		{"blockip", []any{"127.0.0.1", "abuse"}},
		{"blockip", []any{"10.0.0.0/8", "range"}},
		{"blockip", []any{"2001:db8::1", "v6"}},
		{"blockip", []any{"2001:db8::/32", "v6 range"}},
	}

	for _, tc := range accepted {
		out, status := callManagement(t, server, operatorSk, tc.method, tc.params)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, true, out["result"], "%s %v should be accepted, got %v", tc.method, tc.params, out)
	}
}
