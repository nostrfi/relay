package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

	"relay/internal/relay/handler"
	"relay/internal/relay/repository"
	"relay/internal/relay/service"
	"relay/pkg/metrics"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTestRelay(t *testing.T) (*httptest.Server, repository.Repository, func()) {
	t.Helper()
	return startTestRelayWithLimits(t, handler.RelayInfo{}, handler.ResourceLimits{})
}

func startTestRelayWithLimits(t *testing.T, info handler.RelayInfo, limits handler.ResourceLimits) (*httptest.Server, repository.Repository, func()) {
	t.Helper()
	return startTestRelayFull(t, info, limits, handler.AuthConfig{}, handler.WebsocketConfig{})
}

func startTestRelayFull(t *testing.T, info handler.RelayInfo, limits handler.ResourceLimits, auth handler.AuthConfig, ws handler.WebsocketConfig) (*httptest.Server, repository.Repository, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "relay-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := repository.NewDuckDBRepository(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open repository: %v", err)
	}

	svc := service.NewRelayService(repo)
	h := handler.NewRelayHandlerFull(svc, info, limits, auth, ws, "test")
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

	cfg, err := handler.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	assert.Equal(t, "Config Test Relay", cfg.RelayInfo.Name)
	assert.Equal(t, "Testing YAML config", cfg.RelayInfo.Description)
	// Version is not configurable via YAML — it comes from the binary
	assert.Equal(t, "", cfg.RelayInfo.Version)
}

func TestLandingPage(t *testing.T) {
	server, _, cleanup := startTestRelay(t)
	defer cleanup()

	client := server.Client()
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	// Simulate a regular browser request (no WebSocket headers, no nostr+json accept)
	req.Header.Set("Accept", "text/html")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/html")

	body := make([]byte, 8192)
	n, _ := resp.Body.Read(body)
	body = body[:n]

	assert.Contains(t, string(body), "<!DOCTYPE html>")
	assert.Contains(t, string(body), "Nostr Relay")
	assert.Contains(t, string(body), "Supported NIPs")
	assert.Contains(t, string(body), "NIP-1")
	assert.Contains(t, string(body), "NIP-11")
	assert.NotContains(t, string(body), "Connect")
	assert.Contains(t, string(body), "test") // build version injected via NewRelayHandler
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

	var info handler.RelayInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	assert.Equal(t, "Nostr Relay", info.Name)
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
	limitation := &handler.RelayLimitation{MaxContentLength: 10}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxEventTags: 2}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{CreatedAtUpperLimit: 60, CreatedAtLowerLimit: 60}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MinPowDifficulty: 8}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{AuthRequired: true}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxFilters: 1}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxSubscriptions: 1}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxSubidLength: 5}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxLimit: 2}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limitation := &handler.RelayLimitation{MaxMessageLength: 100}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{})
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
	limits := handler.ResourceLimits{MessagesPerSecond: 2}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{}, limits)
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

	// Force SaveEvent to fail by closing the repository out from under the
	// running relay, then confirm the client sees only the generic message.
	repo.Close()

	ev := signedEvent(t, 1, "hi", nil)
	msg, _ := json.Marshal([]any{"EVENT", ev})
	c.WriteMessage(websocket.TextMessage, msg)

	okMsg := c.readOK(t)
	assert.Equal(t, false, okMsg[2])
	assert.Equal(t, "error: failed to save event", okMsg[3])
}

func TestResourceLimitsMaxConnectionsConcurrent(t *testing.T) {
	limits := handler.ResourceLimits{MaxConnections: 5}
	server, _, cleanup := startTestRelayWithLimits(t, handler.RelayInfo{}, limits)
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

	_, err = handler.LoadConfig()
	assert.Error(t, err, "loading a config with payment_required: true should fail since no payment mechanism exists")
}

func TestNip42EndpointBinding(t *testing.T) {
	const canonicalURL = "wss://relay.test.local"
	auth := handler.AuthConfig{RelayURL: canonicalURL}
	limitation := &handler.RelayLimitation{RestrictedWrites: true}
	server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{}, auth, handler.WebsocketConfig{})
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
	auth := handler.AuthConfig{RelayURL: canonicalURL, MaxEventAgeSeconds: 600}
	limitation := &handler.RelayLimitation{RestrictedWrites: true}
	server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{Limitation: limitation}, handler.ResourceLimits{}, auth, handler.WebsocketConfig{})
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
		server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, handler.AuthConfig{}, handler.WebsocketConfig{Mode: "development"})
		defer cleanup()
		dialWithOrigin(t, server, "https://anything.example", true)
	})

	t.Run("production mode allows a configured origin", func(t *testing.T) {
		ws := handler.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, handler.AuthConfig{}, ws)
		defer cleanup()
		dialWithOrigin(t, server, "https://allowed.example", true)
	})

	t.Run("production mode denies an unlisted origin", func(t *testing.T) {
		ws := handler.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, handler.AuthConfig{}, ws)
		defer cleanup()
		dialWithOrigin(t, server, "https://denied.example", false)
	})

	t.Run("production mode denies an absent origin", func(t *testing.T) {
		ws := handler.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, handler.AuthConfig{}, ws)
		defer cleanup()
		dialWithOrigin(t, server, "", false)
	})

	t.Run("production mode denies a malformed origin", func(t *testing.T) {
		ws := handler.WebsocketConfig{Mode: "production", AllowedOrigins: []string{"https://allowed.example"}}
		server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, handler.AuthConfig{}, ws)
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
	auth := handler.AuthConfig{RelayURL: canonicalURL}
	server, _, cleanup := startTestRelayFull(t, handler.RelayInfo{}, handler.ResourceLimits{}, auth, handler.WebsocketConfig{})
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

	_, err = handler.LoadConfig()
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

	cfg, err := handler.LoadConfig()
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

	cfg, err := handler.LoadConfig()
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

	cfg, err := handler.LoadConfig()
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	assert.Equal(t, "127.0.0.1:9090", cfg.Server.ListenAddr)
	assert.Equal(t, 15, cfg.Server.ShutdownTimeoutSeconds)
	assert.Equal(t, "/var/lib/relay/custom.db", cfg.Storage.DBPath)
}

func TestHealthz(t *testing.T) {
	mux := handler.NewMux(handler.NewRelayHandler(nil, handler.RelayInfo{}, "test"), func(context.Context) error { return nil })
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
		mux := handler.NewMux(handler.NewRelayHandler(nil, handler.RelayInfo{}, "test"), func(context.Context) error { return nil })
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
		mux := handler.NewMux(handler.NewRelayHandler(nil, handler.RelayInfo{}, "test"), func(context.Context) error {
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

	mux := handler.NewMux(handler.NewRelayHandler(nil, handler.RelayInfo{}, "test"), repo.Ping)
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
func startTestMuxServer(t *testing.T) (*httptest.Server, repository.Repository, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "relay-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := repository.NewDuckDBRepository(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("failed to open repository: %v", err)
	}
	svc := service.NewRelayService(repo)
	relayHandler := handler.NewRelayHandler(svc, handler.RelayInfo{}, "test")
	server := httptest.NewServer(handler.NewMux(relayHandler, repo.Ping))
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
