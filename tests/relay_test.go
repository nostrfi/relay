package tests

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"relay/internal/relay/handler"
	"relay/internal/relay/repository"
	"relay/internal/relay/service"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func startTestRelay(t *testing.T) (*httptest.Server, repository.Repository, func()) {
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
	h := handler.NewRelayHandler(svc, handler.RelayInfo{})
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
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var raw []any
		if err := json.Unmarshal(msg, &raw); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if raw[0] == "OK" {
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
  version: "2.0.0"
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
	assert.Equal(t, "2.0.0", cfg.RelayInfo.Version)
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
