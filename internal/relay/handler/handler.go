package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log/slog"
	"net/http"
	"relay/internal/relay/service"
	"sync"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type RelayHandler struct {
	service   service.RelayService
	clients   sync.Map // map[*Client]bool
	relayInfo RelayInfo
}

type RelayInfo struct {
	Name          string           `json:"name,omitzero" mapstructure:"name"`
	Description   string           `json:"description,omitzero" mapstructure:"description"`
	Pubkey        string           `json:"pubkey,omitzero" mapstructure:"pubkey"`
	Contact       string           `json:"contact,omitzero" mapstructure:"contact"`
	SupportedNips []int            `json:"supported_nips,omitzero" mapstructure:"supported_nips"`
	Software      string           `json:"software,omitzero" mapstructure:"software"`
	Version       string           `json:"version,omitzero" mapstructure:"version"`
	Limitation    *RelayLimitation `json:"limitation,omitzero" mapstructure:"limitation"`
}

type RelayLimitation struct {
	MaxMessageLength    int  `json:"max_message_length,omitzero" mapstructure:"max_message_length"`
	MaxSubscriptions    int  `json:"max_subscriptions,omitzero" mapstructure:"max_subscriptions"`
	MaxFilters          int  `json:"max_filters,omitzero" mapstructure:"max_filters"`
	MaxLimit            int  `json:"max_limit,omitzero" mapstructure:"max_limit"`
	MaxSubidLength      int  `json:"max_subid_length,omitzero" mapstructure:"max_subid_length"`
	MaxEventTags        int  `json:"max_event_tags,omitzero" mapstructure:"max_event_tags"`
	MaxContentLength    int  `json:"max_content_length,omitzero" mapstructure:"max_content_length"`
	MinPowDifficulty    int  `json:"min_pow_difficulty,omitzero" mapstructure:"min_pow_difficulty"`
	AuthRequired        bool `json:"auth_required,omitzero" mapstructure:"auth_required"`
	PaymentRequired     bool `json:"payment_required,omitzero" mapstructure:"payment_required"`
	RestrictedWrites    bool `json:"restricted_writes,omitzero" mapstructure:"restricted_writes"`
	CreatedAtLowerLimit int  `json:"created_at_lower_limit,omitzero" mapstructure:"created_at_lower_limit"`
	CreatedAtUpperLimit int  `json:"created_at_upper_limit,omitzero" mapstructure:"created_at_upper_limit"`
}

type Config struct {
	RelayInfo RelayInfo `mapstructure:"relay_info"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

type Client struct {
	handler       *RelayHandler
	conn          *websocket.Conn
	subscriptions sync.Map // map[string][]nostr.Filter
	mu            sync.Mutex
	challenge     string
	authPubkey    string
	negSessions   sync.Map // map[string]*NegentropySession
}

type NegentropySession struct {
	id      string
	filter  nostr.Filter
	storage *negentropy.Negentropy
}

func NewRelayHandler(service service.RelayService, info RelayInfo) *RelayHandler {
	if info.Name == "" {
		info.Name = "Nostr Relay"
	}
	if info.Description == "" {
		info.Description = "A minimal Nostr relay written in Go."
	}
	if len(info.SupportedNips) == 0 {
		info.SupportedNips = []int{1, 2, 9, 11, 22, 28, 40, 42, 70, 71, 77}
	}
	if info.Software == "" {
		info.Software = "https://github.com/nostrfi/relay"
	}
	if info.Version == "" {
		info.Version = "1.0.0"
	}

	return &RelayHandler{
		service:   service,
		relayInfo: info,
	}
}

func (h *RelayHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Accept") == "application/nostr+json" {
		w.Header().Set("Content-Type", "application/nostr+json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		json.NewEncoder(w).Encode(h.relayInfo)
		return
	}

	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		slog.Error("upgrade error", "error", err)
		return
	}

	client := &Client{
		handler: h,
		conn:    conn,
	}
	h.clients.Store(client, true)

	// NIP-42: Send AUTH challenge
	client.challenge = fmt.Sprintf("%x", nostr.GeneratePrivateKey()[:16])
	h.sendAuth(client, client.challenge)

	defer func() {
		h.clients.Delete(client)
		conn.Close()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		h.handleMessage(client, message)
	}
}

func (h *RelayHandler) handleMessage(c *Client, msg []byte) {
	var raw []json.RawMessage
	if err := json.Unmarshal(msg, &raw); err != nil {
		h.sendNotice(c, "error: invalid JSON")
		return
	}

	if len(raw) < 2 {
		h.sendNotice(c, "error: invalid message format")
		return
	}

	var msgType string
	if err := json.Unmarshal(raw[0], &msgType); err != nil {
		h.sendNotice(c, "error: invalid message type")
		return
	}

	switch msgType {
	case "EVENT":
		var ev nostr.Event
		if err := json.Unmarshal(raw[1], &ev); err != nil {
			h.sendOK(c, "", false, "error: invalid event")
			return
		}
		h.handleEvent(c, &ev)
	case "REQ":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNotice(c, "error: invalid subscription ID")
			return
		}
		var filters []nostr.Filter
		for i := 2; i < len(raw); i++ {
			var f nostr.Filter
			if err := json.Unmarshal(raw[i], &f); err == nil {
				filters = append(filters, f)
			}
		}
		h.handleReq(c, subID, filters)
	case "CLOSE":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNotice(c, "error: invalid subscription ID")
			return
		}
		c.subscriptions.Delete(subID)
	case "AUTH":
		var ev nostr.Event
		if err := json.Unmarshal(raw[1], &ev); err != nil {
			h.sendNotice(c, "error: invalid AUTH event")
			return
		}
		if ok, err := ev.CheckSignature(); err != nil || !ok {
			h.sendNotice(c, "error: AUTH event signature verification failed")
			return
		}
		if ev.Kind != 22242 {
			h.sendNotice(c, "error: invalid AUTH event kind")
			return
		}
		challengeFound := false
		relayFound := false
		for _, tag := range ev.Tags {
			if len(tag) >= 2 {
				if tag[0] == "challenge" && tag[1] == c.challenge {
					challengeFound = true
				}
				if tag[0] == "relay" {
					// We could verify relay URL here, but keeping it simple for now
					relayFound = true
				}
			}
		}
		if !challengeFound || !relayFound {
			h.sendNotice(c, "error: AUTH event missing challenge or relay tag")
			return
		}
		c.authPubkey = ev.PubKey
		slog.Info("Client authenticated", "pubkey", c.authPubkey)
	case "NEG-OPEN":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNegErr(c, "", "invalid: invalid subscription ID")
			return
		}
		var filter nostr.Filter
		if err := json.Unmarshal(raw[2], &filter); err != nil {
			h.sendNegErr(c, subID, "invalid: invalid filter")
			return
		}
		var initialMsg string
		if err := json.Unmarshal(raw[3], &initialMsg); err != nil {
			h.sendNegErr(c, subID, "invalid: invalid initial message")
			return
		}
		slog.Info("NEG-OPEN received", "subID", subID, "initialMsg", initialMsg)
		h.handleNegOpen(c, subID, filter, initialMsg)
	case "NEG-MSG":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNegErr(c, "", "invalid: invalid subscription ID")
			return
		}
		var msgHex string
		if err := json.Unmarshal(raw[2], &msgHex); err != nil {
			h.sendNegErr(c, subID, "invalid: invalid message hex")
			return
		}
		slog.Info("NEG-MSG received", "subID", subID, "msgHex", msgHex)
		h.handleNegMsg(c, subID, msgHex)
	case "NEG-CLOSE":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNegErr(c, "", "invalid: invalid subscription ID")
			return
		}
		c.negSessions.Delete(subID)
	}
}

func (h *RelayHandler) handleEvent(c *Client, ev *nostr.Event) {
	if ok, err := ev.CheckSignature(); err != nil || !ok {
		h.sendOK(c, ev.ID, false, "invalid: signature verification failed")
		return
	}

	// NIP-70: Protected Events
	protected := false
	for _, tag := range ev.Tags {
		if len(tag) >= 1 && tag[0] == "-" {
			protected = true
			break
		}
	}

	if protected {
		if c.authPubkey == "" {
			h.sendOK(c, ev.ID, false, "auth-required: this event may only be published by its author")
			return
		}
		if c.authPubkey != ev.PubKey {
			h.sendOK(c, ev.ID, false, "restricted: this event may only be published by its author")
			return
		}
	}

	success, err := h.service.SaveEvent(context.Background(), ev)
	if err != nil {
		h.sendOK(c, ev.ID, false, fmt.Sprintf("error: %v", err))
		return
	}

	if success {
		h.sendOK(c, ev.ID, true, "")
		h.broadcast(ev)
	} else {
		h.sendOK(c, ev.ID, false, "error: failed to save event")
	}
}

func (h *RelayHandler) handleReq(c *Client, subID string, filters []nostr.Filter) {
	c.subscriptions.Store(subID, filters)

	seenIDs := make(map[string]bool)
	for _, f := range filters {
		events, err := h.service.QueryEvents(context.Background(), f)
		if err != nil {
			slog.Error("query error", "error", err)
			continue
		}
		for _, ev := range events {
			if !seenIDs[ev.ID] {
				h.sendEvent(c, subID, ev)
				seenIDs[ev.ID] = true
			}
		}
	}
	h.sendEOSE(c, subID)
}

func (h *RelayHandler) broadcast(ev *nostr.Event) {
	h.clients.Range(func(key, value any) bool {
		client := key.(*Client)
		client.subscriptions.Range(func(sKey, sValue any) bool {
			subID := sKey.(string)
			filters := sValue.([]nostr.Filter)
			for _, f := range filters {
				if f.Matches(ev) {
					h.sendEvent(client, subID, ev)
					break
				}
			}
			return true
		})
		return true
	})
}

func (h *RelayHandler) handleNegOpen(c *Client, subID string, filter nostr.Filter, initialMsgHex string) {
	initialMsg, err := hex.DecodeString(initialMsgHex)
	if err != nil {
		h.sendNegErr(c, subID, "invalid: could not decode hex message")
		return
	}

	events, err := h.service.QueryEventsSorted(context.Background(), filter)
	if err != nil {
		h.sendNegErr(c, subID, fmt.Sprintf("error: %v", err))
		return
	}

	items := negentropy.NewVector()
	for _, ev := range events {
		idBytes, err := hex.DecodeString(ev.ID)
		if err != nil {
			continue
		}
		items.Insert(uint64(ev.CreatedAt), idBytes)
	}
	items.Seal()

	storage, err := negentropy.NewNegentropy(items, 0)
	if err != nil {
		h.sendNegErr(c, subID, fmt.Sprintf("error: %v", err))
		return
	}

	session := &NegentropySession{
		id:      subID,
		filter:  filter,
		storage: storage,
	}
	c.negSessions.Store(subID, session)

	response, err := storage.Reconcile(initialMsg)
	if err != nil {
		h.sendNegErr(c, subID, fmt.Sprintf("error: %v", err))
		return
	}

	h.sendNegMsg(c, subID, hex.EncodeToString(response))
}

func (h *RelayHandler) handleNegMsg(c *Client, subID string, msgHex string) {
	val, ok := c.negSessions.Load(subID)
	if !ok {
		h.sendNegErr(c, subID, "closed: session not found")
		return
	}
	session := val.(*NegentropySession)

	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		h.sendNegErr(c, subID, "invalid: could not decode hex message")
		return
	}

	response, err := session.storage.Reconcile(msg)
	if err != nil {
		h.sendNegErr(c, subID, fmt.Sprintf("error: %v", err))
		return
	}

	if len(response) == 0 {
		// reconciliation complete or nothing to send
		return
	}

	h.sendNegMsg(c, subID, hex.EncodeToString(response))
}

func (h *RelayHandler) sendEvent(c *Client, subID string, ev *nostr.Event) {
	msg, _ := json.Marshal([]any{"EVENT", subID, ev})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendOK(c *Client, eventID string, ok bool, reason string) {
	msg, _ := json.Marshal([]any{"OK", eventID, ok, reason})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendNotice(c *Client, message string) {
	msg, _ := json.Marshal([]any{"NOTICE", message})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendAuth(c *Client, challenge string) {
	msg, _ := json.Marshal([]any{"AUTH", challenge})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendEOSE(c *Client, subID string) {
	msg, _ := json.Marshal([]any{"EOSE", subID})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendNegErr(c *Client, subID string, reason string) {
	msg, _ := json.Marshal([]any{"NEG-ERR", subID, reason})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}

func (h *RelayHandler) sendNegMsg(c *Client, subID string, msgHex string) {
	slog.Info("Sending NEG-MSG", "subID", subID, "msgHex", msgHex)
	msg, _ := json.Marshal([]any{"NEG-MSG", subID, msgHex})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.WriteMessage(websocket.TextMessage, msg)
}
