package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"relay/internal/relay/service"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"golang.org/x/time/rate"
)

// NIP-01 machine-readable rejection prefixes, shared across OK, CLOSED, and
// NOTICE responses so clients see one consistent vocabulary.
const (
	prefixInvalid      = "invalid"
	prefixRestricted   = "restricted"
	prefixRateLimited  = "rate-limited"
	prefixAuthRequired = "auth-required"
	prefixPow          = "pow"
	prefixError        = "error"
)

const writeDeadline = 5 * time.Second

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type RelayHandler struct {
	service        service.RelayService
	clients        sync.Map // map[*Client]bool
	relayInfo      RelayInfo
	resourceLimits ResourceLimits
	connCount      atomic.Int64
}

type RelayInfo struct {
	Name          string           `json:"name,omitzero" mapstructure:"name"`
	Description   string           `json:"description,omitzero" mapstructure:"description"`
	Pubkey        string           `json:"pubkey,omitzero" mapstructure:"pubkey"`
	Contact       string           `json:"contact,omitzero" mapstructure:"contact"`
	SupportedNips []int            `json:"supported_nips,omitzero" mapstructure:"supported_nips"`
	Software      string           `json:"software,omitzero" mapstructure:"software"`
	Version       string           `json:"version,omitzero"` // set from build-time ldflags only, not config
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

// ResourceLimits configures operational controls that NIP-11 does not model:
// connection admission and per-connection rate limiting.
type ResourceLimits struct {
	MaxConnections    int `mapstructure:"max_connections"`
	MessagesPerSecond int `mapstructure:"messages_per_second"`
	EventsPerSecond   int `mapstructure:"events_per_second"`
}

type Config struct {
	RelayInfo      RelayInfo      `mapstructure:"relay_info"`
	ResourceLimits ResourceLimits `mapstructure:"resource_limits"`
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

	if cfg.RelayInfo.Limitation != nil && cfg.RelayInfo.Limitation.PaymentRequired {
		return nil, fmt.Errorf("config: relay_info.limitation.payment_required is true but no payment mechanism is implemented; advertising it would be misleading")
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
	msgLimiter    *rate.Limiter
	eventLimiter  *rate.Limiter
}

type NegentropySession struct {
	id      string
	filter  nostr.Filter
	storage *negentropy.Negentropy
}

func NewRelayHandler(service service.RelayService, info RelayInfo, buildVersion string) *RelayHandler {
	return NewRelayHandlerWithLimits(service, info, ResourceLimits{}, buildVersion)
}

func NewRelayHandlerWithLimits(service service.RelayService, info RelayInfo, limits ResourceLimits, buildVersion string) *RelayHandler {
	if info.Name == "" {
		info.Name = "Nostr Relay"
	}
	if info.Description == "" {
		info.Description = "A minimal Nostr relay written in Go."
	}
	if len(info.SupportedNips) == 0 {
		info.SupportedNips = []int{1, 2, 9, 11, 17, 22, 28, 40, 42, 70, 71, 77}
	}
	if info.Software == "" {
		info.Software = "https://github.com/nostrfi/relay"
	}
	info.Version = buildVersion
	if info.Version == "" {
		info.Version = "dev"
	}

	return &RelayHandler{
		service:        service,
		relayInfo:      info,
		resourceLimits: limits,
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

	// Serve HTML landing page for non-WebSocket browser requests
	if !isWebSocketUpgrade(req) {
		h.serveLandingPage(w, req)
		return
	}

	// Reserve a connection slot atomically before upgrading. Checking the
	// count and incrementing it as two separate steps leaves a race window
	// where concurrent requests can all pass the check before any of them
	// is counted, letting more than MaxConnections through.
	if h.resourceLimits.MaxConnections > 0 {
		if h.connCount.Add(1) > int64(h.resourceLimits.MaxConnections) {
			h.connCount.Add(-1)
			http.Error(w, "restricted: too many connections", http.StatusServiceUnavailable)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		slog.Error("upgrade error", "error", err)
		if h.resourceLimits.MaxConnections > 0 {
			h.connCount.Add(-1)
		}
		return
	}

	if h.relayInfo.Limitation != nil && h.relayInfo.Limitation.MaxMessageLength > 0 {
		conn.SetReadLimit(int64(h.relayInfo.Limitation.MaxMessageLength))
	}

	client := &Client{
		handler:      h,
		conn:         conn,
		msgLimiter:   newLimiter(h.resourceLimits.MessagesPerSecond),
		eventLimiter: newLimiter(h.resourceLimits.EventsPerSecond),
	}
	h.clients.Store(client, true)

	// NIP-42: Send AUTH challenge
	client.challenge = fmt.Sprintf("%x", nostr.GeneratePrivateKey()[:16])
	h.sendAuth(client, client.challenge)

	defer func() {
		h.clients.Delete(client)
		if h.resourceLimits.MaxConnections > 0 {
			h.connCount.Add(-1)
		}
		conn.Close()
	}()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if client.msgLimiter != nil && !client.msgLimiter.Allow() {
			h.sendNotice(client, prefixRateLimited+": message rate exceeded")
			continue
		}
		h.handleMessage(client, message)
	}
}

// newLimiter builds a per-connection token-bucket limiter for the configured
// rate. A non-positive rate disables limiting for that dimension.
func newLimiter(perSecond int) *rate.Limiter {
	if perSecond <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(perSecond), perSecond)
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
			h.sendNotice(c, prefixInvalid+": invalid subscription ID")
			return
		}
		limitation := h.relayInfo.Limitation
		if limitation != nil && limitation.MaxSubidLength > 0 && len(subID) > limitation.MaxSubidLength {
			h.sendClosed(c, subID, fmt.Sprintf("%s: subscription id longer than %d characters", prefixInvalid, limitation.MaxSubidLength))
			return
		}
		var filters []nostr.Filter
		for i := 2; i < len(raw); i++ {
			var f nostr.Filter
			if err := json.Unmarshal(raw[i], &f); err == nil {
				filters = append(filters, f)
			}
		}
		if limitation != nil && limitation.MaxFilters > 0 && len(filters) > limitation.MaxFilters {
			h.sendClosed(c, subID, fmt.Sprintf("%s: too many filters, max %d", prefixRestricted, limitation.MaxFilters))
			return
		}
		if limitation != nil && limitation.MaxSubscriptions > 0 {
			if _, exists := c.subscriptions.Load(subID); !exists && countSubscriptions(c) >= limitation.MaxSubscriptions {
				h.sendClosed(c, subID, fmt.Sprintf("%s: too many subscriptions, max %d", prefixRestricted, limitation.MaxSubscriptions))
				return
			}
		}
		if limitation != nil && limitation.MaxLimit > 0 {
			for i := range filters {
				if filters[i].Limit > limitation.MaxLimit {
					filters[i].Limit = limitation.MaxLimit
				}
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
		h.sendOK(c, ev.ID, false, prefixInvalid+": signature verification failed")
		return
	}

	if c.eventLimiter != nil && !c.eventLimiter.Allow() {
		h.sendOK(c, ev.ID, false, prefixRateLimited+": publish rate exceeded")
		return
	}

	limitation := h.relayInfo.Limitation
	if limitation != nil {
		if limitation.MaxContentLength > 0 && len(ev.Content) > limitation.MaxContentLength {
			h.sendOK(c, ev.ID, false, fmt.Sprintf("%s: content longer than %d characters", prefixInvalid, limitation.MaxContentLength))
			return
		}
		if limitation.MaxEventTags > 0 && len(ev.Tags) > limitation.MaxEventTags {
			h.sendOK(c, ev.ID, false, fmt.Sprintf("%s: more than %d tags", prefixInvalid, limitation.MaxEventTags))
			return
		}
		if reason, ok := checkTimestampBounds(ev.CreatedAt, limitation); !ok {
			h.sendOK(c, ev.ID, false, reason)
			return
		}
		if limitation.MinPowDifficulty > 0 {
			if err := nip13.Check(ev.ID, limitation.MinPowDifficulty); err != nil {
				h.sendOK(c, ev.ID, false, fmt.Sprintf("%s: insufficient proof of work: %v", prefixPow, err))
				return
			}
		}
		// A relay-wide auth requirement gates every publish; restricted_writes
		// carries the same meaning here since no separate allow-list exists.
		if (limitation.AuthRequired || limitation.RestrictedWrites) && c.authPubkey == "" {
			h.sendOK(c, ev.ID, false, prefixAuthRequired+": this relay requires authentication to publish")
			return
		}
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
			h.sendOK(c, ev.ID, false, prefixAuthRequired+": this event may only be published by its author")
			return
		}
		if c.authPubkey != ev.PubKey {
			h.sendOK(c, ev.ID, false, prefixRestricted+": this event may only be published by its author")
			return
		}
	}

	success, err := h.service.SaveEvent(context.Background(), ev)
	if err != nil {
		slog.Error("save event failed", "event_id", ev.ID, "error", err)
		h.sendOK(c, ev.ID, false, prefixError+": failed to save event")
		return
	}

	if success {
		h.sendOK(c, ev.ID, true, "")
		h.broadcast(ev)
	} else {
		h.sendOK(c, ev.ID, false, prefixError+": failed to save event")
	}
}

// checkTimestampBounds validates an event's created_at against the
// configured NIP-11 lower/upper offsets from the current time.
func checkTimestampBounds(createdAt nostr.Timestamp, limitation *RelayLimitation) (string, bool) {
	now := nostr.Now()
	if limitation.CreatedAtLowerLimit > 0 {
		lower := now - nostr.Timestamp(limitation.CreatedAtLowerLimit)
		if createdAt < lower {
			return fmt.Sprintf("%s: created_at is more than %d seconds in the past", prefixInvalid, limitation.CreatedAtLowerLimit), false
		}
	}
	if limitation.CreatedAtUpperLimit > 0 {
		upper := now + nostr.Timestamp(limitation.CreatedAtUpperLimit)
		if createdAt > upper {
			return fmt.Sprintf("%s: created_at is more than %d seconds in the future", prefixInvalid, limitation.CreatedAtUpperLimit), false
		}
	}
	return "", true
}

func countSubscriptions(c *Client) int {
	n := 0
	c.subscriptions.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
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
				// NIP-17: Relays MAY protect message metadata by only serving kind:1059 events to users p-tagged on the event
				if ev.Kind == 1059 {
					isRecipient := false
					for _, tag := range ev.Tags {
						if len(tag) >= 2 && tag[0] == "p" && tag[1] == c.authPubkey {
							isRecipient = true
							break
						}
					}
					// Also allow the author to see their own gift wrap
					if !isRecipient && ev.PubKey != c.authPubkey {
						continue
					}
				}

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
					// NIP-17: Kind 1059 access control for live updates
					if ev.Kind == 1059 {
						isRecipient := false
						for _, tag := range ev.Tags {
							if len(tag) >= 2 && tag[0] == "p" && tag[1] == client.authPubkey {
								isRecipient = true
								break
							}
						}
						if !isRecipient && ev.PubKey != client.authPubkey {
							return true // continue to next subscription
						}
					}

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
		h.sendNegErr(c, subID, prefixInvalid+": could not decode hex message")
		return
	}

	events, err := h.service.QueryEventsSorted(context.Background(), filter)
	if err != nil {
		slog.Error("negentropy query failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": could not build reconciliation set")
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
		slog.Error("negentropy session init failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": could not open reconciliation session")
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
		slog.Error("negentropy reconcile failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": reconciliation failed")
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
		h.sendNegErr(c, subID, prefixInvalid+": could not decode hex message")
		return
	}

	response, err := session.storage.Reconcile(msg)
	if err != nil {
		slog.Error("negentropy reconcile failed", "sub_id", subID, "error", err)
		h.sendNegErr(c, subID, prefixError+": reconciliation failed")
		return
	}

	if len(response) == 0 {
		// reconciliation complete or nothing to send
		return
	}

	h.sendNegMsg(c, subID, hex.EncodeToString(response))
}

// write sends a pre-encoded message with a bounded write deadline so a
// stalled or malicious client cannot block the sender indefinitely. Errors
// (including deadline exceeded) are logged and swallowed; the caller already
// has nothing useful to do with a failed send to one client.
func (h *RelayHandler) write(c *Client, msg []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		slog.Warn("write failed, dropping message for client", "error", err)
	}
}

func (h *RelayHandler) sendEvent(c *Client, subID string, ev *nostr.Event) {
	msg, _ := json.Marshal([]any{"EVENT", subID, ev})
	h.write(c, msg)
}

func (h *RelayHandler) sendOK(c *Client, eventID string, ok bool, reason string) {
	msg, _ := json.Marshal([]any{"OK", eventID, ok, reason})
	h.write(c, msg)
}

func (h *RelayHandler) sendNotice(c *Client, message string) {
	msg, _ := json.Marshal([]any{"NOTICE", message})
	h.write(c, msg)
}

func (h *RelayHandler) sendAuth(c *Client, challenge string) {
	msg, _ := json.Marshal([]any{"AUTH", challenge})
	h.write(c, msg)
}

func (h *RelayHandler) sendEOSE(c *Client, subID string) {
	msg, _ := json.Marshal([]any{"EOSE", subID})
	h.write(c, msg)
}

// sendClosed sends a NIP-01 CLOSED message and drops the subscription, used
// when a REQ is rejected instead of served.
func (h *RelayHandler) sendClosed(c *Client, subID string, reason string) {
	c.subscriptions.Delete(subID)
	msg, _ := json.Marshal([]any{"CLOSED", subID, reason})
	h.write(c, msg)
}

func (h *RelayHandler) sendNegErr(c *Client, subID string, reason string) {
	msg, _ := json.Marshal([]any{"NEG-ERR", subID, reason})
	h.write(c, msg)
}

func (h *RelayHandler) sendNegMsg(c *Client, subID string, msgHex string) {
	slog.Info("Sending NEG-MSG", "subID", subID, "msgHex", msgHex)
	msg, _ := json.Marshal([]any{"NEG-MSG", subID, msgHex})
	h.write(c, msg)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (h *RelayHandler) serveLandingPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := landingPageTpl.Execute(w, h.relayInfo); err != nil {
		slog.Error("landing page template error", "error", err)
	}
}

var landingPageTpl = template.Must(template.New("landing").Parse(landingPageHTML))

const landingPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Name}}</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #7c3aed; --accent-hover: #8b5cf6; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; }
  header { padding: 3rem 1.5rem 2rem; text-align: center; }
  header h1 { font-size: 2.5rem; font-weight: 700; letter-spacing: -0.03em; }
  header p { color: var(--muted); font-size: 1.15rem; margin-top: 0.5rem; }
  main { max-width: 720px; margin: 0 auto; padding: 1rem 1.5rem 3rem; width: 100%; flex: 1; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .card h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  .grid div { padding: 0.6rem 0; }
  .grid .label { color: var(--muted); font-size: 0.9rem; }
  .grid .value { font-weight: 500; word-break: break-all; overflow-wrap: anywhere; }
  .grid .value code { display: block; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85rem; word-break: break-all; overflow-wrap: anywhere; }
  .nips { display: flex; flex-wrap: wrap; gap: 0.5rem; }
  .nip { display: inline-flex; align-items: center; padding: 0.3rem 0.7rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; font-size: 0.9rem; font-weight: 500; color: var(--accent); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-hover); text-decoration: underline; }
  footer { text-align: center; padding: 1.5rem; color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--border); }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr; } header h1 { font-size: 1.8rem; } }
</style>
</head>
<body>
  <header>
    <h1>{{.Name}}</h1>
    <p>{{.Description}}</p>
  </header>
  <main>
    <div class="card">
      <h2>Relay Information</h2>
      <div class="grid">
        <div><span class="label">Software</span><br><span class="value"><a href="{{.Software}}" target="_blank" rel="noopener">{{.Software}}</a></span></div>
        <div><span class="label">Version</span><br><span class="value">{{.Version}}</span></div>
        <div><span class="label">Contact</span><br><span class="value">{{.Contact}}</span></div>
      </div>
      <div style="margin-top: 0.75rem; padding-top: 0.6rem;">
        <span class="label">Operator</span><br>
        <span class="value"><code>{{.Pubkey}}</code></span>
      </div>
    </div>

    <div class="card">
      <h2>Supported NIPs</h2>
      <div class="nips">
      {{range .SupportedNips}}
        <span class="nip">NIP-{{.}}</span>
      {{end}}
      </div>
    </div>

    {{if .Limitation}}
    <div class="card">
      <h2>Limitations</h2>
      <div class="grid">
        <div><span class="label">Max Message Length</span><br><span class="value">{{.Limitation.MaxMessageLength}}</span></div>
        <div><span class="label">Max Subscriptions</span><br><span class="value">{{.Limitation.MaxSubscriptions}}</span></div>
        <div><span class="label">Auth Required</span><br><span class="value">{{.Limitation.AuthRequired}}</span></div>
        <div><span class="label">Payment Required</span><br><span class="value">{{.Limitation.PaymentRequired}}</span></div>
      </div>
    </div>
    {{end}}
  </main>
  <footer>
    <p>{{.Name}} &middot; <a href="{{.Software}}" target="_blank" rel="noopener">Source</a></p>
  </footer>
</body>
</html>`
