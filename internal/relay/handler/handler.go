package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"relay/internal/relay/service"
	"relay/pkg/metrics"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type RelayHandler struct {
	service        service.RelayService
	clients        sync.Map // map[*Client]bool
	relayInfo      RelayInfo
	resourceLimits ResourceLimits
	auth           AuthConfig
	websocket      WebsocketConfig
	upgrader       websocket.Upgrader
	connCount      atomic.Int64
	subCount       atomic.Int64
}

func NewRelayHandler(service service.RelayService, info RelayInfo, buildVersion string) *RelayHandler {
	return NewRelayHandlerWithLimits(service, info, ResourceLimits{}, buildVersion)
}

func NewRelayHandlerWithLimits(service service.RelayService, info RelayInfo, limits ResourceLimits, buildVersion string) *RelayHandler {
	return NewRelayHandlerFull(service, info, limits, AuthConfig{}, WebsocketConfig{}, buildVersion)
}

// NewRelayHandlerFull is the fully configured constructor. An empty
// AuthConfig disables endpoint-binding and freshness checks on NIP-42 AUTH
// (matching the historical, presence-only behavior); a zero-value
// WebsocketConfig defaults to development mode (all origins allowed),
// matching the historical CheckOrigin behavior. Both must be set explicitly
// to enable the stricter, internet-facing behavior.
func NewRelayHandlerFull(service service.RelayService, info RelayInfo, limits ResourceLimits, auth AuthConfig, ws WebsocketConfig, buildVersion string) *RelayHandler {
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
	if ws.Mode == "" {
		ws.Mode = websocketModeDevelopment
	}

	h := &RelayHandler{
		service:        service,
		relayInfo:      info,
		resourceLimits: limits,
		auth:           auth,
		websocket:      ws,
	}
	h.upgrader = websocket.Upgrader{CheckOrigin: h.checkOrigin}
	return h
}

// checkOrigin enforces the configured WebSocket origin policy. Development
// mode preserves the historical permissive behavior; production mode is
// fail-closed and is validated at config load to always have a non-empty
// allow-list.
func (h *RelayHandler) checkOrigin(r *http.Request) bool {
	if h.websocket.Mode != websocketModeProduction {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return slices.Contains(h.websocket.AllowedOrigins, origin)
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
	// is counted, letting more than MaxConnections through. The counter
	// itself is always maintained (metrics need it to be accurate even when
	// no cap is configured); only the rejection check is gated on
	// MaxConnections > 0.
	current := h.connCount.Add(1)
	metrics.ConnectionsActive.Inc()
	if h.resourceLimits.MaxConnections > 0 && current > int64(h.resourceLimits.MaxConnections) {
		h.connCount.Add(-1)
		metrics.ConnectionsActive.Dec()
		http.Error(w, "restricted: too many connections", http.StatusServiceUnavailable)
		return
	}

	conn, err := h.upgrader.Upgrade(w, req, nil)
	if err != nil {
		slog.Error("upgrade error", "error", err)
		h.connCount.Add(-1)
		metrics.ConnectionsActive.Dec()
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
		h.connCount.Add(-1)
		metrics.ConnectionsActive.Dec()
		if n := countSubscriptions(client); n > 0 {
			h.subCount.Add(-int64(n))
			metrics.SubscriptionsActive.Sub(float64(n))
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
		h.sendNotice(c, prefixInvalid+": invalid JSON")
		return
	}

	if len(raw) < 2 {
		h.sendNotice(c, prefixInvalid+": invalid message format")
		return
	}

	var msgType string
	if err := json.Unmarshal(raw[0], &msgType); err != nil {
		h.sendNotice(c, prefixInvalid+": invalid message type")
		return
	}

	metrics.MessagesTotal.WithLabelValues(metrics.KnownMessageType(msgType)).Inc()

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
		_, subExisted := c.subscriptions.Load(subID)
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
			if !subExisted && countSubscriptions(c) >= limitation.MaxSubscriptions {
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
		if !subExisted {
			h.subCount.Add(1)
			metrics.SubscriptionsActive.Inc()
		}
		h.handleReq(c, subID, filters)
	case "CLOSE":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNotice(c, prefixInvalid+": invalid subscription ID")
			return
		}
		if _, existed := c.subscriptions.LoadAndDelete(subID); existed {
			h.subCount.Add(-1)
			metrics.SubscriptionsActive.Dec()
		}
	case "AUTH":
		var ev nostr.Event
		if err := json.Unmarshal(raw[1], &ev); err != nil {
			h.sendNotice(c, prefixInvalid+": invalid AUTH event")
			return
		}
		h.handleAuth(c, &ev)
	case "NEG-OPEN":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNegErr(c, "", prefixInvalid+": invalid subscription ID")
			return
		}
		var filter nostr.Filter
		if err := json.Unmarshal(raw[2], &filter); err != nil {
			h.sendNegErr(c, subID, prefixInvalid+": invalid filter")
			return
		}
		var initialMsg string
		if err := json.Unmarshal(raw[3], &initialMsg); err != nil {
			h.sendNegErr(c, subID, prefixInvalid+": invalid initial message")
			return
		}
		// Debug only, and never the raw payload: this fires on every
		// reconciliation message and the hex vector is high-volume metadata,
		// not something worth Info-level disclosure.
		slog.Debug("NEG-OPEN received", "sub_id", subID)
		h.handleNegOpen(c, subID, filter, initialMsg)
	case "NEG-MSG":
		var subID string
		if err := json.Unmarshal(raw[1], &subID); err != nil {
			h.sendNegErr(c, "", prefixInvalid+": invalid subscription ID")
			return
		}
		var msgHex string
		if err := json.Unmarshal(raw[2], &msgHex); err != nil {
			h.sendNegErr(c, subID, prefixInvalid+": invalid message hex")
			return
		}
		slog.Debug("NEG-MSG received", "sub_id", subID)
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

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}
