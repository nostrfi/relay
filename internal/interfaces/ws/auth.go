package ws

import (
	"fmt"
	"log/slog"
	"strings"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

func (h *RelayHandler) handleAuth(c *Client, ev *nostr.Event) {
	if _, err := domainevent.NewEvent(ev); err != nil {
		h.sendNotice(c, prefixInvalid+": AUTH event signature verification failed")
		return
	}
	if ev.Kind != 22242 {
		h.sendNotice(c, prefixInvalid+": invalid AUTH event kind")
		return
	}
	if h.auth.MaxEventAgeSeconds > 0 {
		age := nostr.Now() - ev.CreatedAt
		if age < 0 {
			age = -age
		}
		if int64(age) > int64(h.auth.MaxEventAgeSeconds) {
			h.sendNotice(c, fmt.Sprintf("%s: AUTH event created_at is more than %d seconds from now", prefixInvalid, h.auth.MaxEventAgeSeconds))
			return
		}
	}
	challengeFound := false
	var relayTag string
	relayFound := false
	for _, tag := range ev.Tags {
		if len(tag) >= 2 {
			if tag[0] == "challenge" && tag[1] == c.challenge {
				challengeFound = true
			}
			if tag[0] == "relay" {
				relayTag = tag[1]
				relayFound = true
			}
		}
	}
	if !challengeFound || !relayFound {
		h.sendNotice(c, prefixInvalid+": AUTH event missing challenge or relay tag")
		return
	}
	if h.auth.RelayURL != "" && !sameRelayURL(relayTag, h.auth.RelayURL) {
		h.sendNotice(c, prefixRestricted+": AUTH event relay tag does not match this relay's endpoint")
		return
	}
	c.authPubkey = ev.PubKey
	// Log only the resulting pubkey, never the challenge or the AUTH
	// event payload, per the relay's logging guardrails.
	slog.Info("Client authenticated", "pubkey", c.authPubkey)
}

// sameRelayURL compares a NIP-42 AUTH event's relay tag against the
// configured canonical relay URL, ignoring a trailing slash difference
// since relay URLs are commonly written both ways.
func sameRelayURL(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}
