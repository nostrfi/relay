package handler

import (
	"context"
	"fmt"
	"log/slog"

	"relay/pkg/metrics"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
)

func (h *RelayHandler) handleEvent(c *Client, ev *nostr.Event) {
	banned, err := h.service.IsPubkeyBanned(context.Background(), ev.PubKey)
	if err != nil {
		slog.Error("moderation check failed", "error", err)
		h.sendOK(c, ev.ID, false, prefixError+": failed to process event")
		return
	}
	if banned {
		h.sendOK(c, ev.ID, false, prefixBlocked+": this pubkey is not permitted to publish to this relay")
		return
	}

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
		metrics.SaveFailuresTotal.Inc()
		h.sendOK(c, ev.ID, false, prefixError+": failed to save event")
		return
	}

	if success {
		metrics.EventsStoredTotal.Inc()
		h.sendOK(c, ev.ID, true, "")
		h.broadcast(ev)
	} else {
		metrics.SaveFailuresTotal.Inc()
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
