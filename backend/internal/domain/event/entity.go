// Package event holds the relay's Event domain type: a Nostr event wrapped
// with the invariant every layer above the wire previously assumed ad hoc —
// that its signature has already been verified — plus the repository port
// that persists it.
package event

import (
	"fmt"

	"github.com/nbd-wtf/go-nostr"
)

// Event is the relay's domain wrapper around a Nostr event. Embedding
// *nostr.Event keeps every existing field and method (ID, PubKey, Tags,
// CheckSignature, ...) available on Event without duplicating them; the
// wrapper's only job is to guarantee, at construction, that the event's
// ID is the hash of its content and its signature has been verified.
type Event struct {
	*nostr.Event
}

// NewEvent verifies ev's ID and signature and returns it wrapped as a
// domain Event.
//
// The ID check matters on its own: go-nostr's CheckSignature verifies the
// signature over the recomputed content hash and never looks at ev.ID. An
// event whose content and signature are valid could otherwise claim any ID
// it liked, and everything that keys on the ID, from storage to NIP-98
// replay protection (nostrfi/relay#60), would trust it. This centralizes the signature check that was previously
// duplicated, identically, at three call sites in the interfaces layer
// (NIP-42 AUTH, event publish, and NIP-98 HTTP Auth).
func NewEvent(ev *nostr.Event) (*Event, error) {
	if ev == nil {
		return nil, fmt.Errorf("event: nil event")
	}
	if !ev.CheckID() {
		return nil, fmt.Errorf("event: id does not match the event's content")
	}
	ok, err := ev.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("event: signature verification error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("event: signature verification failed")
	}
	return &Event{Event: ev}, nil
}
