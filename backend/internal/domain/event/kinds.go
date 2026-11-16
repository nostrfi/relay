package event

import "errors"

// ErrEphemeral is returned by a Repository asked to persist an ephemeral
// event. The publish path never does — it broadcasts ephemeral events
// without saving them — so seeing this error means a new call path forgot
// to check IsEphemeral first.
var ErrEphemeral = errors.New("event: ephemeral events are not stored")

// IsEphemeral reports whether kind is in NIP-01's ephemeral range,
// 20000 <= kind < 30000: events relays deliver to open subscriptions but
// are "not expected to be stored". Presence heartbeats (kind 20001),
// typing indicators and NIP-46 signer traffic (kind 24133) all fall here.
func IsEphemeral(kind int) bool {
	return kind >= 20000 && kind < 30000
}
