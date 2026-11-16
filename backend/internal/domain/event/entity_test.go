package event

import (
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signedEvent(t *testing.T) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Content: "hello"}
	require.NoError(t, ev.Sign(nostr.GeneratePrivateKey()))
	return ev
}

func TestNewEventAcceptsAValidEvent(t *testing.T) {
	_, err := NewEvent(signedEvent(t))
	assert.NoError(t, err)
}

// The signature covers the content, not the claimed ID, so only an explicit
// ID check catches an event that keeps its signature and changes its ID
// (nostrfi/relay#60's review).
func TestNewEventRejectsAnIDThatDoesNotMatchTheContent(t *testing.T) {
	ev := signedEvent(t)
	ok, err := ev.CheckSignature()
	require.NoError(t, err)
	require.True(t, ok)

	ev.ID = signedEvent(t).ID
	ok, err = ev.CheckSignature()
	require.NoError(t, err)
	require.True(t, ok, "the signature alone still verifies, which is the problem")

	_, err = NewEvent(ev)
	assert.ErrorContains(t, err, "id does not match")
}

func TestNewEventRejectsABadSignature(t *testing.T) {
	ev := signedEvent(t)
	other := signedEvent(t)
	ev.Sig = other.Sig
	_, err := NewEvent(ev)
	assert.Error(t, err)
}
