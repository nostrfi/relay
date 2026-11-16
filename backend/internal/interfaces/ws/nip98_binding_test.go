package ws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"relay/internal/domain/admin"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedFor is a POST to requestURL whose NIP-98 event names signedURL in
// its u tag: the two differ when a signature made for one site is replayed
// at another, or when a proxy sits in between.
func signedFor(t *testing.T, sk, signedURL, requestURL string, body []byte) *http.Request {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	require.NoError(t, err)
	sum := sha256.Sum256(body)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      27235,
		Tags:      nostr.Tags{{"u", signedURL}, {"method", http.MethodPost}, {"payload", hex.EncodeToString(sum[:])}},
	}
	require.NoError(t, ev.Sign(sk))
	raw, err := json.Marshal(ev)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, requestURL, strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(raw))
	return r
}

func TestCanonicalOrigin(t *testing.T) {
	cases := []struct {
		name, apiOrigin, relayURL, want string
	}{
		{"wss maps to https", "", "wss://Relay.Example.com", "https://relay.example.com"},
		{"ws maps to http", "", "ws://localhost:8080", "http://localhost:8080"},
		{"default port dropped", "", "wss://relay.example.com:443/", "https://relay.example.com"},
		{"non-default port kept", "", "wss://localhost:8443", "https://localhost:8443"},
		{"path ignored", "", "wss://relay.example.com/some/path", "https://relay.example.com"},
		{"api_origin wins", "http://localhost:3000", "wss://relay.example.com", "http://localhost:3000"},
		{"ipv6 host", "", "ws://[::1]:8080", "http://[::1]:8080"},
		{"neither set", "", "", ""},
		{"unparsable", "", "relay.example.com", ""},
		{"unsupported scheme", "", "ftp://relay.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, canonicalOrigin(tc.apiOrigin, tc.relayURL))
		})
	}
}

func TestSameOrigin(t *testing.T) {
	const origin = "https://relay.example.com"
	assert.True(t, sameOrigin("https://relay.example.com/", origin))
	assert.True(t, sameOrigin("https://RELAY.example.com:443/api/config", origin))
	assert.False(t, sameOrigin("https://evil.example/", origin), "another site")
	assert.False(t, sameOrigin("http://relay.example.com/", origin), "another scheme")
	assert.False(t, sameOrigin("https://relay.example.com:8443/", origin), "another port")
	assert.False(t, sameOrigin("https://relay.example.com.evil.example/", origin), "a suffix is not the host")
	assert.False(t, sameOrigin("/", origin), "a bare path names no host")
	assert.False(t, sameOrigin("https://relay.example.com/", ""), "no origin binds nothing")
}

func TestOperatorAuthorizerBindsToOrigin(t *testing.T) {
	ownerSk := nostr.GeneratePrivateKey()
	ownerPk, _ := nostr.GetPublicKey(ownerSk)
	body := []byte(`{"method":"assignrole","params":["` + strings.Repeat("a", 64) + `","admin"]}`)

	t.Run("a signature made for another website is refused, with the reason", func(t *testing.T) {
		// nostrfi/relay#60: the owner signs "for" evil.example, which
		// replays the event at the relay's matching path.
		authorizer := newOperatorAuthorizer(ownerPk, 60, "https://relay.example.com", nil)
		r := signedFor(t, ownerSk, "https://evil.example/", "http://relay.test/", body)
		_, role, err := authorizer.authorize(r, body, admin.RoleOwner)
		require.Error(t, err)
		assert.Equal(t, admin.RoleNone, role)
		assert.Contains(t, publicReasonFor(err), "different host")
	})

	t.Run("the relay's own origin is accepted behind a proxy", func(t *testing.T) {
		// Caddy or the dashboard forwards to http://relay:8080; the browser
		// signed the public https origin.
		authorizer := newOperatorAuthorizer(ownerPk, 60, "https://relay.example.com", nil)
		r := signedFor(t, ownerSk, "https://relay.example.com/", "http://relay:8080/", body)
		pubkey, role, err := authorizer.authorize(r, body, admin.RoleOwner)
		require.NoError(t, err)
		assert.Equal(t, ownerPk, pubkey)
		assert.Equal(t, admin.RoleOwner, role)
	})

	t.Run("no canonical origin refuses everything, with the reason", func(t *testing.T) {
		authorizer := newOperatorAuthorizer(ownerPk, 60, "", nil)
		r := signedFor(t, ownerSk, "http://relay.test/", "http://relay.test/", body)
		_, _, err := authorizer.authorize(r, body, admin.RoleOwner)
		require.Error(t, err)
		assert.Contains(t, publicReasonFor(err), "auth.relay_url")
	})
}

func TestOperatorAuthorizerRefusesReplays(t *testing.T) {
	ownerSk := nostr.GeneratePrivateKey()
	ownerPk, _ := nostr.GetPublicKey(ownerSk)
	strangerSk := nostr.GeneratePrivateKey()
	body := []byte(`{"method":"listbannedpubkeys","params":[]}`)

	t.Run("the same event is admitted once", func(t *testing.T) {
		authorizer := newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil)
		first := signedFor(t, ownerSk, "http://relay.test/", "http://relay.test/", body)
		replay := first.Clone(first.Context())

		_, _, err := authorizer.authorize(first, body, admin.RoleOwner)
		require.NoError(t, err)
		_, _, err = authorizer.authorize(replay, body, admin.RoleOwner)
		require.Error(t, err)
		assert.Contains(t, publicReasonFor(err), "already been used")
	})

	t.Run("a stranger's replay gets the same explanation as the owner's", func(t *testing.T) {
		// Otherwise "already used" would say the signer holds a role.
		authorizer := newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil)
		first := signedFor(t, strangerSk, "http://relay.test/", "http://relay.test/", body)
		replay := first.Clone(first.Context())

		_, _, err := authorizer.authorize(first, body, admin.RoleAdmin)
		require.Error(t, err)
		assert.Empty(t, publicReasonFor(err), "an identity failure stays unexplained")
		_, _, err = authorizer.authorize(replay, body, admin.RoleAdmin)
		require.Error(t, err)
		assert.Contains(t, publicReasonFor(err), "already been used")
	})

	t.Run("copies racing each other admit exactly one", func(t *testing.T) {
		authorizer := newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil)
		original := signedFor(t, ownerSk, "http://relay.test/", "http://relay.test/", body)
		var admitted atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := authorizer.authorize(original.Clone(original.Context()), body, admin.RoleOwner); err == nil {
					admitted.Add(1)
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, int32(1), admitted.Load())
	})
}

func TestNip98ReplayGuard(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	newGuard := func(capacity int) *nip98ReplayGuard {
		g := newNip98ReplayGuard(capacity)
		g.now = func() time.Time { return clock }
		return g
	}

	t.Run("claims once until expiry", func(t *testing.T) {
		g := newGuard(10)
		assert.True(t, g.claim("a", clock.Add(time.Minute)))
		assert.False(t, g.claim("a", clock.Add(time.Minute)))
		clock = clock.Add(2 * time.Minute)
		assert.True(t, g.claim("a", clock.Add(time.Minute)), "an expired event could not pass freshness anyway")
	})

	t.Run("prunes expired entries", func(t *testing.T) {
		g := newGuard(10)
		for i := range 5 {
			g.claim(fmt.Sprint("e", i), clock.Add(time.Second))
		}
		clock = clock.Add(5 * time.Second)
		g.claim("fresh", clock.Add(time.Minute))
		assert.Equal(t, 1, g.size())
	})

	t.Run("evicts the oldest at capacity", func(t *testing.T) {
		g := newGuard(3)
		for _, id := range []string{"a", "b", "c", "d"} {
			assert.True(t, g.claim(id, clock.Add(time.Minute)))
		}
		assert.Equal(t, 3, g.size())
		assert.True(t, g.claim("a", clock.Add(time.Minute)), "a was evicted")
		assert.False(t, g.claim("d", clock.Add(time.Minute)), "d is still remembered")
	})
}

// The refusal for a foreign host is a verification failure: explained, and
// answered 401 rather than 403.
func TestForeignHostRefusalIsExplained(t *testing.T) {
	ownerSk := nostr.GeneratePrivateKey()
	ownerPk, _ := nostr.GetPublicKey(ownerSk)
	authorizer := newOperatorAuthorizer(ownerPk, 60, "https://relay.example.com", nil)
	body := []byte(`{}`)
	r := signedFor(t, ownerSk, "https://evil.example/api/config", "http://relay.test/api/config", body)
	_, _, err := authorizer.authorize(r, body, admin.RoleOwner)
	require.Error(t, err)
	var failure *operatorAuthFailure
	require.True(t, errors.As(err, &failure))

	w := httptest.NewRecorder()
	writeOperatorRefusal(w, err)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "different host")
}
