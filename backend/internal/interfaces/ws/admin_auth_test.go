package ws

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"relay/internal/domain/admin"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	authTestURL    = "http://relay.test/api/config"
	authTestOrigin = "http://relay.test"
)

// signedOperatorRequest is a POST to authTestURL carrying a NIP-98 header
// signed by sk over body.
func signedOperatorRequest(t *testing.T, sk string, body []byte) *http.Request {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	require.NoError(t, err)
	sum := sha256.Sum256(body)
	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      27235,
		Tags:      nostr.Tags{{"u", authTestURL}, {"method", http.MethodPost}, {"payload", hex.EncodeToString(sum[:])}},
	}
	require.NoError(t, ev.Sign(sk))
	raw, err := json.Marshal(ev)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, authTestURL, strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Nostr "+base64.StdEncoding.EncodeToString(raw))
	return r
}

// stubRoles is an application.AdminService answering from a fixed map.
type stubRoles struct {
	owner  string
	admins map[string]bool
}

func (s stubRoles) Owner() string { return s.owner }
func (s stubRoles) RoleOf(pubkey string) admin.Role {
	switch {
	case pubkey != "" && pubkey == s.owner:
		return admin.RoleOwner
	case s.admins[pubkey]:
		return admin.RoleAdmin
	}
	return admin.RoleNone
}
func (stubRoles) Grant(context.Context, string, string, string) error { return nil }
func (stubRoles) Revoke(context.Context, string) error                { return nil }
func (stubRoles) List(context.Context) ([]admin.Administrator, error) { return nil, nil }

func TestOperatorAuthorizer(t *testing.T) {
	ownerSk, adminSk, strangerSk := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	ownerPk, _ := nostr.GetPublicKey(ownerSk)
	adminPk, _ := nostr.GetPublicKey(adminSk)
	roles := stubRoles{owner: ownerPk, admins: map[string]bool{adminPk: true}}
	body := []byte("{}")

	for _, tc := range []struct {
		name       string
		authorizer operatorAuthorizer
		sk         string
		minimum    admin.Role
		wantRole   admin.Role
		wantStatus int // 0 when admitted
		wantReason string
	}{
		{"owner at owner level", newOperatorAuthorizer("", 60, authTestOrigin, roles), ownerSk, admin.RoleOwner, admin.RoleOwner, 0, ""},
		{"owner at admin level", newOperatorAuthorizer("", 60, authTestOrigin, roles), ownerSk, admin.RoleAdmin, admin.RoleOwner, 0, ""},
		{"administrator at admin level", newOperatorAuthorizer("", 60, authTestOrigin, roles), adminSk, admin.RoleAdmin, admin.RoleAdmin, 0, ""},
		{"administrator at owner level", newOperatorAuthorizer("", 60, authTestOrigin, roles), adminSk, admin.RoleOwner, admin.RoleAdmin, http.StatusForbidden, "owner only"},
		{"stranger is refused without a reason", newOperatorAuthorizer("", 60, authTestOrigin, roles), strangerSk, admin.RoleAdmin, admin.RoleNone, http.StatusUnauthorized, ""},
		{"no roles service admits the owner", newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil), ownerSk, admin.RoleOwner, admin.RoleOwner, 0, ""},
		{"no roles service refuses an administrator", newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil), adminSk, admin.RoleAdmin, admin.RoleNone, http.StatusUnauthorized, ""},
		{"no owner configured is explained", newOperatorAuthorizer("", 60, authTestOrigin, stubRoles{admins: map[string]bool{adminPk: true}}), adminSk, admin.RoleAdmin, admin.RoleNone, http.StatusUnauthorized, "no operator pubkey configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, role, err := tc.authorizer.authorize(signedOperatorRequest(t, tc.sk, body), body, tc.minimum)
			assert.Equal(t, tc.wantRole, role)
			if tc.wantStatus == 0 {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)

			rec := httptest.NewRecorder()
			writeOperatorRefusal(rec, err)
			assert.Equal(t, tc.wantStatus, rec.Code)
			var refusal map[string]string
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&refusal))
			if tc.wantReason == "" {
				_, hasReason := refusal["reason"]
				assert.False(t, hasReason, "an identity failure must not carry a reason: %v", refusal)
			} else {
				assert.Contains(t, refusal["reason"], tc.wantReason)
			}
		})
	}
}

func TestOperatorAuthorizerExplainsVerificationFailures(t *testing.T) {
	ownerSk := nostr.GeneratePrivateKey()
	ownerPk, _ := nostr.GetPublicKey(ownerSk)
	authorizer := newOperatorAuthorizer(ownerPk, 60, authTestOrigin, nil)

	// Signed over a different body: the payload hash cannot match.
	r := signedOperatorRequest(t, ownerSk, []byte("{}"))
	_, _, err := authorizer.authorize(r, []byte(`{"tampered":true}`), admin.RoleAdmin)
	require.Error(t, err)

	var failure *operatorAuthFailure
	require.True(t, errors.As(err, &failure))
	assert.NotEmpty(t, failure.PublicReason)
}
