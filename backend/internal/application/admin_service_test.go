package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"relay/internal/domain/admin"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAdminRepo is an in-memory admin.Repository that can be told to fail.
type fakeAdminRepo struct {
	rows map[string]admin.Administrator
	fail error
	// writeCtxErr is ctx.Err() as the last write saw it.
	writeCtxErr error
}

func newFakeAdminRepo(rows ...admin.Administrator) *fakeAdminRepo {
	r := &fakeAdminRepo{rows: map[string]admin.Administrator{}}
	for _, a := range rows {
		r.rows[a.Pubkey] = a
	}
	return r
}

func (r *fakeAdminRepo) GrantAdmin(ctx context.Context, a admin.Administrator) error {
	r.writeCtxErr = ctx.Err()
	if r.fail != nil {
		return r.fail
	}
	r.rows[a.Pubkey] = a
	return nil
}

func (r *fakeAdminRepo) RevokeAdmin(ctx context.Context, pubkey string) error {
	r.writeCtxErr = ctx.Err()
	if r.fail != nil {
		return r.fail
	}
	delete(r.rows, pubkey)
	return nil
}

func (r *fakeAdminRepo) ListAdmins(_ context.Context) ([]admin.Administrator, error) {
	if r.fail != nil {
		return nil, r.fail
	}
	out := []admin.Administrator{}
	for _, a := range r.rows {
		out = append(out, a)
	}
	return out, nil
}

var (
	ownerPk    = strings.Repeat("0", 64)
	adminPk    = strings.Repeat("a", 64)
	strangerPk = strings.Repeat("f", 64)
)

func TestAdminServiceRoleOf(t *testing.T) {
	svc, err := NewAdminService(t.Context(), ownerPk, newFakeAdminRepo(admin.Administrator{Pubkey: adminPk}))
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		pubkey string
		want   admin.Role
	}{
		{"the configured owner", ownerPk, admin.RoleOwner},
		{"a stored administrator", adminPk, admin.RoleAdmin},
		{"anyone else", strangerPk, admin.RoleNone},
		{"an empty pubkey", "", admin.RoleNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, svc.RoleOf(tc.pubkey))
		})
	}
}

func TestAdminServiceWithoutAnOwnerKnowsNoOwner(t *testing.T) {
	svc, err := NewAdminService(t.Context(), "", newFakeAdminRepo())
	require.NoError(t, err)
	assert.Equal(t, admin.RoleNone, svc.RoleOf(""), "an empty signer must never match an empty owner")
}

func TestAdminServiceGrantAndRevoke(t *testing.T) {
	repo := newFakeAdminRepo()
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)

	require.NoError(t, svc.Grant(t.Context(), adminPk, "Ada", ownerPk))
	assert.Equal(t, admin.RoleAdmin, svc.RoleOf(adminPk))
	stored := repo.rows[adminPk]
	assert.Equal(t, "Ada", stored.Label)
	assert.Equal(t, ownerPk, stored.GrantedBy)
	assert.NotZero(t, stored.GrantedAt)

	require.NoError(t, svc.Revoke(t.Context(), adminPk))
	assert.Equal(t, admin.RoleNone, svc.RoleOf(adminPk))

	require.NoError(t, svc.Revoke(t.Context(), adminPk), "revoking a key with no grant is not an error")
}

func TestAdminServiceProtectsTheOwner(t *testing.T) {
	svc, err := NewAdminService(t.Context(), ownerPk, newFakeAdminRepo())
	require.NoError(t, err)

	assert.ErrorIs(t, svc.Grant(t.Context(), ownerPk, "", ownerPk), admin.ErrOwnerNotGrantable)
	assert.ErrorIs(t, svc.Revoke(t.Context(), ownerPk), admin.ErrOwnerNotGrantable)
	assert.Equal(t, admin.RoleOwner, svc.RoleOf(ownerPk))
}

func TestAdminServiceRejectsInvalidInput(t *testing.T) {
	svc, err := NewAdminService(t.Context(), ownerPk, newFakeAdminRepo())
	require.NoError(t, err)

	assert.Error(t, svc.Grant(t.Context(), "npub1notahexkey", "", ownerPk))
	assert.Error(t, svc.Grant(t.Context(), strings.ToUpper(adminPk), "", ownerPk))
	assert.Error(t, svc.Grant(t.Context(), adminPk, strings.Repeat("x", admin.MaxLabelLength+1), ownerPk))
	assert.Error(t, svc.Grant(t.Context(), adminPk, "   ", ownerPk))
	assert.Equal(t, admin.RoleNone, svc.RoleOf(adminPk), "a refused grant must not be admitted")
}

func TestAdminServiceDoesNotAdmitAFailedGrant(t *testing.T) {
	repo := newFakeAdminRepo()
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)

	repo.fail = errors.New("disk full")
	assert.Error(t, svc.Grant(t.Context(), adminPk, "", ownerPk))
	assert.Equal(t, admin.RoleNone, svc.RoleOf(adminPk), "the in-memory set must never claim a role the database does not hold")
}

func TestAdminServiceKeepsARoleWhoseRevocationFailed(t *testing.T) {
	repo := newFakeAdminRepo(admin.Administrator{Pubkey: adminPk})
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)

	repo.fail = errors.New("disk full")
	assert.Error(t, svc.Revoke(t.Context(), adminPk))
	assert.Equal(t, admin.RoleAdmin, svc.RoleOf(adminPk), "the set follows the database, which still holds the grant")
}

func TestNewAdminServiceFailsWhenGrantsCannotBeLoaded(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.fail = errors.New("no database")
	_, err := NewAdminService(t.Context(), ownerPk, repo)
	assert.Error(t, err)
}

func TestNewAdminServiceDeletesAGrantForTheOwner(t *testing.T) {
	// A key granted before it became the owner must not keep a grant that
	// the API cannot revoke and that would revive if ownership moved on.
	repo := newFakeAdminRepo(admin.Administrator{Pubkey: ownerPk, GrantedBy: strangerPk}, admin.Administrator{Pubkey: adminPk, GrantedBy: ownerPk})
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)

	assert.NotContains(t, repo.rows, ownerPk)
	assert.Contains(t, repo.rows, adminPk)
	assert.Equal(t, admin.RoleOwner, svc.RoleOf(ownerPk))

	list, err := svc.List(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, adminPk, list[0].Pubkey)
}

func TestNewAdminServiceKeepsGrantsFromAFormerOwner(t *testing.T) {
	// Kept, and logged for the new owner to review: deleting them would
	// silently strip a legitimate team of access on every key rotation.
	repo := newFakeAdminRepo(admin.Administrator{Pubkey: adminPk, GrantedBy: strangerPk})
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)
	assert.Equal(t, admin.RoleAdmin, svc.RoleOf(adminPk))
}

func TestAdminServiceWritesSurviveACancelledRequest(t *testing.T) {
	repo := newFakeAdminRepo()
	svc, err := NewAdminService(t.Context(), ownerPk, repo)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.NoError(t, svc.Grant(ctx, adminPk, "", ownerPk))
	assert.NoError(t, repo.writeCtxErr, "the grant must not run under the cancelled request context")
	require.NoError(t, svc.Revoke(ctx, adminPk))
	assert.NoError(t, repo.writeCtxErr, "the revocation must not run under the cancelled request context")
	assert.Equal(t, admin.RoleNone, svc.RoleOf(adminPk))
}
