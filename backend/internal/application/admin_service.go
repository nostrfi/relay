package application

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"relay/internal/domain/admin"

	"github.com/nbd-wtf/go-nostr"
)

// AdminService answers "what may this signer do?" for every operator
// request, and manages the administrators the owner grants
// (nostrfi/relay#55).
//
// RoleOf runs on every operator request, so it reads an in-memory set rather
// than the database. The set is loaded once at start and changed only after
// a grant or revocation has been written, so it never claims a role the
// database does not hold. The relay is a single instance by design, so no
// other process can change the table underneath it.
type AdminService interface {
	// Owner is the configured owner pubkey, or "" when none is configured.
	Owner() string
	// RoleOf returns the role pubkey holds right now.
	RoleOf(pubkey string) admin.Role
	// Grant makes pubkey an administrator, granted by grantedBy.
	Grant(ctx context.Context, pubkey, label, grantedBy string) error
	// Revoke removes pubkey's administrator role.
	Revoke(ctx context.Context, pubkey string) error
	// List returns every stored grant, oldest first. The owner is not among
	// them.
	List(ctx context.Context) ([]admin.Administrator, error)
}

type adminService struct {
	owner string
	repo  admin.Repository

	mu     sync.RWMutex
	admins map[string]struct{}
}

// NewAdminService loads the stored grants. owner is the configured owner
// pubkey (moderation.admin_pubkey after its NIP-11 default is applied).
//
// Two kinds of stored grant are dealt with here, because only start-up sees
// the owner change:
//
//   - A grant for the owner's own key is deleted. It outranks nothing while
//     that key is the owner, the API refuses to touch the owner so it could
//     never be revoked, and it would silently come back to life if the owner
//     setting later moved to another key.
//   - Grants made by a key that is no longer the owner are kept, but logged.
//     Rotating the owner key is what an operator does after a compromise,
//     and an attacker holding the old key may have granted themselves
//     administrators; those survive the rotation until the new owner
//     revokes them, so the new owner is told which ones to look at.
func NewAdminService(ctx context.Context, owner string, repo admin.Repository) (AdminService, error) {
	stored, err := repo.ListAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("load administrators: %w", err)
	}
	admins := make(map[string]struct{}, len(stored))
	for _, a := range stored {
		if owner != "" && a.Pubkey == owner {
			if err := repo.RevokeAdmin(ctx, a.Pubkey); err != nil {
				return nil, fmt.Errorf("remove the owner's own administrator grant: %w", err)
			}
			slog.Info("removed a stored administrator grant for the owner's own key; the owner's role comes from configuration", "pubkey", a.Pubkey)
			continue
		}
		if owner != "" && a.GrantedBy != owner {
			slog.Warn("administrator was granted by a key that is no longer the owner; revoke it with unassignrole if the old owner key may have been compromised",
				"pubkey", a.Pubkey, "granted_by", a.GrantedBy, "granted_at", a.GrantedAt)
		}
		admins[a.Pubkey] = struct{}{}
	}
	return &adminService{owner: owner, repo: repo, admins: admins}, nil
}

func (s *adminService) Owner() string { return s.owner }

func (s *adminService) RoleOf(pubkey string) admin.Role {
	if pubkey == "" {
		return admin.RoleNone
	}
	if s.owner != "" && pubkey == s.owner {
		return admin.RoleOwner
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.admins[pubkey]; ok {
		return admin.RoleAdmin
	}
	return admin.RoleNone
}

func (s *adminService) Grant(ctx context.Context, pubkey, label, grantedBy string) error {
	if err := admin.ValidatePubkey(pubkey); err != nil {
		return err
	}
	if err := admin.ValidateLabel(label); err != nil {
		return err
	}
	if pubkey == s.owner {
		return admin.ErrOwnerNotGrantable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Not cancelled with the request: a client that disconnects as the write
	// commits must not leave a stored grant the in-memory set never learned
	// about, active only after the next restart.
	if err := s.repo.GrantAdmin(context.WithoutCancel(ctx), admin.Administrator{
		Pubkey:    pubkey,
		Label:     label,
		GrantedBy: grantedBy,
		GrantedAt: int64(nostr.Now()),
	}); err != nil {
		return err
	}
	s.admins[pubkey] = struct{}{}
	return nil
}

func (s *adminService) Revoke(ctx context.Context, pubkey string) error {
	if err := admin.ValidatePubkey(pubkey); err != nil {
		return err
	}
	if pubkey == s.owner {
		return admin.ErrOwnerNotGrantable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Not cancelled with the request, for the reason Grant gives, and with
	// more at stake: a revocation the database applied but memory missed
	// would leave the revoked key admitted until a retry or a restart.
	if err := s.repo.RevokeAdmin(context.WithoutCancel(ctx), pubkey); err != nil {
		return err
	}
	delete(s.admins, pubkey)
	return nil
}

func (s *adminService) List(ctx context.Context) ([]admin.Administrator, error) {
	stored, err := s.repo.ListAdmins(ctx)
	if err != nil {
		return nil, err
	}
	// A grant for the owner's key is deleted at start, but the owner is
	// never listed as an administrator whatever the table holds.
	list := make([]admin.Administrator, 0, len(stored))
	for _, a := range stored {
		if a.Pubkey != s.owner {
			list = append(list, a)
		}
	}
	return list, nil
}
