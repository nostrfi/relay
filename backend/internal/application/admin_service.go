package application

import (
	"context"
	"fmt"
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
// pubkey (moderation.admin_pubkey after its NIP-11 default is applied); a
// stored grant for the owner's own key is ignored, because the owner's role
// comes from configuration alone.
func NewAdminService(ctx context.Context, owner string, repo admin.Repository) (AdminService, error) {
	stored, err := repo.ListAdmins(ctx)
	if err != nil {
		return nil, fmt.Errorf("load administrators: %w", err)
	}
	admins := make(map[string]struct{}, len(stored))
	for _, a := range stored {
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
	if err := s.repo.GrantAdmin(ctx, admin.Administrator{
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
	if err := s.repo.RevokeAdmin(ctx, pubkey); err != nil {
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
	// A grant for a key that later became the owner is not an administrator
	// role in any sense the caller should see: the owner outranks it.
	list := make([]admin.Administrator, 0, len(stored))
	for _, a := range stored {
		if a.Pubkey != s.owner {
			list = append(list, a)
		}
	}
	return list, nil
}
