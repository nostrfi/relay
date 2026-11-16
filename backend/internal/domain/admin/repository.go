package admin

import "context"

// Repository is the persistence port for administrator grants. The owner is
// never stored: it comes from configuration.
type Repository interface {
	// GrantAdmin stores or updates a grant. Re-granting an existing
	// administrator replaces its label, granter and time.
	GrantAdmin(ctx context.Context, a Administrator) error
	// RevokeAdmin removes a grant. Revoking a pubkey that holds none is not
	// an error.
	RevokeAdmin(ctx context.Context, pubkey string) error
	// ListAdmins returns every grant, oldest first.
	ListAdmins(ctx context.Context) ([]Administrator, error)
}
