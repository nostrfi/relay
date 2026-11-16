// Package admin holds the relay's operator roles: the owner named in
// configuration, and the administrators the owner grants (nostrfi/relay#55).
package admin

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Role is what a signer may do on the relay's operator endpoints.
type Role int

const (
	// RoleNone is a signer the relay does not know: refused everywhere.
	RoleNone Role = iota
	// RoleAdmin is a pubkey the owner has granted administrator rights.
	RoleAdmin
	// RoleOwner is moderation.admin_pubkey, which defaults to the NIP-11
	// pubkey. Configured, never stored, and never removable through the API.
	RoleOwner
)

// String is the role's wire name, as NIP-86 role methods and whoami use it.
func (r Role) String() string {
	switch r {
	case RoleOwner:
		return "owner"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

// Satisfies reports whether r is allowed where minimum is required. The
// roles are strictly ordered: the owner can do everything an administrator
// can.
func (r Role) Satisfies(minimum Role) bool {
	return r != RoleNone && r >= minimum
}

// GrantableRoleID is the only role id assignrole and unassignrole accept.
// Custom roles (createrole and friends) are out of scope for 0.3.0.
const GrantableRoleID = "admin"

// Administrator is one stored grant.
type Administrator struct {
	Pubkey string
	// Label is the owner's own note on who this is; may be empty.
	Label string
	// GrantedBy is the pubkey that granted the role: the owner at the time.
	GrantedBy string
	// GrantedAt is Unix seconds, like the moderation tables' timestamps.
	GrantedAt int64
}

// MaxLabelLength bounds a grant's label, counted in characters for the same
// reason moderation reasons are: the limit must not depend on the
// operator's language.
const MaxLabelLength = 100

// pubkeyLength is the length of a lowercase-hex pubkey.
const pubkeyLength = 64

// ErrOwnerNotGrantable is returned for any attempt to grant, revoke, or
// otherwise change the owner through the API: the owner comes from
// configuration and is always an administrator.
var ErrOwnerNotGrantable = errors.New("the owner's role comes from the relay configuration and cannot be changed through the API")

// ValidatePubkey rejects anything that is not 64 lowercase hex characters.
// A stored non-pubkey could never match a signer, so the owner would believe
// a grant was in force when nothing was.
func ValidatePubkey(pubkey string) error {
	if len(pubkey) != pubkeyLength {
		return fmt.Errorf("pubkey must be %d hex characters, got %d", pubkeyLength, len(pubkey))
	}
	for _, r := range pubkey {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return errors.New("pubkey must be lowercase hex characters")
		}
	}
	return nil
}

// ValidateLabel bounds the optional label.
func ValidateLabel(label string) error {
	if count := utf8.RuneCountInString(label); count > MaxLabelLength {
		return fmt.Errorf("label must be %d characters or fewer, got %d", MaxLabelLength, count)
	}
	if label != "" && strings.TrimSpace(label) == "" {
		return errors.New("label must not be only whitespace")
	}
	return nil
}
