// Package moderation holds the relay's moderation domain types (banned
// pubkeys, banned events, blocked IPs/CIDRs) and the repository port that
// persists them.
package moderation

// ModerationEntry is a single row from a moderation list: a banned pubkey,
// a banned event ID, or a blocked IP/CIDR, along with the operator's
// reason (if given) and when the action was applied.
type ModerationEntry struct {
	Value     string `json:"value"`
	Reason    string `json:"reason,omitzero"`
	AppliedAt int64  `json:"applied_at"`
}
