package ws

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"relay/internal/application"
	"relay/internal/domain/admin"
)

// Operator authorization: a valid NIP-98 signature over this exact
// request, made by a key the relay knows as owner or administrator.
//
// Extracted from the NIP-86 handler when the configuration endpoint became
// a second caller (nostrfi/workspace#38). Both endpoints are reachable from
// the public internet — the reverse proxy routes everything outside /admin
// to the relay — so neither can rely on network position.
//
// Two kinds of failure, told apart because only one of them is safe to
// explain to the caller.
//
// A verification failure — a malformed header, a bad signature, a stale
// created_at, a u tag or payload hash that does not match — says nothing
// about who the operator is. Withholding it costs an operator a debugging
// session for no security gain: they cannot tell a clock problem from a
// proxy rewriting paths, and the relay is the only party that knows.
//
// An identity failure is different: confirming "that signature was valid,
// but you are not the operator" tells an attacker their key is not the one
// to use, and confirms when it is. That stays generic.
//
// A relay with no operator key at all falls on the safe side of that line:
// there is no identity to leak, and the operator would otherwise have no
// way to tell a missing key from a wrong one.
type operatorAuthFailure struct {
	// Safe to return to the caller, empty when it is not.
	PublicReason string
	err          error
}

func (f *operatorAuthFailure) Error() string { return f.err.Error() }
func (f *operatorAuthFailure) Unwrap() error { return f.err }

// operatorAuthorizer is the single admission check for every operator-only
// HTTP endpoint. It verifies the NIP-98 signature, then resolves the
// signer's role: the configured owner, an administrator the owner has
// granted (nostrfi/relay#55), or nobody.
//
// roles may be nil, in which case only the owner is admitted: the behaviour
// every release before 0.3.0 had, and what a handler built without an
// AdminService still gets.
//
// origin is the canonical origin requests must be signed for (see
// canonicalOrigin). When it is "", every request is refused with an
// explanation: an unbound NIP-98 check accepts signatures made for other
// websites (nostrfi/relay#60).
type operatorAuthorizer struct {
	owner              string
	roles              application.AdminService
	maxEventAgeSeconds int
	origin             string
	replays            *nip98ReplayGuard
}

func newOperatorAuthorizer(owner string, maxEventAgeSeconds int, origin string, roles application.AdminService) operatorAuthorizer {
	if roles != nil {
		owner = roles.Owner()
	}
	return operatorAuthorizer{
		owner:              owner,
		roles:              roles,
		maxEventAgeSeconds: maxEventAgeSeconds,
		origin:             origin,
		replays:            newNip98ReplayGuard(defaultNip98ReplayCapacity),
	}
}

// operatorAuthorizerFor builds the authorizer from the relay's configuration.
func operatorAuthorizerFor(auth AuthConfig, moderation ModerationConfig, roles application.AdminService) operatorAuthorizer {
	return newOperatorAuthorizer(moderation.AdminPubkey, moderation.MaxEventAgeSeconds, canonicalOrigin(moderation.APIOrigin, auth.RelayURL), roles)
}

// noOriginReason is what a caller is told when the relay has no canonical
// origin. Safe to say, like a missing owner key: it is configuration, and
// says nothing about anyone's key.
const noOriginReason = "this relay has no canonical URL for its operator APIs; set auth.relay_url (or moderation.api_origin) in its config.yaml"

func (a operatorAuthorizer) roleOf(pubkey string) admin.Role {
	if a.roles != nil {
		return a.roles.RoleOf(pubkey)
	}
	if pubkey != "" && pubkey == a.owner {
		return admin.RoleOwner
	}
	return admin.RoleNone
}

// authorize admits the request if its signer holds at least minimum.
//
// A signer the relay does not know at all gets the same generic refusal as
// ever, so an outsider still cannot learn which keys matter. A signer the
// relay does know, whose role is too low for this endpoint, is told so
// (errInsufficientRole, a 403): they have already proved who they are, and
// "owner only" tells them nothing about anyone else's key.
func (a operatorAuthorizer) authorize(r *http.Request, body []byte, minimum admin.Role) (string, admin.Role, error) {
	if a.origin == "" {
		return "", admin.RoleNone, &operatorAuthFailure{
			PublicReason: noOriginReason,
			err:          fmt.Errorf("no canonical origin is configured (auth.relay_url, moderation.api_origin)"),
		}
	}
	verified, err := verifyNip98(r, body, a.maxEventAgeSeconds, a.origin)
	if err != nil {
		wrapped := fmt.Errorf("NIP-98 verification failed: %w", err)
		return "", admin.RoleNone, &operatorAuthFailure{PublicReason: err.Error(), err: wrapped}
	}
	pubkey := verified.PubKey
	if a.owner == "" {
		// Not an identity failure, and safe to say: there is no operator
		// identity here to confirm or deny. The relay is misconfigured, and
		// the caller cannot act on that knowledge — while the operator, who
		// otherwise sees a bare "unauthorized" indistinguishable from a
		// wrong key, can act on it immediately (nostrfi/workspace#38).
		// Without an owner nobody could have granted an administrator, so
		// nobody is admitted.
		return "", admin.RoleNone, &operatorAuthFailure{
			PublicReason: "this relay has no operator pubkey configured; set relay_info.pubkey or moderation.admin_pubkey in its config.yaml",
			err:          fmt.Errorf("no operator pubkey is configured"),
		}
	}
	role := a.roleOf(pubkey)
	if role == admin.RoleNone {
		return "", admin.RoleNone, &operatorAuthFailure{err: fmt.Errorf("pubkey %s is neither the owner nor an administrator", pubkey)}
	}
	// Only now, for a key that holds a role, is the event recorded: a
	// stranger's events are refused anyway, so they need no record and must
	// not fill one (see nip98ReplayGuard).
	//
	// A replay is refused exactly like an unknown key, without a reason.
	// Explaining it would tell whoever replayed a captured signature that
	// its signer holds a role, since a stranger's replay never gets here.
	expiresAt := time.Unix(int64(verified.CreatedAt)+int64(a.maxEventAgeSeconds)+1, 0)
	switch a.replays.claim(verified.ID, expiresAt) {
	case claimReplayed:
		return "", admin.RoleNone, &operatorAuthFailure{err: fmt.Errorf("NIP-98 event %s from %s replayed", verified.ID, pubkey)}
	case claimFull:
		// Reachable only by the owner and administrators themselves: tens of
		// thousands of signed requests within one freshness window.
		return "", admin.RoleNone, &operatorAuthFailure{
			PublicReason: "too many operator requests in the last minute; try again shortly",
			err:          fmt.Errorf("NIP-98 replay record is full"),
		}
	}
	if !role.Satisfies(minimum) {
		return pubkey, role, &insufficientRoleError{pubkey: pubkey, role: role, minimum: minimum}
	}
	return pubkey, role, nil
}

// insufficientRoleError is a known signer asking for something above their
// role. Answered with 403 and an explanation, never with 401.
type insufficientRoleError struct {
	pubkey  string
	role    admin.Role
	minimum admin.Role
}

func (e *insufficientRoleError) Error() string {
	return fmt.Sprintf("pubkey %s holds role %s, %s required", e.pubkey, e.role, e.minimum)
}

// publicReason is what the caller is told.
func (e *insufficientRoleError) publicReason() string {
	return e.minimum.String() + " only"
}

// writeOperatorRefusal answers a failed authorize with the shared
// {"error": ..., "reason"?: ...} body: 403 "forbidden" for a known signer
// whose role is too low, 401 "unauthorized" for everything else. NIP-86
// callers parse this same envelope, so "unauthorized" stays the error a
// stranger sees, exactly as before.
func writeOperatorRefusal(w http.ResponseWriter, err error) {
	refusal := map[string]string{"error": "unauthorized"}
	status := http.StatusUnauthorized

	var tooLow *insufficientRoleError
	if errors.As(err, &tooLow) {
		status = http.StatusForbidden
		refusal["error"] = "forbidden"
		refusal["reason"] = tooLow.publicReason()
	} else if reason := publicReasonFor(err); reason != "" {
		// A verification failure is safe to explain and expensive to
		// withhold; an identity failure is not. See operatorAuthorizer.
		refusal["reason"] = reason
	}

	w.WriteHeader(status)
	json.NewEncoder(w).Encode(refusal)
}

// publicReasonFor returns the part of err that may be shown to the caller,
// or "" when nothing may be.
func publicReasonFor(err error) string {
	var failure *operatorAuthFailure
	if errors.As(err, &failure) {
		return failure.PublicReason
	}
	return ""
}

// logRejectedOperatorRequest keeps rejection logging consistent across the
// operator endpoints, and keeps auth material out of the log: the reason
// and, where known, the offending pubkey — never the event or the header.
func logRejectedOperatorRequest(endpoint string, err error) {
	slog.Warn("operator request rejected", "endpoint", endpoint, "error", err)
}
