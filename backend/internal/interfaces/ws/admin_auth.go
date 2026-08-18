package ws

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// authorizeOperator is the single admission check for every operator-only
// HTTP endpoint: a valid NIP-98 signature over this exact request, made by
// the configured operator key.
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

func authorizeOperator(r *http.Request, body []byte, adminPubkey string, maxEventAgeSeconds int) (string, error) {
	pubkey, err := verifyNip98(r, body, maxEventAgeSeconds)
	if err != nil {
		wrapped := fmt.Errorf("NIP-98 verification failed: %w", err)
		return "", &operatorAuthFailure{PublicReason: err.Error(), err: wrapped}
	}
	if adminPubkey == "" {
		// Not an identity failure, and safe to say: there is no operator
		// identity here to confirm or deny. The relay is misconfigured, and
		// the caller cannot act on that knowledge — while the operator, who
		// otherwise sees a bare "unauthorized" indistinguishable from a
		// wrong key, can act on it immediately (nostrfi/workspace#38).
		return "", &operatorAuthFailure{
			PublicReason: "this relay has no operator pubkey configured; set relay_info.pubkey or moderation.admin_pubkey in its config.yaml",
			err:          fmt.Errorf("no operator pubkey is configured"),
		}
	}
	if pubkey != adminPubkey {
		return "", &operatorAuthFailure{err: fmt.Errorf("pubkey %s is not the configured operator", pubkey)}
	}
	return pubkey, nil
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
