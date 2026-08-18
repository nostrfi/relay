package ws

import (
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
// The returned error is for logging only. Callers report a generic
// "unauthorized" to the client: which check failed is not the caller's
// business, and saying so would help an attacker tune their attempt.
func authorizeOperator(r *http.Request, body []byte, adminPubkey string, maxEventAgeSeconds int) (string, error) {
	pubkey, err := verifyNip98(r, body, maxEventAgeSeconds)
	if err != nil {
		return "", fmt.Errorf("NIP-98 verification failed: %w", err)
	}
	if adminPubkey == "" {
		return "", fmt.Errorf("no operator pubkey is configured")
	}
	if pubkey != adminPubkey {
		return "", fmt.Errorf("pubkey %s is not the configured operator", pubkey)
	}
	return pubkey, nil
}

// logRejectedOperatorRequest keeps rejection logging consistent across the
// operator endpoints, and keeps auth material out of the log: the reason
// and, where known, the offending pubkey — never the event or the header.
func logRejectedOperatorRequest(endpoint string, err error) {
	slog.Warn("operator request rejected", "endpoint", endpoint, "error", err)
}
