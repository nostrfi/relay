package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"relay/internal/relay/repository"
)

// nip86ContentType is the Content-Type that selects the NIP-86 relay
// management API instead of the normal WebSocket/NIP-11/landing-page
// handling on the same URI.
const nip86ContentType = "application/nostr+json+rpc"

// maxManagementBodyBytes bounds how much of a management request body is
// read, generous for the small JSON-RPC payloads every supported method
// uses.
const maxManagementBodyBytes = 1 << 20

type nip86Request struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type nip86Response struct {
	Result any    `json:"result,omitzero"`
	Error  string `json:"error,omitzero"`
}

// supportedManagementMethods answers the "supportedmethods" call. Only the
// ban-list subset of NIP-86 is implemented: the allow-list methods
// (allowpubkey/listallowedpubkeys) are skipped because operating-model.md
// rules out an admission allow-list for this relay, and roles/kind-filter/
// relay-metadata methods are unrelated to moderation.
var supportedManagementMethods = []string{
	"supportedmethods",
	"banpubkey", "unbanpubkey", "listbannedpubkeys",
	"banevent", "allowevent", "listbannedevents",
	"blockip", "unblockip", "listblockedips",
}

// managementError marks an error as safe to return verbatim to the client
// (a request-validation problem, not internal state). Anything else
// returned by dispatchManagementMethod is logged in full server-side and
// reported to the client only as a generic failure, per the relay's rule
// against leaking internal error detail to callers.
type managementError struct {
	msg string
}

func (e *managementError) Error() string { return e.msg }

func newManagementError(format string, args ...any) error {
	return &managementError{msg: fmt.Sprintf(format, args...)}
}

// handleManagementRequest implements the NIP-86 relay management API,
// authenticated by NIP-98 (see verifyNip98). Every response, including
// unauthorized and method-level errors, uses the NIP-86 envelope
// ({"result":...} or {"error":...}) except the two cases the request never
// gets that far: an unreadable body, and a failed NIP-98/operator check,
// which NIP-98 itself specifies must be a 401.
func (h *RelayHandler) handleManagementRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", nip86ContentType)

	body, err := io.ReadAll(io.LimitReader(r.Body, maxManagementBodyBytes))
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}

	pubkey, err := verifyNip98(r, body, h.moderation.MaxEventAgeSeconds)
	if err != nil {
		slog.Warn("NIP-86 request rejected: NIP-98 verification failed", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(nip86Response{Error: "unauthorized"})
		return
	}
	if h.moderation.AdminPubkey == "" || pubkey != h.moderation.AdminPubkey {
		slog.Warn("NIP-86 request rejected: pubkey is not the configured operator", "pubkey", pubkey)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(nip86Response{Error: "unauthorized"})
		return
	}

	var req nip86Request
	if err := json.Unmarshal(body, &req); err != nil {
		json.NewEncoder(w).Encode(nip86Response{Error: "invalid JSON-RPC request"})
		return
	}

	result, err := h.dispatchManagementMethod(r.Context(), req.Method, req.Params)
	if err != nil {
		var mgmtErr *managementError
		if errors.As(err, &mgmtErr) {
			json.NewEncoder(w).Encode(nip86Response{Error: err.Error()})
		} else {
			slog.Error("NIP-86 management call failed", "method", req.Method, "operator_pubkey", pubkey, "error", err)
			json.NewEncoder(w).Encode(nip86Response{Error: "internal error"})
		}
		return
	}

	// Every successful moderation action is logged for accountability, but
	// never with event content, private keys, or anything beyond the
	// identifiers the operator themselves supplied in params.
	slog.Info("NIP-86 management call applied", "method", req.Method, "operator_pubkey", pubkey)
	json.NewEncoder(w).Encode(nip86Response{Result: result})
}

func (h *RelayHandler) dispatchManagementMethod(ctx context.Context, method string, params []json.RawMessage) (any, error) {
	switch method {
	case "supportedmethods":
		return supportedManagementMethods, nil

	case "banpubkey":
		pubkey, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.BanPubkey(ctx, pubkey, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "unbanpubkey":
		pubkey, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.UnbanPubkey(ctx, pubkey); err != nil {
			return nil, err
		}
		return true, nil

	case "listbannedpubkeys":
		entries, err := h.service.ListBannedPubkeys(ctx)
		if err != nil {
			return nil, err
		}
		return moderationEntriesToList("pubkey", entries), nil

	case "banevent":
		id, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.BanEvent(ctx, id, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "allowevent":
		id, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.AllowEvent(ctx, id); err != nil {
			return nil, err
		}
		return true, nil

	case "listbannedevents":
		entries, err := h.service.ListBannedEvents(ctx)
		if err != nil {
			return nil, err
		}
		return moderationEntriesToList("id", entries), nil

	case "blockip":
		ip, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.BlockIP(ctx, ip, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "unblockip":
		ip, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := h.service.UnblockIP(ctx, ip); err != nil {
			return nil, err
		}
		return true, nil

	case "listblockedips":
		entries, err := h.service.ListBlockedIPs(ctx)
		if err != nil {
			return nil, err
		}
		return moderationEntriesToList("ip", entries), nil

	default:
		return nil, newManagementError("unsupported method %q", method)
	}
}

// parseValueReasonParams parses the ["<value>", "<optional-reason>"] shape
// shared by every ban/unban/block/unblock method NIP-86 defines.
func parseValueReasonParams(params []json.RawMessage) (value, reason string, err error) {
	if len(params) < 1 {
		return "", "", newManagementError("missing required first parameter")
	}
	if err := json.Unmarshal(params[0], &value); err != nil || value == "" {
		return "", "", newManagementError("first parameter must be a non-empty string")
	}
	if len(params) > 1 {
		json.Unmarshal(params[1], &reason) // best-effort; an unparseable reason is simply omitted
	}
	return value, reason, nil
}

func moderationEntriesToList(key string, entries []repository.ModerationEntry) []map[string]string {
	out := make([]map[string]string, len(entries))
	for i, e := range entries {
		m := map[string]string{key: e.Value}
		if e.Reason != "" {
			m["reason"] = e.Reason
		}
		out[i] = m
	}
	return out
}
