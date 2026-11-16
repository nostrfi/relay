package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"relay/internal/domain/admin"
	"relay/internal/domain/moderation"
)

// nip86ContentType is the Content-Type that selects the NIP-86 relay
// management API instead of the normal WebSocket/NIP-11
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
	// Reason explains a refusal when doing so is safe — a malformed or
	// stale NIP-98 header, never who the operator is. Additive to NIP-86's
	// envelope, which defines result and error only.
	Reason string `json:"reason,omitzero"`
}

// supportedManagementMethods answers the "supportedmethods" call. Only the
// ban-list subset of NIP-86 is implemented: the allow-list methods
// (allowpubkey/listallowedpubkeys) are skipped because operating-model.md
// rules out an admission allow-list for this relay, and kind-filter/
// relay-metadata methods are unrelated to moderation.
var supportedManagementMethods = []string{
	"supportedmethods",
	"banpubkey", "unbanpubkey", "listbannedpubkeys",
	"banevent", "allowevent", "listbannedevents",
	"blockip", "unblockip", "listblockedips",
}

// roleManagementMethods are offered only when the handler has
// administrators (UseAdministrators). assignrole and unassignrole are
// NIP-86's, used with the single built-in role id "admin"; createrole and
// its siblings are not implemented. NIP-86 has no way to list assignments
// or to ask who the caller is, so listroleassignments and whoami are this
// relay's own (nostrfi/relay#55).
var roleManagementMethods = []string{
	"assignrole", "unassignrole", "listroleassignments", "whoami",
}

// ownerOnlyManagementMethods need the owner. Every other method an
// administrator may call: moderation is what administrators are for, while
// deciding who moderates stays with the owner, so one compromised
// administrator key cannot add others or lock the owner out (D2).
var ownerOnlyManagementMethods = map[string]bool{
	"assignrole":          true,
	"unassignrole":        true,
	"listroleassignments": true,
}

// managementMethodMinRole is the role a caller needs for method. Unknown
// methods need only an administrator, so they are answered "unsupported
// method" as before rather than with a role refusal.
func managementMethodMinRole(method string) admin.Role {
	if ownerOnlyManagementMethods[method] {
		return admin.RoleOwner
	}
	return admin.RoleAdmin
}

// managementCaller is who signed a management request.
type managementCaller struct {
	pubkey string
	role   admin.Role
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

	// "unauthorized" stays the error a stranger sees, so existing callers
	// parsing the NIP-86 envelope are unaffected; the reason rides
	// alongside it when it is safe to give.
	pubkey, role, err := h.operators.authorize(r, body, admin.RoleAdmin)
	if err != nil {
		logRejectedOperatorRequest("nip86", err)
		writeOperatorRefusal(w, err)
		return
	}

	var req nip86Request
	if err := json.Unmarshal(body, &req); err != nil {
		json.NewEncoder(w).Encode(nip86Response{Error: "invalid JSON-RPC request"})
		return
	}

	if minimum := managementMethodMinRole(req.Method); !role.Satisfies(minimum) {
		err := &insufficientRoleError{pubkey: pubkey, role: role, minimum: minimum}
		logRejectedOperatorRequest("nip86", fmt.Errorf("method %s: %w", req.Method, err))
		writeOperatorRefusal(w, err)
		return
	}

	caller := managementCaller{pubkey: pubkey, role: role}
	result, err := h.dispatchManagementMethod(r.Context(), caller, req.Method, req.Params)
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
	// identifiers the operator themselves supplied in params. whoami
	// changes nothing and runs at every dashboard sign-in, so it is not an
	// action worth a line.
	if req.Method != "whoami" {
		attrs := []any{"method", req.Method, "operator_pubkey", pubkey, "operator_role", role.String()}
		if req.Method == "assignrole" || req.Method == "unassignrole" {
			if target, err := parseRoleParams(req.Params); err == nil {
				attrs = append(attrs, "target_pubkey", target.pubkey)
			}
		}
		slog.Info("NIP-86 management call applied", attrs...)
	}
	json.NewEncoder(w).Encode(nip86Response{Result: result})
}

// maxReasonLength bounds the free-text reason stored alongside a ban or
// block, so a caller cannot push an unbounded string into the database
// through an otherwise small management call.
const maxReasonLength = 500

// hexIDLength is the length of a lowercase-hex event id or pubkey.
const hexIDLength = 64

// validateHexID rejects anything that is not a 64-character lowercase hex
// identifier. Without this the ban tables accept arbitrary text: a stored
// non-identifier can never match a real event or pubkey, so the operator
// believes a ban is in force when nothing is enforced.
func validateHexID(value, label string) error {
	if len(value) != hexIDLength {
		return newManagementError("%s must be %d hex characters, got %d", label, hexIDLength, len(value))
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return newManagementError("%s must be lowercase hex characters", label)
		}
	}
	return nil
}

// validateIPOrCIDR rejects anything net.ParseIP and net.ParseCIDR both
// refuse. isConnectionSourceBlocked parses stored values to match a
// connecting address, so an unparseable entry silently blocks nothing.
func validateIPOrCIDR(value string) error {
	if net.ParseIP(value) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return nil
	}
	return newManagementError("%q is not a valid IP address or CIDR range", value)
}

// validateReason bounds the optional second parameter.
//
// Counted in runes, not bytes: len() would make the limit depend on the
// encoding of the operator's language, and would disagree with the
// dashboard's own character count for any non-ASCII reason — rejecting,
// after the operator had already signed, something the form had accepted.
func validateReason(reason string) error {
	if count := utf8.RuneCountInString(reason); count > maxReasonLength {
		return newManagementError("reason must be %d characters or fewer, got %d", maxReasonLength, count)
	}
	if strings.TrimSpace(reason) == "" && reason != "" {
		return newManagementError("reason must not be only whitespace")
	}
	return nil
}

func (h *RelayHandler) dispatchManagementMethod(ctx context.Context, caller managementCaller, method string, params []json.RawMessage) (any, error) {
	if slices.Contains(roleManagementMethods, method) {
		if h.admins == nil {
			return nil, newManagementError("unsupported method %q", method)
		}
		return h.dispatchRoleMethod(ctx, caller, method, params)
	}

	switch method {
	case "supportedmethods":
		if h.admins == nil {
			return supportedManagementMethods, nil
		}
		return append(slices.Clone(supportedManagementMethods), roleManagementMethods...), nil

	case "banpubkey":
		pubkey, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateHexID(pubkey, "pubkey"); err != nil {
			return nil, err
		}
		if err := validateReason(reason); err != nil {
			return nil, err
		}
		if err := h.moderationService.BanPubkey(ctx, pubkey, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "unbanpubkey":
		pubkey, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateHexID(pubkey, "pubkey"); err != nil {
			return nil, err
		}
		if err := h.moderationService.UnbanPubkey(ctx, pubkey); err != nil {
			return nil, err
		}
		return true, nil

	case "listbannedpubkeys":
		entries, err := h.moderationService.ListBannedPubkeys(ctx)
		if err != nil {
			return nil, err
		}
		return moderationEntriesToList("pubkey", entries), nil

	case "banevent":
		id, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateHexID(id, "event id"); err != nil {
			return nil, err
		}
		if err := validateReason(reason); err != nil {
			return nil, err
		}
		if err := h.moderationService.BanEvent(ctx, id, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "allowevent":
		id, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateHexID(id, "event id"); err != nil {
			return nil, err
		}
		if err := h.moderationService.AllowEvent(ctx, id); err != nil {
			return nil, err
		}
		return true, nil

	case "listbannedevents":
		entries, err := h.moderationService.ListBannedEvents(ctx)
		if err != nil {
			return nil, err
		}
		return moderationEntriesToList("id", entries), nil

	case "blockip":
		ip, reason, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateIPOrCIDR(ip); err != nil {
			return nil, err
		}
		if err := validateReason(reason); err != nil {
			return nil, err
		}
		if err := h.moderationService.BlockIP(ctx, ip, reason); err != nil {
			return nil, err
		}
		return true, nil

	case "unblockip":
		ip, _, err := parseValueReasonParams(params)
		if err != nil {
			return nil, err
		}
		if err := validateIPOrCIDR(ip); err != nil {
			return nil, err
		}
		if err := h.moderationService.UnblockIP(ctx, ip); err != nil {
			return nil, err
		}
		return true, nil

	case "listblockedips":
		entries, err := h.moderationService.ListBlockedIPs(ctx)
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

func moderationEntriesToList(key string, entries []moderation.ModerationEntry) []map[string]string {
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

// roleParams is the parsed ["<pubkey>", "<role-id>", "<label>"?] of
// assignrole and unassignrole. The label is this relay's own extension:
// NIP-86 defines only the first two, and a client that sends just those is
// answered the same way.
type roleParams struct {
	pubkey string
	roleID string
	label  string
}

func parseRoleParams(params []json.RawMessage) (roleParams, error) {
	var p roleParams
	if len(params) < 2 {
		return p, newManagementError("expected [pubkey, role] parameters")
	}
	if err := json.Unmarshal(params[0], &p.pubkey); err != nil || p.pubkey == "" {
		return p, newManagementError("first parameter must be a non-empty pubkey string")
	}
	if err := json.Unmarshal(params[1], &p.roleID); err != nil || p.roleID == "" {
		return p, newManagementError("second parameter must be a non-empty role id string")
	}
	if len(params) > 2 {
		if err := json.Unmarshal(params[2], &p.label); err != nil {
			return p, newManagementError("third parameter, the label, must be a string")
		}
	}
	return p, nil
}

// dispatchRoleMethod answers the role methods. The caller's role has already
// been checked against managementMethodMinRole.
func (h *RelayHandler) dispatchRoleMethod(ctx context.Context, caller managementCaller, method string, params []json.RawMessage) (any, error) {
	switch method {
	case "whoami":
		return map[string]string{"pubkey": caller.pubkey, "role": caller.role.String()}, nil

	case "assignrole", "unassignrole":
		p, err := parseRoleParams(params)
		if err != nil {
			return nil, err
		}
		if err := admin.ValidatePubkey(p.pubkey); err != nil {
			return nil, newManagementError("%s", err.Error())
		}
		if p.roleID != admin.GrantableRoleID {
			return nil, newManagementError("unsupported role %q; the only role is %q", p.roleID, admin.GrantableRoleID)
		}
		if p.pubkey == h.admins.Owner() {
			return nil, newManagementError("%s", admin.ErrOwnerNotGrantable.Error())
		}
		if method == "unassignrole" {
			if err := h.admins.Revoke(ctx, p.pubkey); err != nil {
				return nil, err
			}
			return true, nil
		}
		if err := admin.ValidateLabel(p.label); err != nil {
			return nil, newManagementError("%s", err.Error())
		}
		if err := h.admins.Grant(ctx, p.pubkey, p.label, caller.pubkey); err != nil {
			return nil, err
		}
		return true, nil

	case "listroleassignments":
		admins, err := h.admins.List(ctx)
		if err != nil {
			return nil, err
		}
		// The owner first, from configuration: it holds every right an
		// administrator has, but was never granted, so it has no grant
		// fields.
		out := make([]map[string]any, 0, len(admins)+1)
		out = append(out, map[string]any{"pubkey": h.admins.Owner(), "role": admin.RoleOwner.String()})
		for _, a := range admins {
			m := map[string]any{
				"pubkey":     a.Pubkey,
				"role":       admin.GrantableRoleID,
				"granted_by": a.GrantedBy,
				"granted_at": a.GrantedAt,
			}
			if a.Label != "" {
				m["label"] = a.Label
			}
			out = append(out, m)
		}
		return out, nil

	default:
		return nil, newManagementError("unsupported method %q", method)
	}
}
