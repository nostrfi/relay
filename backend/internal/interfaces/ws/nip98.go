package ws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

const nip98AuthKind = 27235

// verifyNip98 validates the Authorization header of r against NIP-98, with
// the payload tag required (NIP-86 makes it mandatory; generic NIP-98 only
// recommends it). It returns the authenticated event's pubkey on success.
//
// body must be the exact bytes already read from r.Body by the caller:
// verifyNip98 does not read r.Body itself, since the NIP-86 dispatcher
// needs those same bytes to parse the RPC request.
func verifyNip98(r *http.Request, body []byte, maxAgeSeconds int) (string, error) {
	const prefix = "Nostr "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", fmt.Errorf("missing or malformed Authorization header")
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", fmt.Errorf("invalid base64 in Authorization header: %w", err)
	}

	var ev nostr.Event
	if err := json.Unmarshal(decoded, &ev); err != nil {
		return "", fmt.Errorf("invalid event JSON in Authorization header: %w", err)
	}

	if ev.Kind != nip98AuthKind {
		return "", fmt.Errorf("expected kind %d, got %d", nip98AuthKind, ev.Kind)
	}
	if _, err := domainevent.NewEvent(&ev); err != nil {
		return "", fmt.Errorf("signature verification failed")
	}

	age := nostr.Now() - ev.CreatedAt
	if age < 0 {
		age = -age
	}
	if int64(age) > int64(maxAgeSeconds) {
		return "", fmt.Errorf("event created_at is more than %d seconds from now", maxAgeSeconds)
	}

	var u, method, payload string
	for _, tag := range ev.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "u":
			u = tag[1]
		case "method":
			method = tag[1]
		case "payload":
			payload = tag[1]
		}
	}

	if !strings.EqualFold(method, r.Method) {
		return "", fmt.Errorf("method tag %q does not match request method %q", method, r.Method)
	}
	if !sameRequestURL(u, r) {
		return "", fmt.Errorf("u tag %q does not match request URL", u)
	}
	if payload == "" {
		return "", fmt.Errorf("missing required payload tag")
	}
	sum := sha256.Sum256(body)
	if payload != hex.EncodeToString(sum[:]) {
		return "", fmt.Errorf("payload tag does not match request body hash")
	}

	return ev.PubKey, nil
}

// sameRequestURL compares the NIP-98 u tag against the request as this
// server observed it (path and query only), tolerant of the scheme/host
// mismatch a TLS-terminating reverse proxy can introduce. A strict
// absolute-URL comparison would need a configured canonical URL to work
// behind such a proxy, which this relay does not have.
//
// An empty path is normalized to "/" on both sides: a URL with no path
// (e.g. a bare "https://relay.example.com") is conventionally equivalent
// to one with "/", and Go's own HTTP client sends an empty-path request as
// "GET / ..." on the wire — the server never actually observes an empty
// r.URL.Path for such a request, so the client-signed u tag must match
// what the server sees, not what the client originally typed.
func sameRequestURL(u string, r *http.Request) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	reqPath := r.URL.Path
	if reqPath == "" {
		reqPath = "/"
	}
	return path == reqPath && parsed.RawQuery == r.URL.RawQuery
}
