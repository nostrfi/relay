package ws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	domainevent "relay/internal/domain/event"

	"github.com/nbd-wtf/go-nostr"
)

const nip98AuthKind = 27235

// nip98Verified is what a successful verifyNip98 learned about the event.
type nip98Verified struct {
	PubKey    string
	ID        string
	CreatedAt nostr.Timestamp
}

// verifyNip98 validates the Authorization header of r against NIP-98, with
// the payload tag required (NIP-86 makes it mandatory; generic NIP-98 only
// recommends it).
//
// origin is this relay's canonical origin, as canonicalOrigin returns it.
// The u tag must name it (see sameRequestURL).
//
// body must be the exact bytes already read from r.Body by the caller:
// verifyNip98 does not read r.Body itself, since the NIP-86 dispatcher
// needs those same bytes to parse the RPC request.
func verifyNip98(r *http.Request, body []byte, maxAgeSeconds int, origin string) (nip98Verified, error) {
	const prefix = "Nostr "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return nip98Verified{}, fmt.Errorf("missing or malformed Authorization header")
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return nip98Verified{}, fmt.Errorf("invalid base64 in Authorization header: %w", err)
	}

	var ev nostr.Event
	if err := json.Unmarshal(decoded, &ev); err != nil {
		return nip98Verified{}, fmt.Errorf("invalid event JSON in Authorization header: %w", err)
	}

	if ev.Kind != nip98AuthKind {
		return nip98Verified{}, fmt.Errorf("expected kind %d, got %d", nip98AuthKind, ev.Kind)
	}
	if _, err := domainevent.NewEvent(&ev); err != nil {
		return nip98Verified{}, fmt.Errorf("signature verification failed")
	}

	age := nostr.Now() - ev.CreatedAt
	if age < 0 {
		age = -age
	}
	if int64(age) > int64(maxAgeSeconds) {
		return nip98Verified{}, fmt.Errorf("event created_at is more than %d seconds from now", maxAgeSeconds)
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
		return nip98Verified{}, fmt.Errorf("method tag %q does not match request method %q", method, r.Method)
	}
	if !sameOrigin(u, origin) {
		return nip98Verified{}, fmt.Errorf("u tag %q names a different host than this relay (%s)", u, origin)
	}
	if !sameRequestURL(u, r) {
		return nip98Verified{}, fmt.Errorf("u tag %q does not match request URL", u)
	}
	if payload == "" {
		return nip98Verified{}, fmt.Errorf("missing required payload tag")
	}
	sum := sha256.Sum256(body)
	if payload != hex.EncodeToString(sum[:]) {
		return nip98Verified{}, fmt.Errorf("payload tag does not match request body hash")
	}

	return nip98Verified{PubKey: ev.PubKey, ID: ev.ID, CreatedAt: ev.CreatedAt}, nil
}

// canonicalOrigin is the origin operator requests must be signed for:
// "scheme://host[:port]", lower-cased, with a default port dropped.
//
// apiOrigin (moderation.api_origin) wins when set. Otherwise it is derived
// from relayURL (auth.relay_url), the relay's public wss:// address, which
// serves its HTTP APIs at the matching https:// origin. "" means neither is
// set, or the one that is cannot be parsed; operator requests are then
// refused (nostrfi/relay#60).
func canonicalOrigin(apiOrigin, relayURL string) string {
	raw := apiOrigin
	if raw == "" {
		raw = relayURL
	}
	if raw == "" {
		return ""
	}
	origin, ok := originOf(raw)
	if !ok {
		return ""
	}
	return origin
}

// originOf normalizes rawURL's scheme and host. ws:// and wss:// map to the
// http:// and https:// origin a browser or HTTP client would sign.
func originOf(rawURL string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "ws":
		scheme = "http"
	case "wss":
		scheme = "https"
	case "http", "https":
	default:
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, true
}

// sameOrigin reports whether the u tag names this relay's origin.
//
// This is what makes a signature this relay's alone. Without it, a
// signature a NIP-07 extension made for any other website, for a path that
// happens to match, is accepted here: a malicious page can have the owner
// sign an assignrole call "for itself" and replay it at the relay
// (nostrfi/relay#60). The comparison is against configuration, not the
// request: behind a TLS-terminating proxy, or the dashboard's server-side
// forwarding, the request's own scheme and Host are not what was signed.
func sameOrigin(u, origin string) bool {
	if origin == "" {
		return false
	}
	signed, ok := originOf(u)
	return ok && signed == origin
}

// sameRequestURL compares the NIP-98 u tag's path and query against the
// request as this server observed it. The scheme and host are checked
// separately against the configured origin (sameOrigin), since a
// TLS-terminating reverse proxy changes what this server observes.
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
