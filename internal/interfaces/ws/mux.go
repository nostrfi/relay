package ws

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const readinessPingTimeout = 2 * time.Second

// NewMux routes /healthz, /readyz, and /metrics alongside relayHandler,
// which continues to handle every other path (NIP-11, WebSocket upgrades,
// the landing page) exactly as before. Kept in this package rather than
// assembled inline in cmd/relay/main.go so tests/relay_test.go — which
// cannot import a main package — can exercise the exact routing used in
// production.
func NewMux(relayHandler http.Handler, ping func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/readyz", readyz(ping))
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", relayHandler)
	return mux
}

// healthz reflects process health only: if this handler can run at all, the
// process is alive. It deliberately does not check any dependency.
func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// readyz reports whether the relay can actually serve requests, by calling
// the supplied dependency check (in production, the repository's Ping) with
// a bounded timeout so a hung dependency cannot hang this endpoint.
func readyz(ping func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessPingTimeout)
		defer cancel()

		if err := ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	}
}
