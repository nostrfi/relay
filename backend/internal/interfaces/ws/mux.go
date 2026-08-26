package ws

import (
	"context"
	"net/http"
	"time"

	"relay/internal/application"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const readinessPingTimeout = 2 * time.Second

// MuxOption registers additional routes on the relay's mux.
//
// Variadic so the operator API could be added (nostrfi/workspace#38)
// without changing every existing call site, and so later operator
// endpoints have an obvious place to go.
type MuxOption func(*http.ServeMux)

// WithAdminAPI registers the operator-only HTTP API, which needs the whole
// configuration: the relay handler holds only the sections it enforces, so
// retention, server, and storage reach this layer no other way.
//
// Every route it registers authenticates with NIP-98 as the configured
// operator. They are reachable from the public internet — the reverse proxy
// routes everything outside /admin to the relay — so none of them may rely
// on network position.
func WithAdminAPI(cfg Config) MuxOption {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/config", newConfigHandler(cfg))
	}
}

// WithEventsAPI registers the operator's event browse endpoint
// (nostrfi/workspace#36). Separate from WithAdminAPI because it needs the
// event service as well as the configuration, and the configuration
// endpoint has no business holding a repository.
//
// Authenticated as the operator, exactly as WithAdminAPI's routes are, and
// for the same reason: it is reachable from the public internet.
func WithEventsAPI(cfg Config, events application.EventService) MuxOption {
	return func(mux *http.ServeMux) {
		mux.HandleFunc("POST /api/events/query", newEventsQueryHandler(cfg, events))
		mux.HandleFunc("POST /api/events/stats", newEventStatsHandler(cfg, events))
	}
}

// NewMux routes /healthz and /readyz alongside relayHandler, which continues
// to handle every other path (NIP-11, WebSocket upgrades) exactly as before.
// Kept in this package rather than assembled inline in cmd/relay/main.go so
// tests/relay_test.go — which cannot import a main package — can exercise
// the exact routing used in production.
//
// /metrics is deliberately absent: it lives on the separate listener built
// by NewMetricsMux (nostrfi/workspace#53). Liveness and readiness stay here
// because they disclose nothing an operator would mind a stranger knowing,
// and a load balancer has to reach them on the port it already routes to.
func NewMux(relayHandler http.Handler, ping func(context.Context) error, opts ...MuxOption) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/readyz", readyz(ping))
	mux.Handle("/", relayHandler)
	for _, opt := range opts {
		opt(mux)
	}
	return mux
}

// NewMetricsMux serves /metrics, and only /metrics, for the listener bound
// to Config.Server.MetricsListenAddr. Nothing else is registered on it: the
// point of the second listener is that reaching it is already a statement
// about where the caller sits on the network, so anything reachable there
// should be worth that.
//
// It serves the default registry, Go runtime and process collectors
// included. Those were the most disclosing part of the old public endpoint —
// go_info names the exact build — and they are worth keeping now that
// reading them means being inside the deployment. One is load-bearing: the
// dashboard reads process_start_time_seconds to tell a restart from a rate,
// so that a counter reset is shown as one instead of being divided across
// the gap.
//
// Kept beside NewMux for the same reason NewMux is here at all: the tests
// cannot import cmd/relay, and metrics assertions should exercise the
// routing production actually uses.
func NewMetricsMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
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
