package ws

import (
	"encoding/json"
	"io"
	"net/http"
)

// maxConfigBodyBytes bounds how much of a configuration request body is
// read. The body carries no parameters — it exists so the request can be
// NIP-98 signed, which requires a payload to hash — so this is generous.
const maxConfigBodyBytes = 4 << 10

// ConfigSnapshot is the operator-visible view of the relay's running
// configuration, excluding the NIP-11 identity fields the relay already
// publishes to anyone.
//
// It is a deliberate allow-list, not a marshal of Config. Anything added to
// Config later is invisible here until someone exposes it on purpose, which
// is what keeps a future credential from being published by accident —
// nostrfi/workspace#38 puts secret display out of scope. TestConfigSnapshot
// CoversEveryConfigField fails when Config grows a field this neither
// exposes nor explicitly excludes, so the list cannot go quietly stale.
//
// Values are effective: they are what the process is running with, after
// code defaults have been applied at load, not a copy of config.yaml.
type ConfigSnapshot struct {
	ResourceLimits ResourceLimitsView `json:"resource_limits"`
	Auth           AuthView           `json:"auth"`
	Moderation     ModerationView     `json:"moderation"`
	Websocket      WebsocketView      `json:"websocket"`
	Retention      RetentionView      `json:"retention"`
	Server         ServerView         `json:"server"`
	Storage        StorageView        `json:"storage"`
}

type ResourceLimitsView struct {
	MaxConnections       int `json:"max_connections"`
	MessagesPerSecond    int `json:"messages_per_second"`
	EventsPerSecond      int `json:"events_per_second"`
	SearchTimeoutSeconds int `json:"search_timeout_seconds"`
}

type AuthView struct {
	RelayURL           string `json:"relay_url"`
	MaxEventAgeSeconds int    `json:"max_event_age_seconds"`
}

// ModerationView carries the operator pubkey deliberately: it is an
// identity, not a secret — it defaults to the already-public NIP-11 pubkey
// — and showing it is how an operator confirms the dashboard and the relay
// name the same key.
type ModerationView struct {
	AdminPubkey        string `json:"admin_pubkey"`
	MaxEventAgeSeconds int    `json:"max_event_age_seconds"`
}

type WebsocketView struct {
	Mode           string   `json:"mode"`
	AllowedOrigins []string `json:"allowed_origins"`
}

type RetentionView struct {
	PurgeIntervalSeconds int `json:"purge_interval_seconds"`
}

type ServerView struct {
	ListenAddr             string `json:"listen_addr"`
	MetricsListenAddr      string `json:"metrics_listen_addr"`
	ShutdownTimeoutSeconds int    `json:"shutdown_timeout_seconds"`
}

type StorageView struct {
	DBPath string `json:"db_path"`
}

// NewConfigSnapshot projects the loaded configuration onto the view above.
func NewConfigSnapshot(cfg Config) ConfigSnapshot {
	origins := cfg.Websocket.AllowedOrigins
	if origins == nil {
		// Marshal as [] rather than null: the dashboard renders a list, and
		// "no origins configured" is a fact worth showing plainly.
		origins = []string{}
	}

	return ConfigSnapshot{
		ResourceLimits: ResourceLimitsView{
			MaxConnections:       cfg.ResourceLimits.MaxConnections,
			MessagesPerSecond:    cfg.ResourceLimits.MessagesPerSecond,
			EventsPerSecond:      cfg.ResourceLimits.EventsPerSecond,
			SearchTimeoutSeconds: cfg.ResourceLimits.SearchTimeoutSeconds,
		},
		Auth: AuthView{
			RelayURL:           cfg.Auth.RelayURL,
			MaxEventAgeSeconds: cfg.Auth.MaxEventAgeSeconds,
		},
		Moderation: ModerationView{
			AdminPubkey:        cfg.Moderation.AdminPubkey,
			MaxEventAgeSeconds: cfg.Moderation.MaxEventAgeSeconds,
		},
		Websocket: WebsocketView{
			Mode:           cfg.Websocket.Mode,
			AllowedOrigins: origins,
		},
		Retention: RetentionView{
			PurgeIntervalSeconds: cfg.Retention.PurgeIntervalSeconds,
		},
		Server: ServerView{
			ListenAddr:             cfg.Server.ListenAddr,
			MetricsListenAddr:      cfg.Server.MetricsListenAddr,
			ShutdownTimeoutSeconds: cfg.Server.ShutdownTimeoutSeconds,
		},
		Storage: StorageView{
			DBPath: cfg.Storage.DBPath,
		},
	}
}

// newConfigHandler serves the snapshot to the configured operator.
//
// POST rather than GET so verifyNip98 applies unchanged: it requires the
// payload tag, which needs a body to hash. The body carries nothing; it
// exists only to be signed over.
func newConfigHandler(cfg Config) http.HandlerFunc {
	snapshot := NewConfigSnapshot(cfg)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		body, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBodyBytes))
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}

		if _, err := authorizeOperator(r, body, cfg.Moderation.AdminPubkey, cfg.Moderation.MaxEventAgeSeconds); err != nil {
			logRejectedOperatorRequest("config", err)
			w.WriteHeader(http.StatusUnauthorized)

			refusal := map[string]string{"error": "unauthorized"}
			// A verification failure is safe to explain and expensive to
			// withhold; an identity failure is not. See authorizeOperator.
			if reason := publicReasonFor(err); reason != "" {
				refusal["reason"] = reason
			}
			json.NewEncoder(w).Encode(refusal)
			return
		}

		json.NewEncoder(w).Encode(snapshot)
	}
}
