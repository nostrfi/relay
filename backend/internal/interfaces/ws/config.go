package ws

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type RelayInfo struct {
	Name          string           `json:"name,omitzero" mapstructure:"name"`
	Description   string           `json:"description,omitzero" mapstructure:"description"`
	Pubkey        string           `json:"pubkey,omitzero" mapstructure:"pubkey"`
	Contact       string           `json:"contact,omitzero" mapstructure:"contact"`
	SupportedNips []int            `json:"supported_nips,omitzero" mapstructure:"supported_nips"`
	Software      string           `json:"software,omitzero" mapstructure:"software"`
	Version       string           `json:"version,omitzero"` // set from build-time ldflags only, not config
	Limitation    *RelayLimitation `json:"limitation,omitzero" mapstructure:"limitation"`
}

type RelayLimitation struct {
	MaxMessageLength    int  `json:"max_message_length,omitzero" mapstructure:"max_message_length"`
	MaxSubscriptions    int  `json:"max_subscriptions,omitzero" mapstructure:"max_subscriptions"`
	MaxFilters          int  `json:"max_filters,omitzero" mapstructure:"max_filters"`
	MaxLimit            int  `json:"max_limit,omitzero" mapstructure:"max_limit"`
	MaxSubidLength      int  `json:"max_subid_length,omitzero" mapstructure:"max_subid_length"`
	MaxEventTags        int  `json:"max_event_tags,omitzero" mapstructure:"max_event_tags"`
	MaxContentLength    int  `json:"max_content_length,omitzero" mapstructure:"max_content_length"`
	MinPowDifficulty    int  `json:"min_pow_difficulty,omitzero" mapstructure:"min_pow_difficulty"`
	AuthRequired        bool `json:"auth_required,omitzero" mapstructure:"auth_required"`
	PaymentRequired     bool `json:"payment_required,omitzero" mapstructure:"payment_required"`
	RestrictedWrites    bool `json:"restricted_writes,omitzero" mapstructure:"restricted_writes"`
	CreatedAtLowerLimit int  `json:"created_at_lower_limit,omitzero" mapstructure:"created_at_lower_limit"`
	CreatedAtUpperLimit int  `json:"created_at_upper_limit,omitzero" mapstructure:"created_at_upper_limit"`
}

// ResourceLimits configures operational controls that NIP-11 does not model:
// connection admission and per-connection rate limiting.
type ResourceLimits struct {
	MaxConnections    int `mapstructure:"max_connections"`
	MessagesPerSecond int `mapstructure:"messages_per_second"`
	EventsPerSecond   int `mapstructure:"events_per_second"`
}

// AuthConfig binds NIP-42 authentication to this specific relay instance.
// Kept separate from RelayInfo so it never appears in the public NIP-11
// JSON response.
type AuthConfig struct {
	RelayURL           string `mapstructure:"relay_url"`
	MaxEventAgeSeconds int    `mapstructure:"max_event_age_seconds"`
}

// ModerationConfig authorizes NIP-86 relay-management API requests, which
// must be signed (via NIP-98) by AdminPubkey. AdminPubkey defaults to
// RelayInfo.Pubkey — the already-public operator identity — when unset;
// operators who want a separate moderation credential can set it
// explicitly.
type ModerationConfig struct {
	AdminPubkey        string `mapstructure:"admin_pubkey"`
	MaxEventAgeSeconds int    `mapstructure:"max_event_age_seconds"`
}

const (
	websocketModeDevelopment = "development"
	websocketModeProduction  = "production"
)

// WebsocketConfig controls which HTTP Origins may open a WebSocket
// connection. Mode "production" is fail-closed: it requires a non-empty
// AllowedOrigins list. Mode "development" (the default) preserves the
// historical permissive behavior and must not be used for an
// internet-facing deployment.
type WebsocketConfig struct {
	Mode           string   `mapstructure:"mode"`
	AllowedOrigins []string `mapstructure:"allowed_origins"`
}

// RetentionConfig controls the background purge-and-checkpoint worker that
// removes expired events (see repository.PurgeExpired) and reclaims space.
type RetentionConfig struct {
	PurgeIntervalSeconds int `mapstructure:"purge_interval_seconds"`
}

// ServerConfig controls the HTTP/WebSocket listener and shutdown behavior.
//
// MetricsListenAddr is a second listener, and /metrics is served there and
// nowhere else. It used to sit on the public mux, which meant anyone who
// could reach the relay could read its traffic volume and shape, its
// rejection profile, how many clients were connected, how long it had been
// up, how much memory it held, and — via the default registry's Go and
// process collectors — the exact Go version it was built with
// (nostrfi/workspace#53). It defaults to loopback, which is the point: a
// deployment whose scraper lives elsewhere says so explicitly.
type ServerConfig struct {
	ListenAddr             string `mapstructure:"listen_addr"`
	MetricsListenAddr      string `mapstructure:"metrics_listen_addr"`
	ShutdownTimeoutSeconds int    `mapstructure:"shutdown_timeout_seconds"`
}

// StorageConfig controls where the DuckDB database file lives. Shared by
// normal startup and the -backup/-restore flags (see cmd/relay/backup.go).
type StorageConfig struct {
	DBPath string `mapstructure:"db_path"`
}

type Config struct {
	RelayInfo      RelayInfo        `mapstructure:"relay_info"`
	ResourceLimits ResourceLimits   `mapstructure:"resource_limits"`
	Auth           AuthConfig       `mapstructure:"auth"`
	Moderation     ModerationConfig `mapstructure:"moderation"`
	Websocket      WebsocketConfig  `mapstructure:"websocket"`
	Retention      RetentionConfig  `mapstructure:"retention"`
	Server         ServerConfig     `mapstructure:"server"`
	Storage        StorageConfig    `mapstructure:"storage"`
}

// ConfigFileEnv names the configuration file outright, overriding the
// search below. Set it when the relay runs from a directory that is
// neither its own nor the repository root — a systemd unit, say, or a
// packaged install with the config under /etc.
const ConfigFileEnv = "RELAY_CONFIG_FILE"

// MetricsListenAddrEnv overrides server.metrics_listen_addr. The container
// needs a non-loopback metrics bind, and overriding one field by environment
// is less machinery than shipping it a second configuration file.
const MetricsListenAddrEnv = "RELAY_METRICS_LISTEN_ADDR"

// defaultMetricsListenAddr keeps the metrics listener on loopback unless the
// operator says otherwise, so a relay upgraded with no configuration change
// stops serving metrics publicly rather than serving them on a new port.
//
// 2112 is client_golang's own documentation port. The obvious alternative,
// 9090, is Prometheus's, and 9091 is the Pushgateway's — a default that
// collides with the thing scraping it is a poor default, and this
// repository already uses 9090 as its example of a relay moved off :8080.
const defaultMetricsListenAddr = "127.0.0.1:2112"

// configSearchPaths lists where a config.yaml is looked for, in order.
//
// The relay used to look only in the working directory, which is right for
// the container (WORKDIR /app, config copied beside the binary) and for
// `go run ./cmd/relay` from backend/ — and wrong for every other way an
// operator starts it. Started from the repository root, or as a binary
// built elsewhere, the relay found nothing, said nothing, and came up on
// defaults: no relay_info.pubkey, so no moderation.admin_pubkey, so every
// signed operator request refused with a bare "unauthorized"
// (nostrfi/workspace#38).
func configSearchPaths() []string {
	paths := []string{"."}

	// Beside the binary, which is where the container keeps it and where a
	// packaged install usually does.
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Dir(exe))
	}

	// The repository root, one directory above the config: where a relay
	// built with `go build -o ../relay ./cmd/relay` gets started from.
	paths = append(paths, "backend")

	return paths
}

func LoadConfig() (*Config, error) {
	viper.SetConfigType("yaml")
	if explicit := os.Getenv(ConfigFileEnv); explicit != "" {
		// An explicitly named file that does not exist is a hard error:
		// falling back to defaults would ignore what the operator asked for.
		viper.SetConfigFile(explicit)
	} else {
		viper.SetConfigName("config")
		for _, path := range configSearchPaths() {
			viper.AddConfigPath(path)
		}
	}
	viper.AutomaticEnv()
	// AutomaticEnv does not reach a nested key through Unmarshal, so the one
	// setting a container has to override without mounting its own
	// configuration file is bound explicitly. docker-compose.yml uses it:
	// loopback is container-local, and the dashboard is a different
	// container.
	if err := viper.BindEnv("server.metrics_listen_addr", MetricsListenAddrEnv); err != nil {
		return nil, err
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Not fatal — the defaults below still make a runnable relay — but
		// said out loud, because the relay it makes has no operator key and
		// refuses every privileged call.
		slog.Warn("no configuration file found; continuing with built-in defaults",
			"searched", configSearchPaths(), "override_with", ConfigFileEnv)
	} else {
		slog.Info("configuration loaded", "file", viper.ConfigFileUsed())
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if cfg.RelayInfo.Limitation != nil && cfg.RelayInfo.Limitation.PaymentRequired {
		return nil, fmt.Errorf("config: relay_info.limitation.payment_required is true but no payment mechanism is implemented; advertising it would be misleading")
	}

	if cfg.Websocket.Mode == "" {
		cfg.Websocket.Mode = websocketModeDevelopment
	}
	if cfg.Websocket.Mode != websocketModeDevelopment && cfg.Websocket.Mode != websocketModeProduction {
		return nil, fmt.Errorf("config: websocket.mode must be %q or %q, got %q", websocketModeDevelopment, websocketModeProduction, cfg.Websocket.Mode)
	}
	if cfg.Websocket.Mode == websocketModeProduction && len(cfg.Websocket.AllowedOrigins) == 0 {
		return nil, fmt.Errorf("config: websocket.mode is %q but websocket.allowed_origins is empty; production mode is fail-closed and requires an explicit allow-list", websocketModeProduction)
	}

	if cfg.Auth.MaxEventAgeSeconds == 0 {
		cfg.Auth.MaxEventAgeSeconds = 600
	}

	if cfg.Moderation.AdminPubkey == "" {
		cfg.Moderation.AdminPubkey = cfg.RelayInfo.Pubkey
	}
	if cfg.Moderation.MaxEventAgeSeconds == 0 {
		cfg.Moderation.MaxEventAgeSeconds = 60
	}
	if cfg.Moderation.AdminPubkey == "" {
		// Every NIP-86 call and the configuration endpoint compare against
		// this key, so an unset one refuses everyone. Nothing downstream can
		// tell that apart from a wrong key, so it is named here, once, at
		// the only point that knows.
		slog.Warn("no operator pubkey configured; the NIP-86 management API and /api/config will refuse every request",
			"set", "relay_info.pubkey or moderation.admin_pubkey")
	}

	if cfg.Retention.PurgeIntervalSeconds == 0 {
		cfg.Retention.PurgeIntervalSeconds = 3600
	}

	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.MetricsListenAddr == "" {
		cfg.Server.MetricsListenAddr = defaultMetricsListenAddr
	}
	// Caught here rather than at bind time: the two listeners would race for
	// the port and the loser's "address already in use" says nothing about
	// which setting was wrong. Only the literal collision is detected —
	// ":8080" and "0.0.0.0:8080" name the same socket and still fail at bind
	// — but that is the one an operator writes by hand.
	if cfg.Server.MetricsListenAddr == cfg.Server.ListenAddr {
		return nil, fmt.Errorf("config: server.metrics_listen_addr (%q) must differ from server.listen_addr (%q); /metrics is served on its own listener so it is not reachable from the public one", cfg.Server.MetricsListenAddr, cfg.Server.ListenAddr)
	}
	if cfg.Server.ShutdownTimeoutSeconds == 0 {
		cfg.Server.ShutdownTimeoutSeconds = 5
	}
	if cfg.Storage.DBPath == "" {
		cfg.Storage.DBPath = "db/relay.db"
	}
	// A relative db_path is relative to the configuration file that set it,
	// not to whatever directory the relay was started from. The two used to
	// be the same thing, because the config was only ever found in the
	// working directory; now that it is found from elsewhere, a relay
	// started from the repository root would otherwise read backend/
	// config.yaml and then look for its database beside the repository
	// root instead of under backend/, which is where the file it just read
	// says it is — and what README.md has always documented.
	//
	// Unchanged for the container, where the config and the db directory
	// both sit in the working directory, and for an absolute db_path, which
	// names its own location.
	if configFile := viper.ConfigFileUsed(); configFile != "" && !filepath.IsAbs(cfg.Storage.DBPath) {
		cfg.Storage.DBPath = filepath.Join(filepath.Dir(configFile), cfg.Storage.DBPath)
	}

	return &cfg, nil
}
