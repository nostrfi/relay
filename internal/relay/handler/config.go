package handler

import (
	"fmt"

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
type ServerConfig struct {
	ListenAddr             string `mapstructure:"listen_addr"`
	ShutdownTimeoutSeconds int    `mapstructure:"shutdown_timeout_seconds"`
}

// StorageConfig controls where the DuckDB database file lives. Shared by
// normal startup and the -backup/-restore flags (see cmd/relay/backup.go).
type StorageConfig struct {
	DBPath string `mapstructure:"db_path"`
}

type Config struct {
	RelayInfo      RelayInfo       `mapstructure:"relay_info"`
	ResourceLimits ResourceLimits  `mapstructure:"resource_limits"`
	Auth           AuthConfig      `mapstructure:"auth"`
	Websocket      WebsocketConfig `mapstructure:"websocket"`
	Retention      RetentionConfig `mapstructure:"retention"`
	Server         ServerConfig    `mapstructure:"server"`
	Storage        StorageConfig   `mapstructure:"storage"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
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

	if cfg.Retention.PurgeIntervalSeconds == 0 {
		cfg.Retention.PurgeIntervalSeconds = 3600
	}

	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.ShutdownTimeoutSeconds == 0 {
		cfg.Server.ShutdownTimeoutSeconds = 5
	}
	if cfg.Storage.DBPath == "" {
		cfg.Storage.DBPath = "db/relay.db"
	}

	return &cfg, nil
}
