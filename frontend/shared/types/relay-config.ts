/**
 * The relay's operator-visible configuration, mirroring ConfigSnapshot in
 * backend/internal/interfaces/ws/config_api.go.
 *
 * Identity fields are deliberately absent: they are the NIP-11 document,
 * which the dashboard already reads from its own public route.
 *
 * Values are effective — what the running process is enforcing, after code
 * defaults were applied at load — not a copy of config.yaml.
 */
export interface RelayConfig {
  resource_limits: {
    max_connections: number
    messages_per_second: number
    events_per_second: number
  }
  auth: {
    relay_url: string
    max_event_age_seconds: number
  }
  moderation: {
    admin_pubkey: string
    max_event_age_seconds: number
  }
  websocket: {
    mode: string
    allowed_origins: string[]
  }
  retention: {
    purge_interval_seconds: number
  }
  server: {
    listen_addr: string
    shutdown_timeout_seconds: number
  }
  storage: {
    db_path: string
  }
}
