import type { RelayConfig } from '~~/shared/types/relay-config'

/**
 * Turns the relay's configuration response into the rows the page renders.
 *
 * Extracted from the page so it can be tested without a browser: the
 * formatting decisions here are where a misleading view would come from,
 * particularly the zero-means-unlimited case.
 */

/** One label/value line. `mono` for protocol data, `tabular` for figures. */
export interface ConfigRow {
  label: string
  value: string
  mono?: boolean
  tabular?: boolean
}

export interface ConfigSection {
  title: string
  rows: ConfigRow[]
}

export const EMPTY = '—'

export function formatText(value: string | undefined): string {
  return value === undefined || value === '' ? EMPTY : value
}

export function formatSeconds(value: number | undefined): string {
  return value === undefined ? EMPTY : `${value}s`
}

/**
 * Resource limits are disabled at zero, not set to zero: the relay creates
 * no limiter below 1, and skips the connection cap unless it is positive. A
 * bare "0" would read as "nothing allowed" when it means the opposite.
 */
export function formatLimit(value: number | undefined, unit: string): string {
  if (value === undefined) {
    return EMPTY
  }
  return value > 0 ? `${value} ${unit}` : 'Unlimited'
}

/** True when every resource limit is off, which an omitted section causes. */
export function hasNoResourceLimits(config: RelayConfig | null): boolean {
  const limits = config?.resource_limits
  return !!limits
    && limits.max_connections <= 0
    && limits.messages_per_second <= 0
    && limits.events_per_second <= 0
}

export function configSections(config: RelayConfig): ConfigSection[] {
  return [
    {
      title: 'Resource limits',
      rows: [
        { label: 'Max connections', value: formatLimit(config.resource_limits.max_connections, 'connections'), tabular: true },
        { label: 'Messages per second', value: formatLimit(config.resource_limits.messages_per_second, 'per second'), tabular: true },
        { label: 'Events per second', value: formatLimit(config.resource_limits.events_per_second, 'per second'), tabular: true }
      ]
    },
    {
      title: 'Authentication (NIP-42)',
      rows: [
        { label: 'Relay URL binding', value: formatText(config.auth.relay_url), mono: true },
        { label: 'Max event age', value: formatSeconds(config.auth.max_event_age_seconds), tabular: true }
      ]
    },
    {
      title: 'Moderation (NIP-86)',
      rows: [
        { label: 'Admin pubkey', value: formatText(config.moderation.admin_pubkey), mono: true },
        { label: 'Max event age', value: formatSeconds(config.moderation.max_event_age_seconds), tabular: true }
      ]
    },
    {
      title: 'WebSocket origins',
      rows: [
        { label: 'Mode', value: formatText(config.websocket.mode) },
        {
          label: 'Allowed origins',
          value: config.websocket.allowed_origins.length > 0 ? config.websocket.allowed_origins.join(', ') : EMPTY,
          mono: true
        }
      ]
    },
    {
      title: 'Retention',
      rows: [{ label: 'Purge interval', value: formatSeconds(config.retention.purge_interval_seconds), tabular: true }]
    },
    {
      title: 'Listener',
      rows: [
        { label: 'Listen address', value: formatText(config.server.listen_addr), mono: true },
        { label: 'Shutdown timeout', value: formatSeconds(config.server.shutdown_timeout_seconds), tabular: true }
      ]
    },
    {
      title: 'Storage',
      rows: [{ label: 'Database path', value: formatText(config.storage.db_path), mono: true }]
    }
  ]
}

/**
 * Whether the relay's operator key is the one signed into the dashboard.
 * Null when either is unknown — an absent answer is not a mismatch.
 */
export function operatorKeysMatch(relayAdminPubkey: string | undefined, signedInPubkey: string | undefined): boolean | null {
  if (!relayAdminPubkey || !signedInPubkey) {
    return null
  }
  return relayAdminPubkey === signedInPubkey
}
