import { describe, expect, it } from 'vitest'
import type { RelayConfig } from '../shared/types/relay-config'
import {
  EMPTY,
  configSections,
  formatLimit,
  formatSeconds,
  formatText,
  hasNoResourceLimits,
  operatorKeysMatch
} from '../shared/utils/config-view'

/** A relay configured explicitly — every field set in config.yaml. */
const configured: RelayConfig = {
  resource_limits: { max_connections: 1000, messages_per_second: 20, events_per_second: 5, search_timeout_seconds: 5 },
  auth: { relay_url: 'wss://relay.example.com', max_event_age_seconds: 600 },
  moderation: { admin_pubkey: 'a'.repeat(64), max_event_age_seconds: 60 },
  websocket: { mode: 'production', allowed_origins: ['https://relay.example.com'] },
  retention: { purge_interval_seconds: 3600 },
  server: { listen_addr: ':8080', metrics_listen_addr: '127.0.0.1:2112', shutdown_timeout_seconds: 5 },
  storage: { db_path: 'db/relay.db' }
}

/** What the relay reports when config.yaml omits those sections. */
const omitted: RelayConfig = {
  ...configured,
  resource_limits: { max_connections: 0, messages_per_second: 0, events_per_second: 0, search_timeout_seconds: 0 },
  auth: { relay_url: '', max_event_age_seconds: 600 },
  websocket: { mode: 'development', allowed_origins: [] }
}

const rowsOf = (config: RelayConfig, title: string) =>
  Object.fromEntries(configSections(config).find(s => s.title === title)!.rows.map(r => [r.label, r.value]))

describe('formatLimit', () => {
  it('reads zero as unlimited, not as none allowed', () => {
    // The relay creates no limiter below 1, so zero disables the limit.
    // Rendering a bare "0" would say the opposite of what it means.
    expect(formatLimit(0, 'connections')).toBe('Unlimited')
  })

  it('shows a configured limit with its unit', () => {
    expect(formatLimit(1000, 'connections')).toBe('1000 connections')
  })

  it('treats a negative value as disabled too, matching the relay', () => {
    expect(formatLimit(-1, 'connections')).toBe('Unlimited')
  })

  it('renders an unknown value as absent rather than as unlimited', () => {
    expect(formatLimit(undefined, 'connections')).toBe(EMPTY)
  })
})

describe('formatText and formatSeconds', () => {
  it('renders an unset string as absent', () => {
    expect(formatText('')).toBe(EMPTY)
    expect(formatText(undefined)).toBe(EMPTY)
  })

  it('passes a set string through', () => {
    expect(formatText('wss://relay.example.com')).toBe('wss://relay.example.com')
  })

  it('suffixes durations, including zero, which is a real value here', () => {
    expect(formatSeconds(600)).toBe('600s')
    expect(formatSeconds(0)).toBe('0s')
    expect(formatSeconds(undefined)).toBe(EMPTY)
  })
})

describe('hasNoResourceLimits', () => {
  it('is true when every limit is off, which an omitted section causes', () => {
    expect(hasNoResourceLimits(omitted)).toBe(true)
  })

  it('is false when any limit is set', () => {
    expect(hasNoResourceLimits(configured)).toBe(false)
    expect(hasNoResourceLimits({ ...omitted, resource_limits: { ...omitted.resource_limits, max_connections: 10 } })).toBe(false)
  })

  it('is false when there is no configuration to judge', () => {
    expect(hasNoResourceLimits(null)).toBe(false)
  })
})

describe('configSections', () => {
  it('covers every section the endpoint returns', () => {
    expect(configSections(configured).map(s => s.title)).toEqual([
      'Resource limits',
      'Authentication (NIP-42)',
      'Moderation (NIP-86)',
      'WebSocket origins',
      'Retention',
      'Listener',
      'Storage'
    ])
  })

  it('renders a fully configured relay as written', () => {
    expect(rowsOf(configured, 'Resource limits')['Max connections']).toBe('1000 connections')
    expect(rowsOf(configured, 'WebSocket origins')['Allowed origins']).toBe('https://relay.example.com')
    expect(rowsOf(configured, 'Listener')['Listen address']).toBe(':8080')
    // The metrics listener is a separate address, and an operator whose
    // scrape is refused needs to see which one it is (nostrfi/workspace#53).
    expect(rowsOf(configured, 'Listener')['Metrics address']).toBe('127.0.0.1:2112')
    expect(rowsOf(configured, 'Storage')['Database path']).toBe('db/relay.db')
  })

  it('renders omitted fields without inventing values', () => {
    const limits = rowsOf(omitted, 'Resource limits')
    expect(limits['Max connections']).toBe('Unlimited')
    expect(limits['Messages per second']).toBe('Unlimited')
    expect(limits['Events per second']).toBe('Unlimited')

    // An unset NIP-42 binding is absent, not the string "undefined".
    expect(rowsOf(omitted, 'Authentication (NIP-42)')['Relay URL binding']).toBe(EMPTY)
    // An empty origin allow-list reads as absent, and the mode still shows.
    expect(rowsOf(omitted, 'WebSocket origins')['Allowed origins']).toBe(EMPTY)
    expect(rowsOf(omitted, 'WebSocket origins')['Mode']).toBe('development')
  })

  it('joins multiple allowed origins', () => {
    const many = { ...configured, websocket: { mode: 'production', allowed_origins: ['https://a.example', 'https://b.example'] } }
    expect(rowsOf(many, 'WebSocket origins')['Allowed origins']).toBe('https://a.example, https://b.example')
  })

  it('marks protocol data as monospace and figures as tabular', () => {
    const moderation = configSections(configured).find(s => s.title === 'Moderation (NIP-86)')!
    expect(moderation.rows.find(r => r.label === 'Admin pubkey')?.mono).toBe(true)
    expect(moderation.rows.find(r => r.label === 'Max event age')?.tabular).toBe(true)
  })
})

describe('operatorKeysMatch', () => {
  it('is true when the relay operator is the signed-in key', () => {
    expect(operatorKeysMatch('a'.repeat(64), 'a'.repeat(64))).toBe(true)
  })

  it('is false when they have drifted apart', () => {
    // NUXT_ADMIN_PUBKEY and moderation.admin_pubkey are set separately;
    // this is the only place an operator learns they disagree.
    expect(operatorKeysMatch('a'.repeat(64), 'b'.repeat(64))).toBe(false)
  })

  it('is null rather than false when either side is unknown', () => {
    expect(operatorKeysMatch(undefined, 'a'.repeat(64))).toBeNull()
    expect(operatorKeysMatch('a'.repeat(64), undefined)).toBeNull()
    expect(operatorKeysMatch('', '')).toBeNull()
  })
})
