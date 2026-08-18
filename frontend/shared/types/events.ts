/**
 * The operator event-browse API, mirroring eventQueryRequest and
 * eventQueryResponse in backend/internal/interfaces/ws/events_api.go.
 *
 * A stored event is the Nostr event as the relay saved it: the dashboard
 * neither adds fields nor drops any, so the detail view can verify the
 * signature over exactly what is on disk.
 */

export interface StoredEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: string[][]
  content: string
  sig: string
}

export interface EventQueryRequest {
  ids?: string[]
  authors?: string[]
  kinds?: number[]
  tags?: Record<string, string[]>
  since?: number
  until?: number
  /** Case-insensitive substring of the content; at least three characters. */
  content_contains?: string
  limit?: number
}

export interface EventQueryResponse {
  events: StoredEvent[]
  /** The limit the relay actually applied, which may be lower than asked. */
  limit: number
  /**
   * The oldest created_at in this page, to send back as `until` for the
   * next one. Absent when this page is the last.
   */
  next_until?: number
}
