// Mirrors backend/internal/interfaces/ws/config.go's RelayInfo/RelayLimitation
// JSON shape (the relay's NIP-11 document).
export interface RelayLimitation {
  max_message_length?: number
  max_subscriptions?: number
  max_filters?: number
  max_limit?: number
  max_subid_length?: number
  max_event_tags?: number
  max_content_length?: number
  min_pow_difficulty?: number
  auth_required?: boolean
  payment_required?: boolean
  restricted_writes?: boolean
  created_at_lower_limit?: number
  created_at_upper_limit?: number
}

export interface RelayInfo {
  name?: string
  description?: string
  pubkey?: string
  contact?: string
  supported_nips?: number[]
  software?: string
  version?: string
  limitation?: RelayLimitation
}
