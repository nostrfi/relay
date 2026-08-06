// Package metrics defines the relay's Prometheus instrumentation. All
// metrics and label values are deliberately low-cardinality and never
// include event content, pubkeys, or other high-cardinality/sensitive
// values — see KnownMessageType and KnownRejectionReason, which bound the
// "type" and "reason" label values so a client sending arbitrary garbage
// strings cannot inflate the metrics' cardinality.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	ConnectionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "relay_connections_active",
		Help: "Current number of open WebSocket connections.",
	})

	MessagesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_messages_total",
		Help: "Total messages received, by protocol message type.",
	}, []string{"type"})

	RejectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "relay_rejections_total",
		Help: "Total rejected messages or events, by rejection reason.",
	}, []string{"reason"})

	SubscriptionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "relay_subscriptions_active",
		Help: "Current number of active REQ subscriptions across all connections.",
	})

	QueryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "relay_query_duration_seconds",
		Help: "Repository query duration in seconds, by query type.",
	}, []string{"query"})

	EventsStoredTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "relay_events_stored_total",
		Help: "Total events successfully persisted.",
	})

	SaveFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "relay_save_failures_total",
		Help: "Total event save failures.",
	})
)

func init() {
	prometheus.MustRegister(
		ConnectionsActive,
		MessagesTotal,
		RejectionsTotal,
		SubscriptionsActive,
		QueryDuration,
		EventsStoredTotal,
		SaveFailuresTotal,
	)
}

// knownMessageTypes bounds the MessagesTotal "type" label to the relay's
// actual protocol message types.
var knownMessageTypes = map[string]bool{
	"EVENT":     true,
	"REQ":       true,
	"CLOSE":     true,
	"AUTH":      true,
	"NEG-OPEN":  true,
	"NEG-MSG":   true,
	"NEG-CLOSE": true,
}

// KnownMessageType returns msgType if it's one of the relay's protocol
// message types, or "unknown" otherwise.
func KnownMessageType(msgType string) string {
	if knownMessageTypes[msgType] {
		return msgType
	}
	return "unknown"
}

// knownRejectionReasons bounds the RejectionsTotal "reason" label to the
// relay's fixed NIP-01 prefix vocabulary.
var knownRejectionReasons = map[string]bool{
	"invalid":       true,
	"restricted":    true,
	"rate-limited":  true,
	"auth-required": true,
	"pow":           true,
	"error":         true,
}

// KnownRejectionReason returns reason if it's one of the relay's fixed
// rejection prefixes, or "unknown" otherwise.
func KnownRejectionReason(reason string) string {
	if knownRejectionReasons[reason] {
		return reason
	}
	return "unknown"
}
