package ws

import (
	"context"
	"sync"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type Client struct {
	handler       *RelayHandler
	conn          *websocket.Conn
	subscriptions sync.Map // map[string]*subscription.Subscription
	mu            sync.Mutex
	challenge     string
	authPubkey    string
	negSessions   sync.Map // map[string]*NegentropySession
	msgLimiter    *rate.Limiter
	eventLimiter  *rate.Limiter

	// ctx is the connection's lifetime: cancelled by the read pump the
	// moment the socket errors out, so repository work started on behalf
	// of this connection stops instead of running to completion for a
	// client that can no longer receive the answer. Rooted in
	// context.Background(), not the upgrade request's context — after the
	// hijack the http.Request context's lifecycle no longer tracks the
	// connection.
	ctx    context.Context
	cancel context.CancelFunc
}

type NegentropySession struct {
	id      string
	filter  nostr.Filter
	storage *negentropy.Negentropy
}
