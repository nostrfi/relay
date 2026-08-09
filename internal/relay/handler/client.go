package handler

import (
	"sync"

	"github.com/gorilla/websocket"
	negentropy "github.com/illuzen/go-negentropy"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type Client struct {
	handler       *RelayHandler
	conn          *websocket.Conn
	subscriptions sync.Map // map[string][]nostr.Filter
	mu            sync.Mutex
	challenge     string
	authPubkey    string
	negSessions   sync.Map // map[string]*NegentropySession
	msgLimiter    *rate.Limiter
	eventLimiter  *rate.Limiter
}

type NegentropySession struct {
	id      string
	filter  nostr.Filter
	storage *negentropy.Negentropy
}
