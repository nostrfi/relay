package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/nbd-wtf/go-nostr"
)

func main() {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)

	ev := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nil,
		Content:   "Hello, Nostr! This is a test event from wscat.",
	}
	err := ev.Sign(sk)
	if err != nil {
		log.Fatalf("Failed to sign event: %v", err)
	}

	msg := []any{"EVENT", ev}
	b, err := json.Marshal(msg)
	if err != nil {
		log.Fatalf("Failed to marshal event: %v", err)
	}

	fmt.Println(string(b))
}
