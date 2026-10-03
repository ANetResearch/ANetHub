package aghub_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/ANetResearch/ANetCore/seal"
)

// testMbox is a mailbox signing key for a test key set: epoch 1 and a fresh
// Ed25519 public key.
func testMbox(tb testing.TB) seal.Mbox {
	tb.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatal(err)
	}
	return seal.Mbox{Epoch: 1, Pub: pub}
}
