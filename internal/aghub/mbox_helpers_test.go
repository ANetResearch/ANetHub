package aghub_test

import (
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetCore/seal"
)

// testMboxPub is the one mailbox signing key the test key sets carry.
var testMboxPub = sync.OnceValue(func() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return pub
})

// testMbox is the mailbox signing key of a test key set: epoch 1 and the
// same Ed25519 public key every time. A set minted again for an AID keeps
// its mailbox key, as an honest daemon's does; a new key needs a higher
// epoch (sealed-sender SSR-W9), which the tests that change it give
// themselves (mboxEpochSet).
func testMbox(tb testing.TB) seal.Mbox {
	tb.Helper()
	return seal.Mbox{Epoch: 1, Pub: testMboxPub()}
}
