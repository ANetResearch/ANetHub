package aghub

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

func init() { wire3Setups["keys"] = wire3KeysSetup }

// wire3KeysSetup is the hub of wire3HubSetup for the key set fixtures
// (testdata/wire3/keys.json; core §2.12.2, forward-secrecy FS-H4, CORE-E5,
// G1): alice is registered here and has published nothing yet; mallory is
// not registered. Key sets of alice, base64url, signed by her:
//
//	${keys1000}      seq 1000, mailbox key A under epoch 1
//	${keys1000_std}  the same bytes in padded standard base64, which differs
//	                 from the base64url spelling
//	${keys2000}      seq 2000, key A
//	${keys3000}      seq 3000, key A
//	${keys500}       seq 500, key A
//	${keys_w9}       seq 2500, another mailbox key under epoch 1 (SSR-W9)
//	${keys_foreign}  seq 4000, alice's AID signed by mallory
//
// ${alice_kel} is alice's key history, base64url.
func wire3KeysSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, _, signers := wire3Hub(t)
	alice := signers["alice"]
	mallory := wire3Incept(t)
	signers["mallory"] = mallory
	env.Vars["mallory"] = mallory.AID()
	kel, err := identity.MarshalKEL(alice.KEL())
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	env.Vars["alice_kel"] = b64(kel)
	pubA, _, _ := ed25519.GenerateKey(nil)
	pubB, _, _ := ed25519.GenerateKey(nil)
	set := func(seq uint64, mbox ed25519.PublicKey, signer *identity.Controller) []byte {
		now := uint64(time.Now().UnixMilli())
		kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := seal.SignEncKeySet(&seal.EncKeySet{Type: seal.EncKeySetType, AID: alice.AID(), Seq: seq,
			Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: seal.Mbox{Epoch: 1, Pub: mbox}}, signer.Sign)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var k1000 []byte
	for {
		// A spelling in the standard alphabet that a lenient decoder would
		// take: one with padding, "+" or "/".
		k1000 = set(1000, pubA, alice)
		if strings.ContainsAny(base64.StdEncoding.EncodeToString(k1000), "+/=") {
			break
		}
	}
	env.Vars["keys1000"], env.Vars["keys1000_std"] = b64(k1000), base64.StdEncoding.EncodeToString(k1000)
	env.Vars["keys2000"] = b64(set(2000, pubA, alice))
	env.Vars["keys3000"] = b64(set(3000, pubA, alice))
	env.Vars["keys500"] = b64(set(500, pubA, alice))
	env.Vars["keys_w9"] = b64(set(2500, pubB, alice))
	env.Vars["keys_foreign"] = b64(set(4000, pubA, mallory))
	return env
}
