package aghub

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

func init() { wire3Setups["directory"] = wire3DirectorySetup }

// wire3DirectorySetup is the hub of wire3HubSetup for the directory fixtures
// (testdata/wire3/directory.json; sealed-sender §2.9, core §2.12.2): alice
// is registered with a key set, so the directory holds one entry and
// dir_max_bits is 0. ${alice_h} is alice's directory hash and
// ${alice_prefix8} its first byte, both base64url.
func wire3DirectorySetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, store, signers := wire3Hub(t)
	alice := signers["alice"]
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: alice.AID(), Seq: 1, IssuedAt: uint64(time.Now().UnixMilli()),
		Mbox: seal.Mbox{Epoch: 1, Pub: make([]byte, 32)}}
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	set.Keys = []seal.EncKey{kp.Public}
	signed, err := seal.SignEncKeySet(set, alice.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishKeys(alice.AID(), raw, alice.KEL(), time.Now()); err != nil {
		t.Fatal(err)
	}
	h, err := dirbox.Hash(alice.AID())
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(alice.KEL())
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	env.Vars["alice_h"] = b64(h)
	env.Vars["alice_prefix8"] = b64(h[:1])
	env.Vars["alice_kel"] = b64(kel)
	env.Vars["alice_keys"] = b64(raw)
	return env
}
