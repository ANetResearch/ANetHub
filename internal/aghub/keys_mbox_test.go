package aghub_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// mboxEpochSet signs a key set for c with seq and the given mailbox key.
func mboxEpochSet(t *testing.T, c *identity.Controller, seq uint64, mbox seal.Mbox) []byte {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := seal.SignEncKeySet(&seal.EncKeySet{Type: seal.EncKeySetType, AID: c.AID(), Seq: seq,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: mbox}, c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newMboxPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestPublishKeysMboxEpochMustRise (sealed-sender SSR-W9, M25): a mailbox
// key's epoch only rises, and only with a new key. On POST
// /agents/{aid}/keys and on /register, a set that changes the key without
// raising the epoch (as a daemon that lost its key file and made a new key
// under the old epoch would), raises the epoch without changing the key,
// lowers it (bringing an old key back), or carries an epoch of 2^53 or more
// is refused as invalid, and the stored set stays what it was.
func TestPublishKeysMboxEpochMustRise(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	a, b, cc, d := newMboxPub(t), newMboxPub(t), newMboxPub(t), newMboxPub(t)

	served := func() []byte {
		t.Helper()
		code, body := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys")
		if code != http.StatusOK {
			t.Fatalf("get keys: %d %s", code, body)
		}
		var v aghub.KeysView
		if err := json.Unmarshal(body, &v); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(v.KeySet)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var stored []byte
	accept := func(name string, seq uint64, m seal.Mbox) {
		t.Helper()
		raw := mboxEpochSet(t, c, seq, m)
		if code, body := publishKeys(t, srv, c, raw); code != http.StatusOK || !strings.Contains(string(body), `"ok"`) {
			t.Fatalf("%s: %d %s, want 200 ok", name, code, body)
		}
		stored = raw
		if !bytes.Equal(served(), raw) {
			t.Fatalf("%s: the hub does not serve the set it accepted", name)
		}
	}
	refuse := func(name string, seq uint64, m seal.Mbox) {
		t.Helper()
		raw := mboxEpochSet(t, c, seq, m)
		code, body := publishKeys(t, srv, c, raw)
		if code != http.StatusBadRequest || !strings.Contains(string(body), "mailbox key") {
			t.Errorf("%s over POST keys: %d %s, want 400 naming the mailbox key", name, code, body)
		}
		// The same set in a registration: registered, the set reported
		// invalid with why, nothing stored.
		reg := registerBody(t, c, "Agent", nil)
		reg["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
		code, body = registerFunded(t, srv, c, reg)
		var out aghub.RegisterResponse
		if err := json.Unmarshal(body, &out); err != nil || code != http.StatusOK {
			t.Fatalf("%s over /register: %d %s", name, code, body)
		}
		if out.KeysStatus != aghub.KeysStatusInvalid || !strings.Contains(out.KeysError, "mailbox key") {
			t.Errorf("%s over /register: keys_status %q (%s), want invalid naming the mailbox key", name, out.KeysStatus, out.KeysError)
		}
		if !bytes.Equal(served(), stored) {
			t.Errorf("%s: the stored set changed", name)
		}
	}

	accept("the first set", 10, seal.Mbox{Epoch: 1, Pub: a})
	accept("a new seq with the same mailbox key", 11, seal.Mbox{Epoch: 1, Pub: a})
	refuse("a new key under the same epoch", 12, seal.Mbox{Epoch: 1, Pub: b})
	refuse("the same key under a new epoch", 12, seal.Mbox{Epoch: 2, Pub: a})
	accept("a new key under a higher epoch", 12, seal.Mbox{Epoch: 2, Pub: b})
	refuse("a lower epoch with a new key", 13, seal.Mbox{Epoch: 1, Pub: cc})
	refuse("the old key back under its old epoch", 13, seal.Mbox{Epoch: 1, Pub: a})
	refuse("the current key under a lower epoch", 13, seal.Mbox{Epoch: 1, Pub: b})
	accept("an epoch that skips some", 13, seal.Mbox{Epoch: 7, Pub: cc})
	refuse("epoch 2^53", 14, seal.Mbox{Epoch: aghub.MaxMboxEpoch, Pub: d})
	refuse("epoch 2^64-1", 14, seal.Mbox{Epoch: ^uint64(0), Pub: d})
	accept("epoch 2^53-1", 14, seal.Mbox{Epoch: aghub.MaxMboxEpoch - 1, Pub: d})

	// The bound holds for a first set too: a hub never stores an epoch a
	// daemon cannot add one to (SSR-W10).
	fresh, _ := twoAgents(t)
	register(t, srv, fresh, "Fresh", nil)
	for _, e := range []uint64{aghub.MaxMboxEpoch, aghub.MaxMboxEpoch + 1, ^uint64(0)} {
		raw := mboxEpochSet(t, fresh, 1, seal.Mbox{Epoch: e, Pub: newMboxPub(t)})
		if _, err := store.PublishKeys(fresh.AID(), raw, fresh.KEL(), time.Now()); err == nil {
			t.Errorf("a first set with epoch %d was stored", e)
		}
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+fresh.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("after refused first sets the hub serves a set (%d)", code)
	}
}
