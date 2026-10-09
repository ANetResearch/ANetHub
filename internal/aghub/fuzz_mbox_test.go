package aghub_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// storedMbox is the mailbox key of the set the hub holds for aid (nil: none).
func storedMbox(tb testing.TB, h *fz, aid string) (*seal.Mbox, uint64) {
	tb.Helper()
	raw, _, _, err := h.store.LocalKeys(aid)
	if err != nil {
		tb.Fatal(err)
	}
	if raw == nil {
		return nil, 0
	}
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		tb.Fatal(err)
	}
	var set seal.EncKeySet
	if err := coredet.Unmarshal(signed.Set, &set); err != nil {
		tb.Fatal(err)
	}
	return &set.Mbox, set.Seq
}

// FuzzHubMboxEpoch (sealed-sender SSR-W9): an agent publishes valid key sets
// with fuzzed sequence numbers and mailbox keys (one of three public keys,
// a small or an arbitrary epoch) over POST /agents/{aid}/keys. Properties:
//
//   - no answer is a 5xx;
//   - a set is accepted exactly when its seq is above the stored one, its
//     epoch is 1 or more and below 2^53, and against the stored set the
//     epoch did not go down and changed if and only if the key changed;
//   - a refused set leaves the stored set as it was;
//   - the hub never holds an epoch of 2^53 or more.
func FuzzHubMboxEpoch(f *testing.F) {
	h := newFZ(f)
	k, _ := h.agent(f, "fuzz-mbox", nil, false)
	var pubs [3]ed25519.PublicKey
	for i := range pubs {
		pubs[i], _, _ = ed25519.GenerateKey(nil)
	}
	f.Add(uint64(1), uint64(1), uint8(0))
	f.Add(uint64(2), uint64(1), uint8(1))
	f.Add(uint64(3), uint64(2), uint8(1))
	f.Add(uint64(4), uint64(1), uint8(2))
	f.Add(uint64(5), uint64(aghub.MaxMboxEpoch), uint8(2))
	f.Add(uint64(6), uint64(aghub.MaxMboxEpoch-1), uint8(2))
	f.Add(uint64(7), ^uint64(0), uint8(0))
	f.Add(uint64(8), uint64(0), uint8(0))

	f.Fuzz(func(t *testing.T, seq, epoch uint64, sel uint8) {
		if epoch > 8 && sel&0x80 == 0 {
			epoch = epoch%8 + 1 // mostly small epochs, so that the rule is met often
		}
		seq %= 1 << 40
		next := seal.Mbox{Epoch: epoch, Pub: pubs[int(sel&0x7f)%len(pubs)]}
		prev, prevSeq := storedMbox(t, h, k.AID())
		before, _, _, _ := h.store.LocalKeys(k.AID())

		now := uint64(time.Now().UnixMilli())
		kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
		if err != nil {
			t.Fatal(err)
		}
		set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: k.AID(), Seq: seq, Keys: []seal.EncKey{kp.Public},
			IssuedAt: now, Mbox: next}
		signed, err := seal.SignEncKeySet(set, k.Sign)
		var rec int
		if err != nil {
			// The signer refuses what no verifier takes (epoch 0); the hub
			// never sees it.
			if epoch != 0 {
				t.Fatalf("signing epoch %d: %v", epoch, err)
			}
			return
		}
		raw, _ := signed.Marshal()
		body := fzJSON(t, map[string]any{"keys": base64.RawURLEncoding.EncodeToString(raw), "prev_seq": prevSeq})
		rec = h.signedDo(k, relayauth.ActionKeys, http.MethodPost, "/agents/"+k.AID()+"/keys", "", body).Code
		if !allowed(rec, 200, 400, 409) {
			t.Fatalf("publish: unexpected %d", rec)
		}

		rule := next.Epoch >= 1 && next.Epoch < aghub.MaxMboxEpoch
		if prev != nil {
			same := bytes.Equal(prev.Pub, next.Pub)
			rule = rule && next.Epoch >= prev.Epoch && same == (next.Epoch == prev.Epoch)
		}
		advances := prev == nil || seq > prevSeq
		if want := rule && advances; (rec == http.StatusOK) != want {
			t.Fatalf("seq %d over %d, mbox %d over %v: answered %d, want accepted %v", seq, prevSeq, next.Epoch, prev, rec, want)
		}
		after, _, _, _ := h.store.LocalKeys(k.AID())
		if rec != http.StatusOK && !bytes.Equal(before, after) {
			t.Fatalf("a refused set (%d) changed the stored one", rec)
		}
		if m, _ := storedMbox(t, h, k.AID()); m != nil && m.Epoch >= aghub.MaxMboxEpoch {
			t.Fatalf("the hub holds epoch %d", m.Epoch)
		}
	})
}
