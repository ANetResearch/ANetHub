package aghub

// The federation of the kernel: SSR-H14a's bound on refreshes, SSR-W22's
// choice between equal key histories, SSR-H12's card home on a refresh,
// SSR-W21's 5 seconds.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// TestOriginRefreshBudget (SSR-H14a, 2026-10-09): a credential that does
// not verify under the mailbox key held for its remote owner has the
// owner's resolution made again at its next use, and anyone can send one.
// Forged credentials for each of 80 owners make at most 60 such
// resolutions in a minute for the whole hub, so the peers are asked for at
// most 60 buckets; past the bound a send takes the resolution kept. A
// minute later the bound is free again.
func TestOriginRefreshBudget(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	const owners = 80
	var all []*relayAgent
	for i := 0; i < owners; i++ {
		all = append(all, b.agent())
	}
	ip := 0
	send := func(o *relayAgent, forged bool) int {
		t.Helper()
		g := b.issue(o, seal.CapClassContact, time.Hour)
		if forged {
			_, wrong, _ := ed25519.GenerateKey(nil)
			c, err := seal.SignCap(wrong, &g.body)
			if err != nil {
				t.Fatal(err)
			}
			g.cap = c
		}
		ip++
		return a.send1Hint(withCap(t, envelope(t, o.aid, []byte(fmt.Sprint("m", ip))), g), "",
			fmt.Sprintf("198.51.%d.%d", ip/250, ip%250)).Code
	}
	// Each owner resolved once (not a refresh), then a forged credential
	// for each: refused, and the owner's resolution marked to be made again.
	for _, o := range all {
		if code := send(o, false); code != 200 {
			t.Fatalf("a first send to an owner: %d", code)
		}
	}
	for _, o := range all {
		if code := send(o, true); code != 403 {
			t.Fatalf("a forged credential: %d", code)
		}
	}
	before := b.hitsOf("/fed/v3/directory:bucket")
	for _, o := range all {
		send(o, true)
	}
	if asked := b.hitsOf("/fed/v3/directory:bucket") - before; asked > HomeRefreshesPerMinute || asked < HomeRefreshesPerMinute/2 {
		t.Fatalf("80 owners' resolutions made again asked the peer %d buckets in a minute, want at most %d",
			asked, HomeRefreshesPerMinute)
	}
	// Past the bound the resolution kept is used: a good credential still
	// reaches an owner whose refresh was refused.
	if code := send(all[owners-1], false); code != 200 {
		t.Fatalf("a good credential past the bound: %d", code)
	}
	a.advance(time.Minute)
	before = b.hitsOf("/fed/v3/directory:bucket")
	send(all[0], true)
	if b.hitsOf("/fed/v3/directory:bucket") == before {
		t.Fatal("a minute later an owner's resolution was not made again")
	}
	if HomeRefreshesPerMinute != 60 {
		t.Errorf("HomeRefreshesPerMinute = %d", HomeRefreshesPerMinute)
	}
}

// TestEqualKELsTakeTheNewerKeySet (SSR-W22): two peers serve entries of one
// AID with the same key history: the one with the newer key set is taken,
// whatever the order of the peer table.
func TestEqualKELsTakeTheNewerKeySet(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	kel, err := b.store.AgentKEL(owner.aid)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.PutAgent(owner.aid, "moved", nil, kel); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Second)
	c.publish(owner, 2) // a newer key set, with another mailbox key
	newer := owner.mbox
	for _, peers := range [][]string{{b.hubAID, c.hubAID}, {c.hubAID, b.hubAID}} {
		e, ok := a.srv.lookupEntry(context.Background(), owner.aid, peers, true)
		if !ok || e.home != c.hubAID || !bytes.Equal(e.mbox.Pub, newer.Pub) || e.mbox.Epoch != 2 {
			t.Fatalf("peers %v: resolved %+v %v, want C's newer key set", peers, e, ok)
		}
	}
}

// TestARefreshAsksOnlyTheCardsHome (SSR-H12 step 3, §2.12): the owner of a
// credential whose federated A2A card names its home is resolved again, for
// a newer epoch, by asking that home alone; no other peer learns the bucket.
func TestARefreshAsksOnlyTheCardsHome(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	owner := b.agent()
	kel, err := b.store.AgentKEL(owner.aid)
	if err != nil {
		t.Fatal(err)
	}
	keys, _, _, err := b.store.LocalKeys(owner.aid)
	if err != nil || keys == nil {
		t.Fatalf("B's key set for the owner: %v", err)
	}
	if _, err := a.store.db.Exec(`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, keys, home, peer_aid, verified_at, stored_at)
	    VALUES(?,?,?,?,?,?,?,?,?,?)`, owner.aid, 1, make([]byte, 32), []byte(`{}`), kel, keys, b.http.URL, b.hubAID, nowStamp(), nowStamp()); err != nil {
		t.Fatal(err)
	}
	b.publish(owner, 2) // the card's key set is of epoch 1
	env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "epoch 2")
	if rec := a.send1Hint(env, "", ""); rec.Code != 200 {
		t.Fatalf("a credential under the newer epoch: %d %s", rec.Code, rec.Body)
	}
	if b.hitsOf("/fed/v3/directory:bucket") == 0 {
		t.Fatal("the card's home was not asked")
	}
	if n := c.hitsOf("/fed/v3/directory:bucket"); n != 0 {
		t.Fatalf("a peer that is not the card's home was asked %d buckets", n)
	}
}

// TestALookupEndsWithinFiveSeconds (SSR-W21): the look-up of an AID's
// directory entry asks its peers for 5 seconds in all, whatever each
// request is allowed: a peer that answers each page within its own 5
// seconds, but not the whole bucket within 5 seconds, is missing from it.
func TestALookupEndsWithinFiveSeconds(t *testing.T) {
	net := newFedNet(t, 2)
	a, c := net.nodes[0], net.nodes[1]
	owner := c.agent()
	h, err := dirbox.Hash(owner.aid)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := c.store.DirBucket(h, dirbox.HashBits, nil)
	if err != nil || len(entries) != 1 {
		t.Fatalf("C's entry: %v %v", entries, err)
	}
	// Page 1: an entry of another AID at the start of the bucket; page 2:
	// the owner's. Each page takes 3 seconds.
	first := make([]byte, dirbox.HashLen)
	copy(first, truncatePrefix(h, FedLookupMaxBits))
	if bytes.Equal(first, h) {
		t.Skip("the owner's hash is the first of its bucket; run again")
	}
	c.mu.Lock()
	c.bucket = func(w http.ResponseWriter, r *http.Request) {
		var req DirBucketRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		time.Sleep(3 * time.Second)
		w.Header().Set(wire3.Header, "3")
		if req.Cursor == "" {
			writeJSON(w, http.StatusOK, map[string]any{"max_bits": 256, "next": b64u(first),
				"entries": []map[string]string{{"h": b64u(first), "box": "AAAA"}}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"max_bits": 256, "entries": entries})
	}
	c.mu.Unlock()
	start := time.Now()
	_, ok := a.srv.lookupEntry(context.Background(), owner.aid, []string{c.hubAID}, true)
	took := time.Since(start)
	if ok || took > PeerBucketWait+time.Second {
		t.Fatalf("the look-up took %s and found %v; want it to end at %s without the slow peer", took, ok, PeerBucketWait)
	}
	if PeerBucketWait != 5*time.Second {
		t.Errorf("PeerBucketWait = %s", PeerBucketWait)
	}
}
