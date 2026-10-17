package aghub

// Federation v3 at the origin, more of it (sealed-sender §2.9, §4.2.6,
// SSR-H12, SSR-H13, SSR-W19, SSR-W22): what a peer learns from this hub's
// lookups, the bucket the sender's send takes, the routes a card and a
// refusal give, the entries taken and the pages of a merged bucket.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// TestHomeLookupAsksABucketNotTheAID (SSR-H12 step 4, SSR-W19, §6.2): when
// the origin looks for the home of a recipient, each peer is asked for a
// bucket of at most FedLookupMaxBits bits, never for the recipient's
// directory hash: a peer that is not the home learns a bucket, not whom a
// sender here writes to. A peer that states a dir_max_bits of 256 is asked
// no narrower bucket for it.
func TestHomeLookupAsksABucketNotTheAID(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	var mu sync.Mutex
	asked := map[*fedNode][]uint{}
	// B answers as itself; C states it serves 256 bits and holds nothing.
	for _, x := range []struct {
		nd    *fedNode
		claim bool
	}{{b, false}, {c, true}} {
		nd, claim := x.nd, x.claim
		nd.mu.Lock()
		nd.bucket = func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var q DirBucketRequest
			if json.Unmarshal(body, &q) != nil || q.Bits == nil {
				t.Errorf("a bucket request %q", body)
				return
			}
			mu.Lock()
			asked[nd] = append(asked[nd], *q.Bits)
			mu.Unlock()
			if claim {
				w.Header().Set(wire3.Header, "3")
				writeJSON(w, http.StatusOK, map[string]any{"max_bits": dirbox.HashBits, "entries": []any{}})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			nd.mu.Lock()
			root := nd.root
			nd.mu.Unlock()
			root.ServeHTTP(w, r)
		}
		nd.mu.Unlock()
	}
	first, second, owner := b.agent(), b.agent(), b.agent()
	if rec := a.send0To(first.aid, "", "k0"); rec.Code != 200 {
		t.Fatalf("a first contact: %d %s", rec.Code, rec.Body)
	}
	env, _ := capEnv(t, b, owner, seal.CapClassContact, time.Hour, "k1")
	if rec := a.send1Hint(env, "", ""); rec.Code != 200 {
		t.Fatalf("a send under a credential: %d %s", rec.Code, rec.Body)
	}
	// C has now stated 256 bits.
	if rec := a.send0To(second.aid, "", "k0 again"); rec.Code != 200 {
		t.Fatalf("a first contact after C's statement: %d %s", rec.Code, rec.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked[b]) == 0 || len(asked[c]) < 3 {
		t.Fatalf("bucket requests: %d at B, %d at C; want each lookup asked of both", len(asked[b]), len(asked[c]))
	}
	for nd, name := range map[*fedNode]string{b: "B (the home)", c: "C"} {
		for _, bits := range asked[nd] {
			if bits > FedLookupMaxBits {
				t.Errorf("%s was asked for a bucket of %d bits, more than %d", name, bits, FedLookupMaxBits)
			}
		}
	}
}

// TestOriginTakesOnlyTheSendersBucket (SSR-H13): a send the origin hands on
// to a peer costs the sender's own bucket one token there — a credential's
// bucket, or a first contact's session send bucket — and nothing else; once
// that bucket is empty, the send is refused 429 at the origin and nothing is
// forwarded.
func TestOriginTakesOnlyTheSendersBucket(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	g := b.issue(recip, seal.CapClassContact, time.Hour)
	key, rate := capKey(&g.body), capRate(&g.body)
	if rec := a.send1Hint(withCap(t, envelope(t, recip.aid, []byte("1")), g), b.hubAID, ""); rec.Code != 200 {
		t.Fatalf("kind 1: %d %s", rec.Code, rec.Body)
	}
	if lost := rate.burst - a.srv.relay.caps.tokens(key, rate); lost < 0.99 || lost > 1.01 {
		t.Errorf("a forwarded send took %v tokens from the credential's bucket at the origin, want 1", lost)
	}
	drain(a.srv.relay.caps, key, rate)
	forwards := b.forwards()
	expectRefusal(t, a.send1Hint(withCap(t, envelope(t, recip.aid, []byte("2")), g), b.hubAID, ""), 429, "rate_limited")
	if b.forwards() != forwards {
		t.Fatal("a send was forwarded with the credential's bucket empty at the origin")
	}
	sender := a.agent()
	ss := a.openSession(sender.c)
	sr := a.srv.sessionRate(sender.aid)
	fc := firstContactRate(a.store.QuotaFor(recip.aid))
	if rec := a.send0(ss, envelope(t, recip.aid, []byte("k0")), kind0Opts{home: b.hubAID}); rec.Code != 200 {
		t.Fatalf("kind 0: %d %s", rec.Code, rec.Body)
	}
	if lost := sr.burst - a.srv.relay.sessionSend.tokens(sender.aid, sr); lost < 0.99 || lost > 1.01 {
		t.Errorf("a forwarded first contact took %v tokens from the session send bucket at the origin, want 1", lost)
	}
	if got := a.srv.relay.firstContact.tokens(recip.aid, fc); got != fc.burst {
		t.Errorf("the origin took from the recipient's first-contact bucket (%v left): that bucket is the home's", got)
	}
	drain(a.srv.relay.sessionSend, sender.aid, sr)
	forwards = b.forwards()
	expectRefusal(t, a.send0(ss, envelope(t, recip.aid, []byte("k0 2")), kind0Opts{home: b.hubAID}), 429, "rate_limited")
	if b.forwards() != forwards {
		t.Fatal("a first contact was forwarded with the session send bucket empty at the origin")
	}
}

// TestACardsHomeIsUsedWithoutAskingTheBuckets (SSR-H12 step 3): a
// recipient whose federated A2A card names a delivery peer as its home is
// sent there, a first contact and a send under a credential (whose mailbox
// key comes from the key set the card arrived with) alike, without asking
// any peer for a bucket.
func TestACardsHomeIsUsedWithoutAskingTheBuckets(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	recip := b.agent()
	kel, err := b.store.AgentKEL(recip.aid)
	if err != nil {
		t.Fatal(err)
	}
	keys, _, _, err := b.store.LocalKeys(recip.aid)
	if err != nil || keys == nil {
		t.Fatalf("B's key set for the recipient: %v", err)
	}
	// The card names B's endpoint, in other case and with a slash.
	home := strings.ToUpper(b.http.URL) + "/"
	if _, err := a.store.db.Exec(`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, keys, home, peer_aid, verified_at, stored_at)
	    VALUES(?,?,?,?,?,?,?,?,?,?)`, recip.aid, 1, make([]byte, 32), []byte(`{}`), kel, keys, home, b.hubAID, nowStamp(), nowStamp()); err != nil {
		t.Fatal(err)
	}
	if rec := a.send0To(recip.aid, "", "k0"); rec.Code != 200 {
		t.Fatalf("a first contact: %d %s", rec.Code, rec.Body)
	}
	env, _ := capEnv(t, b, recip, seal.CapClassContact, time.Hour, "k1")
	if rec := a.send1Hint(env, "", ""); rec.Code != 200 {
		t.Fatalf("a send under a credential: %d %s", rec.Code, rec.Body)
	}
	if b.forwards() != 2 || c.forwards() != 0 {
		t.Fatalf("forwards: %d at B, %d at C; want 2, 0", b.forwards(), c.forwards())
	}
	if n := b.hitsOf("/fed/v3/directory:bucket") + c.hitsOf("/fed/v3/directory:bucket"); n != 0 {
		t.Fatalf("%d bucket requests for a recipient whose card names its home", n)
	}
}

// TestAMovedRecipientIsFoundAgainAfterA404 (SSR-H13, §2.12): when the home
// held for a first contact's recipient answers that it is not registered
// there, the sender is told 404 recipient_unknown and no other hub is tried;
// the next first contact resolves the recipient afresh, past the peers'
// cached buckets, and reaches it at the hub it moved to.
func TestAMovedRecipientIsFoundAgainAfterA404(t *testing.T) {
	net := newFedNet(t, 3)
	a, b, c := net.nodes[0], net.nodes[1], net.nodes[2]
	recip := b.agent()
	if rec := a.send0To(recip.aid, "", "at B"); rec.Code != 200 || b.forwards() != 1 {
		t.Fatalf("at B: %d %s", rec.Code, rec.Body)
	}
	kel, _ := b.store.AgentKEL(recip.aid)
	if err := c.store.PutAgent(recip.aid, "moved", nil, kel); err != nil {
		t.Fatal(err)
	}
	keyset, _, _, _ := b.store.LocalKeys(recip.aid)
	if _, err := c.store.PublishKeys(recip.aid, keyset, 0, recip.c.KEL(), c.clock()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.store.db.Exec(`DELETE FROM agent WHERE aid=?`, recip.aid); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, a.send0To(recip.aid, "", "to B, which no longer has it"), 404, "recipient_unknown")
	if b.forwards() != 2 || c.forwards() != 0 {
		t.Fatalf("forwards: %d at B, %d at C; want 2, 0", b.forwards(), c.forwards())
	}
	if rec := a.send0To(recip.aid, "", "found at C"); rec.Code != 200 || c.forwards() != 1 || b.forwards() != 2 {
		t.Fatalf("after the 404: %d %s; forwards at B %d, at C %d", rec.Code, rec.Body, b.forwards(), c.forwards())
	}
}

// TestAPeersWiderBucketIsCutToTheOneAsked (SSR-W19): a peer asked at its
// own, smaller dir_max_bits answers a wider bucket; only the entries of the
// bucket asked for are taken from it.
func TestAPeersWiderBucketIsCutToTheOneAsked(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	var halves [2]int
	for i := 0; i < 64 && (halves[0] == 0 || halves[1] == 0); i++ {
		h, err := dirbox.Hash(b.agent().aid)
		if err != nil {
			t.Fatal(err)
		}
		halves[h[0]>>7]++
	}
	if halves[0] == 0 || halves[1] == 0 {
		t.Fatalf("B's entries all fall in one half: %v", halves)
	}
	a.srv.fedState.setBits(b.hubAID, 0) // B serves the whole directory only
	for bit := 0; bit < 2; bit++ {
		prefix := []byte{byte(bit << 7)}
		es, ok := a.srv.peerBucket(context.Background(), b.hubAID, prefix, 1, false)
		if !ok || len(es) != halves[bit] {
			t.Fatalf("bucket %d/1: %d entries (ok %v), want %d", bit, len(es), ok, halves[bit])
		}
		for _, e := range es {
			if !dirbox.InBucket(e.h, prefix, 1) {
				t.Fatalf("bucket %d/1 holds an entry of another bucket", bit)
			}
		}
	}
}

// TestAPeersBucketPageIsInHashOrder (SSR-W19): a page of a peer's bucket
// whose entries are not in hash order is no answer.
func TestAPeersBucketPageIsInHashOrder(t *testing.T) {
	h1, h2 := make([]byte, dirbox.HashLen), make([]byte, dirbox.HashLen)
	h1[0], h2[0] = 1, 2
	page := func(hs ...[]byte) []byte {
		var es []map[string]string
		for _, h := range hs {
			es = append(es, map[string]string{"h": base64.RawURLEncoding.EncodeToString(h), "box": "AAAA"})
		}
		b, _ := json.Marshal(map[string]any{"max_bits": 0, "entries": es})
		return b
	}
	if p, err := decodeFedBucketPage(page(h1, h2), nil, 0); err != nil || len(p.entries) != 2 {
		t.Fatalf("a page in hash order: %v", err)
	}
	if _, err := decodeFedBucketPage(page(h2, h1), nil, 0); err == nil {
		t.Fatal("a page out of hash order was taken")
	}
}

// TestAnEntryIsTakenOnlyWhenItVerifies (SSR-W22): an entry whose A2A card
// does not verify against its KEL, or whose witness notice does not confirm
// the KEL's tip, is not taken; a notice from the agent's witness is, also
// when the witness is this hub itself (an agent that named this hub and is
// registered at a peer).
func TestAnEntryIsTakenOnlyWhenItVerifies(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	notices := map[string][]byte{}
	b.store.SetDirNoticeForTest(func(aid string) []byte { return notices[aid] })
	// witnessed registers at B an agent whose KEL names witness, with the
	// witness's notice of its KEL's tip in its directory entry.
	witnessed := func(witness *fedNode) (*relayAgent, peerEntry) {
		t.Helper()
		ctl, err := identitytest.Agent()
		if err != nil {
			t.Fatal(err)
		}
		if err := identitytest.SwitchWitness(ctl, witness.hubAID, identitytest.InceptTS+1000); err != nil {
			t.Fatal(err)
		}
		kel, err := identity.MarshalKEL(ctl.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := b.store.PutAgent(ctl.AID(), "witnessed", nil, kel); err != nil {
			t.Fatal(err)
		}
		states, err := identity.Replay(ctl.KEL())
		if err != nil {
			t.Fatal(err)
		}
		tip := states[len(states)-1]
		n, err := identity.SignNotice(witness.hubID.Ctrl, identity.NoticeBody{AID: ctl.AID(), Seq: tip.KeyStateSeq,
			Head: tip.LastEventID, ObservedAt: witness.nowMS()})
		if err != nil {
			t.Fatal(err)
		}
		notices[ctl.AID()] = n
		ag := &relayAgent{c: ctl, aid: ctl.AID()}
		b.publish(ag, 1)
		h, _ := dirbox.Hash(ag.aid)
		entries, _, err := b.store.DirBucket(h, dirbox.HashBits, nil)
		if err != nil || len(entries) != 1 {
			t.Fatalf("B's entry: %v %v", entries, err)
		}
		return ag, peerEntry{h: mustB64(t, entries[0].H), box: mustB64(t, entries[0].Box)}
	}
	// edited is pe with its entry changed by edit, sealed again.
	edited := func(ag *relayAgent, pe peerEntry, edit func(*dirbox.DirEntry)) peerEntry {
		t.Helper()
		e, err := dirbox.Open(ag.aid, pe.h, pe.box)
		if err != nil {
			t.Fatal(err)
		}
		edit(e)
		box, err := dirbox.Seal(ag.aid, e, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return peerEntry{h: pe.h, box: box}
	}
	ag, pe := witnessed(b)
	if e, err := dirbox.Open(ag.aid, pe.h, pe.box); err != nil || len(e.Notice) == 0 {
		t.Fatalf("B's entry carries no notice: %v", err)
	}
	if _, ok := a.srv.verifyEntry(ag.aid, b.hubAID, pe, a.clock()); !ok {
		t.Fatal("an entry with its witness's notice was not taken")
	}
	for name, edit := range map[string]func(*dirbox.DirEntry){
		"a notice that is not one": func(e *dirbox.DirEntry) { e.Notice = []byte("not a notice") },
		"a card that does not verify": func(e *dirbox.DirEntry) {
			e.Card = []byte(`{"name":"not a signed card"}`)
		},
	} {
		if _, ok := a.srv.verifyEntry(ag.aid, b.hubAID, edited(ag, pe, edit), a.clock()); ok {
			t.Errorf("%s: the entry was taken", name)
		}
	}
	own, pe := witnessed(a)
	if _, ok := a.srv.verifyEntry(own.aid, b.hubAID, pe, a.clock()); !ok {
		t.Fatal("an entry with this hub's own notice was not taken")
	}
}

// TestFedBucketPagesMergeWithoutLossOrRepeat (SSR-W19, §2.9 item 6): a
// bucket larger than a page is answered page by page with this hub's own
// entries and its peers' merged in hash order: every entry once, each page
// at most DirPageBytes, also when a page of this hub's own is cut short with
// room left that the peers' small entries past it would fill.
func TestFedBucketPagesMergeWithoutLossOrRepeat(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	want := map[string]bool{}
	box := make([]byte, 150<<10)
	for i := 0; i < 70; i++ {
		h := make([]byte, dirbox.HashLen)
		if _, err := rand.Read(h); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(box); err != nil {
			t.Fatal(err)
		}
		if _, err := a.store.db.Exec(`INSERT INTO agent(aid, kel, registered_at, dir_hash, dir_box) VALUES(?,?,?,?,?)`,
			fmt.Sprintf("synthetic-%d", i), []byte{1}, time.Now().UTC().Format(time.RFC3339), h, box); err != nil {
			t.Fatal(err)
		}
		want[base64.RawURLEncoding.EncodeToString(h)] = true
	}
	var peer [][]byte
	for i := 0; i < 40; i++ {
		h := make([]byte, dirbox.HashLen)
		if _, err := rand.Read(h); err != nil {
			t.Fatal(err)
		}
		peer = append(peer, h)
		want[base64.RawURLEncoding.EncodeToString(h)] = true
	}
	sort.Slice(peer, func(i, j int) bool { return bytes.Compare(peer[i], peer[j]) < 0 })
	var entries []map[string]string
	for _, h := range peer {
		entries = append(entries, map[string]string{"h": base64.RawURLEncoding.EncodeToString(h), "box": "c21hbGwgYm94"})
	}
	b.mu.Lock()
	b.bucket = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(wire3.Header, "3")
		writeJSON(w, http.StatusOK, map[string]any{"max_bits": 0, "entries": entries})
	}
	b.mu.Unlock()
	seen := map[string]int{}
	var last []byte
	cursor := ""
	for pages := 0; ; pages++ {
		if pages == 10 {
			t.Fatal("the bucket did not end in 10 pages")
		}
		body := `{"prefix":"","bits":0`
		if cursor != "" {
			body += `,"cursor":"` + cursor + `"`
		}
		req := httptest.NewRequest(http.MethodPost, "http://hub.test/directory:bucket", strings.NewReader(body+`}`))
		req.Header.Set(wire3.Header, "3")
		req.Header.Set("Content-Type", "application/json")
		rec := a.serve(req, "192.0.2.79")
		if rec.Code != 200 || rec.Body.Len() > DirPageBytes {
			t.Fatalf("page %d: %d, %d bytes", pages, rec.Code, rec.Body.Len())
		}
		var out DirBucketResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Partial {
			t.Fatalf("page %d: %v, partial %v", pages, err, out.Partial)
		}
		for _, e := range out.Entries {
			seen[e.H]++
			h := mustB64(t, e.H)
			if last != nil && bytes.Compare(h, last) < 0 {
				t.Fatalf("page %d goes back in hash order", pages)
			}
			last = h
		}
		if out.Next == "" {
			break
		}
		cursor = out.Next
	}
	for h := range want {
		if seen[h] != 1 {
			t.Errorf("entry %s is on %d pages, want 1", h, seen[h])
		}
	}
	if len(seen) != len(want) {
		t.Errorf("%d entries answered, want %d", len(seen), len(want))
	}
}

// TestAPeersBucketPageKeepsOnlyItsBucket (SSR-W19, §2.9 item 1): of a page
// a peer answers for a bucket, an entry is taken only when its h is a
// directory hash of that bucket and its box no larger than a directory
// carries; a next that is outside the bucket, or before the page's last
// entry, makes the page no answer.
func TestAPeersBucketPageKeepsOnlyItsBucket(t *testing.T) {
	prefix := []byte{0x80} // the bucket 1/1: hashes whose first bit is set
	in := func(b byte) []byte { h := make([]byte, dirbox.HashLen); h[0], h[31] = 0x80, b; return h }
	out := make([]byte, dirbox.HashLen) // first bit clear
	b64 := base64.RawURLEncoding.EncodeToString
	small := b64([]byte("a box"))
	page := func(next []byte, es ...map[string]string) []byte {
		m := map[string]any{"max_bits": 1, "entries": es}
		if next != nil {
			m["next"] = b64(next)
		}
		b, _ := json.Marshal(m)
		return b
	}
	p, err := decodeFedBucketPage(page(in(9),
		map[string]string{"h": b64(in(1)), "box": small},
		map[string]string{"h": b64(out), "box": small},                                   // another bucket
		map[string]string{"h": b64(in(2)[:31]), "box": small},                            // not a hash
		map[string]string{"h": b64(in(3)), "box": b64(make([]byte, dirbox.MaxBoxLen+1))}, // too large
		map[string]string{"h": b64(in(4)), "box": "not base64url!"},
		map[string]string{"h": b64(in(5)), "box": b64(make([]byte, dirbox.MaxBoxLen))},
	), prefix, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.entries) != 2 || !bytes.Equal(p.entries[0].h, in(1)) || !bytes.Equal(p.entries[1].h, in(5)) {
		t.Fatalf("taken %d entries, want the two of the bucket within the size", len(p.entries))
	}
	if !bytes.Equal(p.next, in(9)) {
		t.Fatalf("next %x", p.next)
	}
	for name, next := range map[string][]byte{"outside the bucket": out, "before the last entry": in(0)} {
		if _, err := decodeFedBucketPage(page(next, map[string]string{"h": b64(in(1)), "box": small}), prefix, 1); err == nil {
			t.Errorf("a page whose next is %s was taken", name)
		}
	}
	if _, err := decodeFedBucketPage(page(in(9)), prefix, 1); err == nil {
		t.Error("a page with a next and no entry was taken")
	}
}

// TestAPeersOversizedBucketIsNoAnswer (SSR-W21; PeerBucketMaxBytes): a peer
// whose answer for one bucket runs past PeerBucketMaxBytes over its pages is
// taken as not answering, and no page past the one that crossed the bound is
// asked for. (Asked directly, not through a merged bucket, whose 5-second
// deadline a slow run would hit first.)
func TestAPeersOversizedBucketIsNoAnswer(t *testing.T) {
	net := newFedNet(t, 2)
	a, c := net.nodes[0], net.nodes[1]
	const perPage, pages = 9, 12 // about 2.2 MiB a page, 27 MiB in all
	box := base64.RawURLEncoding.EncodeToString(make([]byte, 190<<10))
	var mu sync.Mutex
	var sizes []int
	c.mu.Lock()
	c.bucket = func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		i := len(sizes) + 1
		mu.Unlock()
		var es []map[string]string
		var last []byte
		for j := 0; j < perPage; j++ {
			h := make([]byte, dirbox.HashLen)
			h[29], h[30] = byte(i), byte(j+1)
			es = append(es, map[string]string{"h": base64.RawURLEncoding.EncodeToString(h), "box": box})
			last = h
		}
		m := map[string]any{"max_bits": 0, "entries": es}
		if i < pages {
			m["next"] = base64.RawURLEncoding.EncodeToString(last)
		}
		raw, _ := json.Marshal(m)
		mu.Lock()
		sizes = append(sizes, len(raw))
		mu.Unlock()
		w.Header().Set(wire3.Header, "3")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}
	c.mu.Unlock()
	got, _, err := a.srv.askPeerBucket(context.Background(), c.hubAID, nil, 0)
	if err == nil {
		t.Fatalf("a peer's answer of %d pages (about 27 MiB) was taken: %d entries", pages, len(got.entries))
	}
	mu.Lock()
	defer mu.Unlock()
	crossing, total := 0, 0
	for i, n := range sizes {
		if total += n; total > PeerBucketMaxBytes {
			crossing = i + 1
			break
		}
	}
	if crossing == 0 || len(sizes) != crossing {
		t.Fatalf("the peer was asked %d pages, want %d (the one that crosses %d bytes): %v", len(sizes), crossing, PeerBucketMaxBytes, err)
	}
}

// TestFedCachesAreBounded (sealed-sender §2.12, §3.1): what the kernel keeps
// in memory of its peers is bounded — the resolved homes and the refused
// credentials by their number, the least recently used leaving first, the
// peers' bucket answers by their bytes, the oldest leaving first.
func TestFedCachesAreBounded(t *testing.T) {
	c := newLRU[string, int](2)
	c.put("a", 1)
	c.put("b", 2)
	if _, ok := c.get("a"); !ok {
		t.Fatal("a is not kept")
	}
	if ev := c.put("c", 3); len(ev) != 1 || ev[0] != 2 {
		t.Fatalf("putting a third evicted %v, want b (the least recently used)", ev)
	}
	if _, ok := c.get("b"); ok || c.len() != 2 {
		t.Fatalf("b kept, or %d entries kept, want 2", c.len())
	}
	f := newFedState()
	if f.homes.max != HomeCacheMax || f.refreshed.max != HomeCacheMax || f.neg.max != NegCacheMax {
		t.Fatalf("bounds: homes %d, refreshed %d, refused %d", f.homes.max, f.refreshed.max, f.neg.max)
	}
	now := time.Unix(1_700_000_000, 0)
	third := BucketCacheBytes/3 + 1
	key := func(p string) bucketKey { return bucketKey{peer: "p", prefix: p, bits: 8} }
	for _, p := range []string{"a", "b", "c", "d"} {
		f.putBucket(&bucketAnswer{key: key(p), size: third, at: now})
		if f.bucketBytes > BucketCacheBytes {
			t.Fatalf("after %s the answers kept hold %d bytes, more than %d", p, f.bucketBytes, BucketCacheBytes)
		}
	}
	for p, want := range map[string]bool{"a": false, "b": false, "c": true, "d": true} {
		if _, ok := f.bucket(key(p), now); ok != want {
			t.Errorf("answer %s kept %v, want %v", p, ok, want)
		}
	}
	f.putBucket(&bucketAnswer{key: key("d"), size: 10, at: now})
	if f.bucketBytes != third+10 {
		t.Fatalf("a replaced answer: %d bytes counted, want %d", f.bucketBytes, third+10)
	}
}

// TestAFreshlyJoinedAgentIsFoundPastAnEmptyCachedBucket (XHUB): a peer hub's
// bucket kept from before an agent registered there must not hide it. The
// lookup that finds nothing in the kept answer asks the peer again, and a
// directory query that carries Cache-Control: no-cache is answered past the
// kept answer too.
func TestAFreshlyJoinedAgentIsFoundPastAnEmptyCachedBucket(t *testing.T) {
	old := BucketFreshMinAge
	BucketFreshMinAge = 0
	defer func() { BucketFreshMinAge = old }()
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	ctx := context.Background()
	joined := b.agent()
	// Empty out B's directory view for the bucket: delete the entry, let A
	// cache the bucket without it, then register it again.
	kel, _ := b.store.AgentKEL(joined.aid)
	keyset, _, _, _ := b.store.LocalKeys(joined.aid)
	if _, err := b.store.db.Exec(`DELETE FROM agent WHERE aid=?`, joined.aid); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.srv.lookupEntryOnce(ctx, joined.aid, []string{b.hubAID}, false, 0); ok {
		t.Fatal("found an agent that is not registered")
	}
	if err := b.store.PutAgent(joined.aid, "joined", nil, kel); err != nil {
		t.Fatal(err)
	}
	if _, err := b.store.PublishKeys(joined.aid, keyset, 0, joined.c.KEL(), b.clock()); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.srv.lookupEntryOnce(ctx, joined.aid, []string{b.hubAID}, false, 0); ok {
		t.Fatal("the kept empty bucket was not used; the test does not exercise the cache")
	}
	if e, ok := a.srv.lookupEntry(ctx, joined.aid, []string{b.hubAID}, false); !ok || e.home != b.hubAID {
		t.Fatal("an agent that joined its hub after the bucket was kept was not found")
	}
}

func TestWantsFresh(t *testing.T) {
	for v, want := range map[string]bool{"": false, "no-cache": true, "No-Cache": true, "max-age=0, no-cache": true, "no-store": false} {
		r := httptest.NewRequest(http.MethodPost, "http://hub.test/directory:bucket", nil)
		if v != "" {
			r.Header.Set("Cache-Control", v)
		}
		if got := wantsFresh(r); got != want {
			t.Errorf("Cache-Control %q: %v, want %v", v, got, want)
		}
	}
}
