package aghub

// The hub's half of forward secrecy (forward-secrecy §4.2): the kid of every
// queued envelope (FS-H1 to FS-H3, FS-H6, FS-H7), the end of a poll page
// (FS-H5), the Date of every answer (FS-H8) and the relay TTL under the hard
// bound (FS-T1).

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// setClockMS sets the hub's clock to ms (unix milliseconds).
func (h *relayHub) setClockMS(ms uint64) {
	h.mu.Lock()
	h.now = time.UnixMilli(int64(ms))
	h.mu.Unlock()
}

// fixtureKey is the key envelope seals to aid (the one aid published last).
func fixtureKey(t testing.TB, aid string) seal.EncKey {
	t.Helper()
	k, ok := fixtureKIDs.Load(aid)
	if !ok {
		t.Fatalf("%s published no key", aid)
	}
	return k.(seal.EncKey)
}

// kidStaleBody is the one body of 409 kid_stale.
func kidStaleBody(t testing.TB) string {
	t.Helper()
	b, err := wire3.Body(wire3.Refusal{Reason: wire3.ReasonKidStale})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// expectKidStale checks a 409 kid_stale in its one body, and that the send
// took no token and wrote nothing.
func expectKidStale(t *testing.T, h *relayHub, before effects, rec *httptest.ResponseRecorder) {
	t.Helper()
	expectRefusal(t, rec, http.StatusConflict, "kid_stale")
	if rec.Body.String() != kidStaleBody(t) {
		t.Errorf("the kid_stale body is %s, want the code's one body", rec.Body)
	}
	if d := before.diff(h.effects()); d != "" {
		t.Errorf("a kid_stale refusal took or wrote something: %s", d)
	}
}

// replacementSet is a key set for a that keeps its mailbox key and carries
// one new encryption key, valid at at, and the seq above the stored one.
func replacementSet(t testing.TB, h *relayHub, a *relayAgent, at time.Time) (raw []byte, key seal.EncKey, seq uint64) {
	t.Helper()
	var stored uint64
	if err := h.store.db.QueryRow(`SELECT seq FROM agent_keys WHERE aid=?`, a.aid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	now := uint64(at.UnixMilli())
	kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
	if err != nil {
		t.Fatal(err)
	}
	set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: a.aid, Seq: stored + 1,
		Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: a.mbox}
	signed, err := seal.SignEncKeySet(set, a.c.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err = signed.Marshal(); err != nil {
		t.Fatal(err)
	}
	return raw, kp.Public, stored + 1
}

// TestRelayRejectsKidNotInSet (FS-H1, FS-H2, mutation 1): an envelope sealed
// to a key its recipient does not publish is refused 409 kid_stale, as a
// first contact and under either class of credential, before anything is
// taken or written: the tokens of step 8 are given back. So is any envelope
// to a recipient with no key set at all, and one sealed to a key the
// recipient published and has since replaced. The key it publishes is
// taken.
func TestRelayRejectsKidNotInSet(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	unknown := make([]byte, seal.KIDLen)
	if _, err := rand.Read(unknown); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		send func() *httptest.ResponseRecorder
	}{
		{"a first contact", func() *httptest.ResponseRecorder {
			return h.send0(sc.ss, envelopeTo(t, sc.recip.aid, unknown, []byte("k0")), kind0Opts{})
		}},
		{"under a contact credential", func() *httptest.ResponseRecorder {
			return sc.send1(envelopeTo(t, sc.recip.aid, unknown, []byte("k1")), sc.contact)
		}},
		{"under a stranger's credential", func() *httptest.ResponseRecorder {
			return sc.send1(envelopeTo(t, sc.recip.aid, unknown, []byte("k2")), sc.stranger)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := h.effects()
			expectKidStale(t, h, before, c.send())
		})
	}
	// The key the recipient publishes goes through, on every path.
	decodeSent(t, sc.send0(nil))
	decodeSent(t, sc.send1(sc.env(), sc.contact))
	decodeSent(t, sc.send1(sc.env(), sc.stranger))

	t.Run("a recipient with no key set", func(t *testing.T) {
		bare := h.bareAgent()
		before := h.effects()
		expectKidStale(t, h, before, h.send0(sc.ss, envelopeTo(t, bare.aid, fixtureKID(sc.recip.aid), []byte("bare")), kind0Opts{}))
	})
	t.Run("a key the recipient replaced", func(t *testing.T) {
		old := fixtureKey(t, sc.recip.aid)
		raw, _, seq := replacementSet(t, h, sc.recip, h.clock())
		if _, err := h.store.PublishKeys(sc.recip.aid, raw, seq-1, sc.recip.c.KEL(), h.clock()); err != nil {
			t.Fatal(err)
		}
		before := h.effects()
		expectKidStale(t, h, before, sc.send1(envelopeTo(t, sc.recip.aid, old.KID, []byte("old")), sc.contact))
	})
}

// TestRelayRejectsAfterDeadline (FS-H1, mutation 2): an envelope sealed to a
// published key is accepted up to D after the key's not_after, by the hub's
// clock when it is queued: at not_after + D it is queued, a millisecond later
// it is 409 kid_stale.
func TestRelayRejectsAfterDeadline(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	deadline := fixtureKey(t, sc.recip.aid).NotAfter + seal.DeliveryDeadlineMS
	if DeliveryDeadline != time.Hour || seal.DeliveryDeadlineMS != 3_600_000 {
		t.Fatalf("D is %s; forward-secrecy §0 fixes it at one hour", DeliveryDeadline)
	}
	h.setClockMS(deadline)
	decodeSent(t, sc.send1(sc.env(), sc.contact))
	h.setClockMS(deadline + 1)
	before := h.effects()
	expectKidStale(t, h, before, sc.send1(sc.env(), sc.contact))
}

// The deadline compares without overflow at the ends of the range.
func TestWithinDeadlineAtTheEnds(t *testing.T) {
	const d = uint64(seal.DeliveryDeadlineMS)
	for _, c := range []struct {
		notAfter uint64
		at       int64
		want     bool
	}{
		{1000, 1000, true}, {1000, int64(1000 + d), true}, {1000, int64(1000 + d + 1), false},
		{0, int64(d), true}, {0, int64(d + 1), false},
		{math.MaxUint64, math.MaxInt64, true}, {math.MaxUint64 - 1, 0, true},
		{0, math.MaxInt64, false}, {1000, -1, true},
	} {
		if got := withinDeadline(c.notAfter, c.at); got != c.want {
			t.Errorf("not_after %d, accepted at %d: %v, want %v", c.notAfter, c.at, got, c.want)
		}
	}
}

// TestKidCheckInsideEnqueueTx (FS-H1, mutation 3): the key set and the
// time a send is checked against are read in the transaction that writes
// its row, under the store's lock that a key set publication takes too. A
// set replaced, or the deadline passing, while a send waits for the store
// counts: the send is refused, as it would be a moment later. A send that
// read either before taking the lock would queue an envelope that its
// recipient may already have deleted the key of.
func TestKidCheckInsideEnqueueTx(t *testing.T) {
	waiting := func(t *testing.T, h *relayHub, f func()) {
		t.Helper()
		enqueueLocked = func(s *Store) {
			if s == h.store {
				enqueueLocked = nil
				f()
			}
		}
		t.Cleanup(func() { enqueueLocked = nil })
	}
	t.Run("a key set published while the send waits", func(t *testing.T) {
		sc := newScene(t)
		h := sc.h
		env := sc.env()
		raw, _, seq := replacementSet(t, h, sc.recip, h.clock())
		waiting(t, h, func() {
			// What PublishKeys writes, written here because the send holds
			// the lock PublishKeys would wait for.
			if _, err := h.store.db.Exec(`UPDATE agent_keys SET seq=?, keyset=? WHERE aid=?`, seq, raw, sc.recip.aid); err != nil {
				t.Error(err)
			}
		})
		before := h.effects()
		rec := sc.send1(env, sc.contact)
		if enqueueLocked != nil {
			t.Fatal("the send did not reach the store")
		}
		expectRefusal(t, rec, http.StatusConflict, "kid_stale")
		after := h.effects()
		if strings.Contains(before.diff(after), "bucket") {
			t.Errorf("tokens were taken: %s", before.diff(after))
		}
		if n, _ := h.store.RelayPending(sc.recip.aid); n != 0 {
			t.Errorf("%d rows queued", n)
		}
	})
	t.Run("the deadline passing while the send waits", func(t *testing.T) {
		sc := newScene(t)
		h := sc.h
		deadline := fixtureKey(t, sc.recip.aid).NotAfter + seal.DeliveryDeadlineMS
		h.setClockMS(deadline)
		env := sc.env()
		waiting(t, h, func() { h.setClockMS(deadline + 1) })
		before := h.effects()
		rec := sc.send1(env, sc.contact)
		if enqueueLocked != nil {
			t.Fatal("the send did not reach the store")
		}
		expectKidStale(t, h, before, rec)
	})
	t.Run("without either, the same send is queued", func(t *testing.T) {
		sc := newScene(t)
		waiting(t, sc.h, func() {})
		decodeSent(t, sc.send1(sc.env(), sc.contact))
	})
}

// TestKidCheckOrder (core G23, SS §4.2.1 step 10): in the transaction that
// writes the row, the kid is checked after the duplicate re-check and before
// the mailbox capacity. An envelope already waiting is the same envelope
// whatever happened to its key since it was queued: a sender retrying after
// a lost answer is told it is queued (duplicate, the same rid), not to seal
// it again. And an envelope no key opens is refused as that (409 kid_stale,
// fetch the keys and seal again), not as a full mailbox to wait for.
func TestKidCheckOrder(t *testing.T) {
	t.Run("the duplicate re-check comes first", func(t *testing.T) {
		sc := newScene(t)
		h := sc.h
		env := sc.env()
		d, _ := seal.EnvDigest(env)
		item := RelayItem{To: sc.recip.aid, Envelope: env, Digest: d, Class: seal.CapClassStranger,
			KID: fixtureKID(sc.recip.aid)}
		first, err := h.store.RelayEnqueue(item)
		if err != nil {
			t.Fatal(err)
		}
		raw, _, seq := replacementSet(t, h, sc.recip, h.clock())
		if _, err := h.store.PublishKeys(sc.recip.aid, raw, seq-1, sc.recip.c.KEL(), h.clock()); err != nil {
			t.Fatal(err)
		}
		again, err := h.store.RelayEnqueue(item)
		if err != nil || !again.Duplicate || !bytes.Equal(again.RID, first.RID) {
			t.Fatalf("the waiting envelope again after its key was replaced: %+v, %v; want a duplicate with rid %x",
				again, err, first.RID)
		}
	})
	t.Run("the kid comes before the capacity", func(t *testing.T) {
		sc := newScene(t)
		h := sc.h
		l := DefaultLimits()
		l.MailboxMessages = 1
		if err := h.srv.SetLimits(l); err != nil {
			t.Fatal(err)
		}
		decodeSent(t, sc.send1(sc.env(), sc.contact))
		if rec := sc.send1(sc.env(), sc.contact); rec.Code != http.StatusInsufficientStorage {
			t.Fatalf("the mailbox is not full: %d %s", rec.Code, rec.Body)
		}
		before := h.effects()
		stale := bytes.Repeat([]byte{0x6b}, seal.KIDLen)
		expectKidStale(t, h, before, sc.send1(envelopeTo(t, sc.recip.aid, stale, []byte("full")), sc.contact))
	})
}

// Publications and sends at once (under -race): a send that starts after a
// publication that replaced its key returned is refused, every queued row is
// one the old key was still published for, and no send fails otherwise.
func TestKidCheckUnderConcurrentPublication(t *testing.T) {
	h := newRelayHub(t)
	recip := h.agent()
	old := fixtureKey(t, recip.aid)
	raw, _, seq := replacementSet(t, h, recip, h.clock())
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := 0; j < 20; j++ {
				env := envelopeTo(t, recip.aid, old.KID, []byte("c "+strconv.Itoa(i)+" "+strconv.Itoa(j)))
				d, _ := seal.EnvDigest(env)
				_, err := h.store.RelayEnqueue(RelayItem{To: recip.aid, Envelope: env, Digest: d,
					Class: seal.CapClassStranger, KID: old.KID})
				if err != nil && !strings.Contains(err.Error(), ErrKidStale.Error()) {
					errs <- err
				}
			}
		}(i)
	}
	close(start)
	if _, err := h.store.PublishKeys(recip.aid, raw, seq-1, recip.c.KEL(), h.clock()); err != nil {
		t.Fatal(err)
	}
	env := envelopeTo(t, recip.aid, old.KID, []byte("after"))
	d, _ := seal.EnvDigest(env)
	if _, err := h.store.RelayEnqueue(RelayItem{To: recip.aid, Envelope: env, Digest: d,
		Class: seal.CapClassStranger, KID: old.KID}); err == nil || !strings.Contains(err.Error(), ErrKidStale.Error()) {
		t.Errorf("a send after the publication returned: %v, want kid_stale", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestPreviewSubjectToKidCheck (FS-H7): one-time envelopes (preview frames
// and the two card kinds carry outer key 8 and are never retried) are held
// to the same rule: sealed to a key the recipient does not publish, 409.
func TestPreviewSubjectToKidCheck(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	exp := h.nowMS() + 30_000
	oneTime := func(kid []byte, ct string) []byte {
		env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: sc.recip.aid, Suite: seal.SuiteX25519,
			KID: kid, Enc: bytes.Repeat([]byte{9}, 32), CT: []byte(ct),
			Access: &seal.Access{Kind: seal.AccessKindSession}, Exp: &exp}
		b, err := env.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	stale := bytes.Repeat([]byte{0xa5}, seal.KIDLen)
	before := h.effects()
	expectKidStale(t, h, before, sc.send1(oneTime(stale, "a preview frame"), sc.contact))
	decodeSent(t, sc.send1(oneTime(fixtureKID(sc.recip.aid), "a preview frame"), sc.contact))
}

// TestRandomKidsAreAllRefused (red team A3, in the unit layer): a sender
// that sends a hundred envelopes a second under a good credential, each
// sealed to a random kid, gets a hundred 409s; the recipient's mailbox and
// every bucket are as they were.
func TestRandomKidsAreAllRefused(t *testing.T) {
	sc := newScene(t)
	h := sc.h
	before := h.effects()
	for i := 0; i < 100; i++ {
		kid := make([]byte, seal.KIDLen)
		if _, err := rand.Read(kid); err != nil {
			t.Fatal(err)
		}
		rec := sc.send1(envelopeTo(t, sc.recip.aid, kid, []byte("a3 "+strconv.Itoa(i))), sc.contact)
		if rec.Code != http.StatusConflict || reasonOf(rec) != "kid_stale" {
			t.Fatalf("envelope %d: %d %s, want 409 kid_stale", i, rec.Code, rec.Body)
		}
		h.advance(10 * time.Millisecond)
	}
	if d := before.diff(h.effects()); d != "" {
		t.Errorf("a hundred refused envelopes took or wrote something: %s", d)
	}
	if n, _ := h.store.RelayPending(sc.recip.aid); n != 0 {
		t.Errorf("the mailbox holds %d rows", n)
	}
}

// TestRelaySchemaHasNoKid (FS-H6, core §2.16): the relay tables hold no key
// id and nothing derived from one, and no index is by key id: the hub reads
// the kid of an envelope when it queues it and keeps nothing of it.
func TestRelaySchemaHasNoKid(t *testing.T) {
	h := newRelayHub(t)
	rows, err := h.store.db.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
	                               WHERE tbl_name IN ('relay_message', 'relay_redelivery', 'relay_dack')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var typ, name, stmt string
		if err := rows.Scan(&typ, &name, &stmt); err != nil {
			t.Fatal(err)
		}
		seen++
		if strings.Contains(strings.ToLower(name+" "+stmt), "kid") {
			t.Errorf("%s %s names a key id: %s", typ, name, stmt)
		}
	}
	if seen == 0 {
		t.Fatal("no relay tables found")
	}
	cols, err := tableColumns(h.store.db, "relay_message")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cap_id", "class", "created_at", "env_digest", "exp", "id", "payload", "rid", "size", "to_aid"}
	if len(cols) != len(want) {
		t.Errorf("relay_message has the columns %v, want exactly %v", cols, want)
	}
	for _, c := range want {
		if !cols[c] {
			t.Errorf("relay_message lacks %s", c)
		}
	}
}

// pollPage is a decoded /relay/poll answer.
type pollPage struct {
	Messages []struct {
		ID         int64  `json:"id"`
		Envelope   string `json:"envelope"`
		AcceptedAt uint64 `json:"accepted_at"`
	} `json:"messages"`
	More bool `json:"more"`
}

// poll is a signed /relay/poll by a.
func (h *relayHub) poll(a *relayAgent, req map[string]any) pollPage {
	h.t.Helper()
	body, _ := json.Marshal(req)
	rec := h.serve(h.signed(a.c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", body), relayClientIP)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("poll: %d %s", rec.Code, rec.Body)
	}
	var p pollPage
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// queueTo queues n envelopes of size bytes of ciphertext for a, the
// first with outer exp exp when it is not nil, and returns their ids.
func (h *relayHub) queueTo(a *relayAgent, n, size int, exp *uint64, tag string) []int64 {
	h.t.Helper()
	var ids []int64
	for i := 0; i < n; i++ {
		ct := bytes.Repeat([]byte{'x'}, size)
		copy(ct, tag+strconv.Itoa(i)+" ")
		env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: a.aid, Suite: seal.SuiteX25519,
			KID: fixtureKID(a.aid), Enc: bytes.Repeat([]byte{9}, 32), CT: ct,
			Access: &seal.Access{Kind: seal.AccessKindSession}, Exp: exp}
		raw, err := env.Marshal()
		if err != nil {
			h.t.Fatal(err)
		}
		q, err := h.store.QueueEnvelope(a.aid, raw)
		if err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, q.ID)
	}
	return ids
}

// TestPollMore (FS-H5): more says whether returnable envelopes remain past
// the page, in the snapshot the page was read from: true when the page was
// cut by the limit or by the byte budget, false for an empty page and when
// all that remains has expired (exp <= now is never returned, CUX-H2). The
// envelope itself is base64url (core G2) and accepted_at is when this hub
// queued it.
func TestPollMore(t *testing.T) {
	h := newRelayHub(t)
	recip := h.agent()

	t.Run("an empty mailbox", func(t *testing.T) {
		if p := h.poll(recip, map[string]any{}); len(p.Messages) != 0 || p.More {
			t.Fatalf("%+v, want no messages and more false", p)
		}
	})
	ids := h.queueTo(recip, 3, 16, nil, "count")
	t.Run("a page cut by the limit", func(t *testing.T) {
		p := h.poll(recip, map[string]any{"limit": 2})
		if len(p.Messages) != 2 || !p.More {
			t.Fatalf("%d messages, more %v; want 2 and more", len(p.Messages), p.More)
		}
		p = h.poll(recip, map[string]any{"limit": 2, "after_id": p.Messages[1].ID})
		if len(p.Messages) != 1 || p.More || p.Messages[0].ID != ids[2] {
			t.Fatalf("the rest: %+v, want the third and more false", p)
		}
	})
	t.Run("a page of exactly the limit", func(t *testing.T) {
		if p := h.poll(recip, map[string]any{"limit": 3}); len(p.Messages) != 3 || p.More {
			t.Fatalf("%d messages, more %v; want 3 and no more", len(p.Messages), p.More)
		}
	})
	t.Run("the envelope and accepted_at", func(t *testing.T) {
		p := h.poll(recip, map[string]any{"limit": 1})
		raw, err := wire3.DecodeB64URL("envelope", p.Messages[0].Envelope)
		if err != nil {
			t.Fatalf("the envelope is not base64url: %v", err)
		}
		var stored []byte
		var created int64
		if err := h.store.db.QueryRow(`SELECT payload, created_at FROM relay_message WHERE id=?`, ids[0]).Scan(&stored, &created); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, stored) || p.Messages[0].AcceptedAt != uint64(created) || created != h.clock().UnixMilli() {
			t.Fatalf("accepted_at %d (queued at %d, clock %d), envelope as queued %v",
				p.Messages[0].AcceptedAt, created, h.clock().UnixMilli(), bytes.Equal(raw, stored))
		}
	})
	t.Run("the envelope in the URL-safe alphabet", func(t *testing.T) {
		// Ciphertext bytes whose standard spelling has "+" and "/", so the
		// two alphabets cannot spell the envelope alike (core G2).
		env, err := (&seal.SealedEnvelope{V: seal.EnvelopeVersion, To: recip.aid, Suite: seal.SuiteX25519,
			KID: fixtureKID(recip.aid), Enc: bytes.Repeat([]byte{9}, 32), CT: bytes.Repeat([]byte{0xfb, 0xff, 0xbf}, 8),
			Access: &seal.Access{Kind: seal.AccessKindSession}}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		q, err := h.store.QueueEnvelope(recip.aid, env)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, q.ID)
		p := h.poll(recip, map[string]any{"after_id": ids[2]})
		want := base64.RawURLEncoding.EncodeToString(env)
		if want == base64.StdEncoding.EncodeToString(env) || !strings.ContainsAny(base64.StdEncoding.EncodeToString(env), "+/") {
			t.Fatal("the test envelope does not tell the alphabets apart")
		}
		if len(p.Messages) != 1 || p.Messages[0].Envelope != want {
			t.Fatalf("%+v, want the envelope spelled %s", p.Messages, want)
		}
	})
	if _, err := h.store.RelayAck(recip.aid, ids); err != nil {
		t.Fatal(err)
	}

	t.Run("a page cut by the byte budget", func(t *testing.T) {
		big := h.queueTo(recip, 3, 1000, nil, "budget")
		msgs, more, err := h.store.RelayPoll(recip.aid, 0, 100, 2500)
		if err != nil {
			t.Fatal(err)
		}
		if len(msgs) != 2 || !more {
			t.Fatalf("%d messages, more %v; want 2 within the budget and more", len(msgs), more)
		}
		// The first envelope always comes, even past the budget.
		msgs, more, _ = h.store.RelayPoll(recip.aid, 0, 100, 10)
		if len(msgs) != 1 || !more {
			t.Fatalf("a budget below one envelope: %d messages, more %v; want 1 and more", len(msgs), more)
		}
		if _, err := h.store.RelayAck(recip.aid, big); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("only expired envelopes left", func(t *testing.T) {
		live := h.queueTo(recip, 1, 16, nil, "live")
		soon := h.nowMS() + 60_000
		h.queueTo(recip, 2, 16, &soon, "soon")
		if p := h.poll(recip, map[string]any{"limit": 1}); len(p.Messages) != 1 || !p.More {
			t.Fatalf("before they expire: %+v, want 1 and more", p)
		}
		h.advance(time.Minute)
		p := h.poll(recip, map[string]any{"limit": 1})
		if len(p.Messages) != 1 || p.Messages[0].ID != live[0] || p.More {
			t.Fatalf("at their exp: %+v, want the live one and more false", p)
		}
		if p := h.poll(recip, map[string]any{"after_id": live[0]}); len(p.Messages) != 0 || p.More {
			t.Fatalf("past the live one: %+v, want nothing and more false", p)
		}
	})
	t.Run("a limit above what one ack clears", func(t *testing.T) {
		// MaxPollLimit + 1 small rows, written in one transaction (queueing
		// them one by one is slow and not what is under test).
		tx, err := h.store.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= MaxPollLimit; i++ {
			rid, digest := make([]byte, RIDLen), make([]byte, 32)
			_, _ = rand.Read(rid)
			_, _ = rand.Read(digest)
			if _, err := tx.Exec(`INSERT INTO relay_message(rid, to_aid, env_digest, class, size, created_at, payload)
			                      VALUES(?,?,?,?,?,?,?)`, rid, recip.aid, digest, seal.CapClassStranger, 1, h.nowMS(), []byte{1}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		msgs, more, err := h.store.RelayPoll(recip.aid, 0, MaxPollLimit*10, 1<<40)
		if err != nil || len(msgs) != MaxPollLimit || !more {
			t.Fatalf("%d messages, more %v, %v; want %d and more", len(msgs), more, err, MaxPollLimit)
		}
		p := h.poll(recip, map[string]any{"limit": MaxPollLimit + 1})
		if len(p.Messages) != MaxPollLimit || !p.More {
			t.Fatalf("over the wire: %d messages, more %v; want %d and more", len(p.Messages), p.More, MaxPollLimit)
		}
	})
}

// TestPollDoesNotWaitForWriters (FS-H5): the snapshot a poll page and its
// more are read from is a read transaction, not a write one. The store
// begins its transactions IMMEDIATE (aghub.go Open), so a poll that began an
// ordinary one would take the database's write lock for as long as it reads
// a page of up to PollBudget bytes, and every send, ack and registration of
// the hub would wait behind each poll. Here a writer holds the write lock:
// the poll still answers at once, from the last committed state.
func TestPollDoesNotWaitForWriters(t *testing.T) {
	h := newRelayHub(t)
	recip := h.agent()
	ids := h.queueTo(recip, 2, 16, nil, "w")
	writer, err := h.store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = writer.Rollback()
		}
	}
	defer release()
	// A row the writer adds and has not committed is not in the snapshot.
	if _, err := writer.Exec(`DELETE FROM relay_message WHERE id=?`, ids[0]); err != nil {
		t.Fatal(err)
	}
	type page struct {
		n    int
		more bool
		err  error
	}
	done := make(chan page, 1)
	go func() {
		msgs, more, err := h.store.RelayPoll(recip.aid, 0, 1, 1<<20)
		done <- page{len(msgs), more, err}
	}()
	select {
	case p := <-done:
		if p.err != nil || p.n != 1 || !p.more {
			t.Fatalf("a poll while a writer holds the lock: %d messages, more %v, %v; want 1 and more", p.n, p.more, p.err)
		}
	case <-time.After(3 * time.Second):
		release()
		<-done
		t.Fatal("a poll waited for a writer: it took the database's write lock")
	}
}

// TestHubResponsesCarryDate (FS-H8): every answer of the hub, refusals
// included, carries an HTTP Date the daemon checks its clock against
// (FS-K14).
func TestHubResponsesCarryDate(t *testing.T) {
	sc := newScene(t)
	srv := httptest.NewServer(sc.h.h)
	defer srv.Close()
	stale := envelopeTo(t, sc.recip.aid, bytes.Repeat([]byte{0x3c}, seal.KIDLen), []byte("date"))
	for _, c := range []struct {
		name string
		req  func() *http.Request
		code int
	}{
		{"the index", func() *http.Request { r, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil); return r }, 200},
		{"a wire-3 refusal", func() *http.Request {
			r, _ := http.NewRequest(http.MethodPost, srv.URL+"/no/such/route", nil)
			r.Header.Set(wire3.Header, "3")
			return r
		}, 404},
		{"a refusal before the handler", func() *http.Request {
			r, _ := http.NewRequest(http.MethodPost, srv.URL+"/relay/poll", nil)
			return r
		}, 426},
		{"409 kid_stale", func() *http.Request {
			r := kind1Request(t, withCap(t, stale, sc.contact))
			out, _ := http.NewRequest(r.Method, srv.URL+r.URL.Path, r.Body)
			out.Header = r.Header
			return out
		}, 409},
		{"a key set lookup", func() *http.Request {
			r, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents/"+sc.recip.aid+"/keys", nil)
			return r
		}, 200},
	} {
		resp, err := http.DefaultClient.Do(c.req())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.code {
			t.Errorf("%s: %d, want %d", c.name, resp.StatusCode, c.code)
		}
		d, err := http.ParseTime(resp.Header.Get("Date"))
		if err != nil {
			t.Errorf("%s: no Date (%q): %v", c.name, resp.Header.Get("Date"), err)
		} else if time.Since(d).Abs() > time.Minute {
			t.Errorf("%s: Date %s", c.name, d)
		}
	}
}

// TestRelayTTLBelowHardBound (FS-T1 1, mutation 39): an envelope accepted at
// the last moment its key allows (not_after + D) and kept the whole relay
// TTL is still read before its recipient's clock, up to ClockSkewMS ahead,
// reaches the key's hard deletion at not_after + L. The bound holds for the
// default TTL and for any an operator may set: a longer one is refused at
// start.
func TestRelayTTLBelowHardBound(t *testing.T) {
	L := time.Duration(seal.MaxMessageLifetimeMS) * time.Millisecond
	D := time.Duration(seal.DeliveryDeadlineMS) * time.Millisecond
	skew := time.Duration(seal.ClockSkewMS) * time.Millisecond
	ttl := DefaultLimits().UndeliveredTTL
	if L < D+ttl+skew {
		t.Fatalf("L = %s < D + TTL + skew = %s + %s + %s", L, D, ttl, skew)
	}
	if ttl != 14*24*time.Hour || L != 15*24*time.Hour {
		t.Fatalf("TTL %s and L %s: forward-secrecy §0 fixes them at 14 and 15 days", ttl, L)
	}
	if MaxUndeliveredTTL != L-D-skew {
		t.Fatalf("MaxUndeliveredTTL = %s, want L - D - skew = %s", MaxUndeliveredTTL, L-D-skew)
	}
	l := DefaultLimits()
	l.UndeliveredTTL = MaxUndeliveredTTL
	if err := l.Validate(); err != nil {
		t.Errorf("the longest TTL the bound allows: %v", err)
	}
	l.UndeliveredTTL = MaxUndeliveredTTL + time.Millisecond
	if err := l.Validate(); err == nil || !strings.Contains(err.Error(), "-relay-ttl") {
		t.Errorf("a TTL past the bound: %v, want a refusal naming -relay-ttl", err)
	}
}

// The kid check's cache answers for the very bytes stored: another set under
// the same seq is decoded afresh, and bytes that are not a set are an error.
func TestKidCacheFollowsTheStoredSet(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	first := fixtureKey(t, a.aid)
	var seq uint64
	var raw []byte
	if err := h.store.db.QueryRow(`SELECT seq, keyset FROM agent_keys WHERE aid=?`, a.aid).Scan(&seq, &raw); err != nil {
		t.Fatal(err)
	}
	keys, err := h.store.kids.keysOf(a.aid, seq, raw)
	if err != nil || len(keys) != 1 || keys[[seal.KIDLen]byte(first.KID)] != first.NotAfter {
		t.Fatalf("%v %v", keys, err)
	}
	// The same seq stored again with other bytes (an agent deregistered
	// and registered again) is decoded afresh.
	raw2, second, _ := replacementSet(t, h, a, h.clock())
	keys, err = h.store.kids.keysOf(a.aid, seq, raw2)
	if err != nil || len(keys) != 1 || keys[[seal.KIDLen]byte(second.KID)] != second.NotAfter {
		t.Fatalf("other bytes under the same seq: %v %v", keys, err)
	}
	if _, err := h.store.kids.keysOf(a.aid, seq, []byte("not a key set")); err == nil {
		t.Fatal("bytes that are not a key set decoded")
	}
	var q rowQuerier = h.store.db
	if err := h.store.kidAcceptable(q, "bafy-nobody", first.KID, 0); err == nil || err == sql.ErrNoRows {
		t.Fatalf("an AID with no set: %v", err)
	}
}

// TestFedForwardPassesKidStale (FS-H3, red team A4): the recipient's home
// checks the kid where it queues a forwarded envelope, and the origin hub
// answers the sender with the home's 409 kid_stale, status and body as they
// are, never as 502. The origin cannot check the kid itself: the key set is
// the home's. After a recipient replaced its keys (as an emergency rotation
// does), a sender at a peer hub that seals to the key it cached is refused
// at both hubs, as a first contact and under a credential; the current key
// goes through.
func TestFedForwardPassesKidStale(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	old := fixtureKey(t, owner.aid)
	raw, _, seq := replacementSet(t, b.relayHub, owner, b.clock())
	if _, err := b.store.PublishKeys(owner.aid, raw, seq-1, owner.c.KEL(), b.clock()); err != nil {
		t.Fatal(err)
	}
	sender := a.agent()
	ss := a.openSession(sender.c)
	check := func(name string, rec *httptest.ResponseRecorder, forwards int) {
		t.Helper()
		expectRefusal(t, rec, http.StatusConflict, "kid_stale")
		if rec.Body.String() != kidStaleBody(t) {
			t.Errorf("%s: the sender got %s, not the home's body", name, rec.Body)
		}
		if b.forwards() != forwards {
			t.Errorf("%s: %d forwards at the home, want %d", name, b.forwards(), forwards)
		}
		if n := b.queued(owner.aid) + a.queued(owner.aid); n != 0 {
			t.Errorf("%s: %d rows queued", name, n)
		}
	}
	check("a first contact", a.send0(ss, envelopeTo(t, owner.aid, old.KID, []byte("fed k0")), kind0Opts{home: b.hubAID}), 1)
	g := b.issue(owner, seal.CapClassContact, time.Hour)
	env := withCap(t, envelopeTo(t, owner.aid, old.KID, []byte("fed k1")), g)
	check("under a credential", a.send1Hint(env, b.hubAID, ""), 2)

	// What the home answered: the same status and bytes.
	home := b.fedServe(b.signedForward(a, env, nil))
	if home.Code != http.StatusConflict || home.Body.String() != kidStaleBody(t) {
		t.Errorf("the home answered %d %s", home.Code, home.Body)
	}

	sealToKeysAt(t, b.store, owner.aid)
	out := decodeSent(t, a.send0(ss, envelope(t, owner.aid, []byte("fed ok")), kind0Opts{home: b.hubAID}))
	if out.Status != RelayQueued || b.queued(owner.aid) != 1 {
		t.Fatalf("the current key: %+v, %d queued at the home", out, b.queued(owner.aid))
	}
}
