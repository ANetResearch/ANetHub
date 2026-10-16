package aghub

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/seal"
)

// expEnv is an envelope for to with outer exp at the given millisecond.
func expEnv(t testing.TB, to string, exp uint64) []byte {
	t.Helper()
	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: fixtureKID(to), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte("exp"),
		Access: &seal.Access{Kind: seal.AccessKindSession}, Exp: &exp}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRelaySendExpiredBeforeAuth(t *testing.T) {
	day := uint64(24 * time.Hour / time.Millisecond)
	for _, c := range []struct {
		name   string
		reason string
		exp    func(now uint64) uint64
	}{
		{"exp equal to now", "expired", func(n uint64) uint64 { return n }},
		{"exp in the past", "expired", func(n uint64) uint64 { return n - 1000 }},
		{"exp beyond 15 days", "bad_exp", func(n uint64) uint64 { return n + 15*day + 1 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc := newScene(t)
			exp := c.exp(sc.h.nowMS())
			before := sc.h.effects()
			rec := sc.send1(expEnv(t, sc.recip.aid, exp), sc.contact)
			if rec.Code != 400 || reasonOf(rec) != c.reason {
				t.Fatalf("known recipient: %d %s", rec.Code, rec.Body)
			}
			if d := before.diff(sc.h.effects()); d != "" {
				t.Errorf("took or wrote something: %s", d)
			}
			// A recipient nobody knows is answered with the same bytes.
			ghost := "aid:ghost"
			rec2 := sc.h.send0(sc.ss, expEnv(t, ghost, exp), kind0Opts{})
			if rec2.Code != rec.Code || rec2.Body.String() != rec.Body.String() {
				t.Errorf("unknown recipient answered differently: %d %s", rec2.Code, rec2.Body)
			}
		})
	}
}

func TestBadExpOver15Days(t *testing.T) {
	sc := newScene(t)
	day := uint64(24 * time.Hour / time.Millisecond)
	ok := sc.send1(expEnv(t, sc.recip.aid, sc.h.nowMS()+15*day), sc.contact)
	if got := decodeSent(t, ok); got.Status != RelayQueued {
		t.Fatalf("exactly 15 days ahead: %+v", got)
	}
	rec := sc.send1(expEnv(t, sc.recip.aid, sc.h.nowMS()+15*day+1), sc.contact)
	if rec.Code != http.StatusBadRequest || reasonOf(rec) != "bad_exp" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestPollSkipsExpired(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	soon := h.nowMS() + 10_000
	h.queueTo(a, 2, 16, &soon, "soon")
	later := h.nowMS() + 3_600_000
	h.queueTo(a, 1, 16, &later, "later")
	if p := h.poll(a, map[string]any{}); len(p.Messages) != 3 {
		t.Fatalf("before: %d", len(p.Messages))
	}
	h.advance(10 * time.Second)
	if p := h.poll(a, map[string]any{}); len(p.Messages) != 1 || p.More {
		t.Fatalf("after exp: %+v", p)
	}
}

func TestPurgeExpiredWithin60s(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	soon := h.nowMS() + 30_000
	h.queueTo(a, 2, 16, &soon, "soon")
	h.queueTo(a, 1, 16, nil, "none")
	if n, _ := h.store.PurgeExpiredByExp(h.clock()); n != 0 {
		t.Fatalf("before exp: %d", n)
	}
	h.advance(60 * time.Second)
	n, err := h.store.PurgeExpiredByExp(h.clock())
	if err != nil || n != 2 {
		t.Fatalf("purged %d, %v", n, err)
	}
	if p, _ := h.store.RelayPending(a.aid); p != 1 {
		t.Fatalf("%d left, want the row without exp", p)
	}
}

func TestExpRowsCountTowardMailbox(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	soon := h.nowMS() + 30_000
	h.queueTo(a, 2, 16, &soon, "soon")
	h.advance(time.Minute)
	// Expired but not yet swept: the row is still held.
	if n, _ := h.store.RelayPending(a.aid); n != 2 {
		t.Fatalf("pending %d, want 2 until the sweep", n)
	}
}

func TestExpDropCounterHasNoAID(t *testing.T) {
	h := newRelayHub(t)
	a := h.agent()
	soon := h.nowMS() + 1000
	h.queueTo(a, 3, 16, &soon, "soon")
	h.advance(time.Minute)
	n, err := h.store.PurgeExpiredByExp(h.srv.store.now())
	if err != nil {
		t.Fatal(err)
	}
	h.srv.relay.expDropped.Add(int64(n))
	if h.srv.RelayExpDropped() != 3 {
		t.Fatalf("counter %d", h.srv.RelayExpDropped())
	}
}

func TestFedForwardDropsExpired(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	sender := a.agent()
	ss := a.openSession(sender.c)
	exp := a.nowMS() - 1
	env := expEnv(t, owner.aid, exp)
	// Origin: refused without a forward.
	rec := a.send0(ss, env, kind0Opts{home: b.hubAID})
	if rec.Code != 400 || reasonOf(rec) != "expired" || b.forwards() != 0 {
		t.Fatalf("origin: %d %s, forwards %d", rec.Code, rec.Body, b.forwards())
	}
	// Destination: refused on its own.
	g := b.issue(owner, seal.CapClassContact, time.Hour)
	env = withCap(t, expEnv(t, owner.aid, exp), g)
	home := b.fedServe(b.signedForward(a, env, nil))
	if home.Code != 400 || reasonOf(home) != "expired" {
		t.Fatalf("destination: %d %s", home.Code, home.Body)
	}
	if b.queued(owner.aid) != 0 {
		t.Fatal("queued at the destination")
	}
	_ = httptest.NewRecorder
}
