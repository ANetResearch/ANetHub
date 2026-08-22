package federation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// fakeLocal is hub B's mailbox: it accepts exactly one agent.
type fakeLocal struct {
	agent    string
	enqueued []string // payloads received
}

func (f *fakeLocal) HasAgent(aid string) bool { return aid == f.agent }
func (f *fakeLocal) Enqueue(_, _, _, _ string, payload []byte) (int64, error) {
	f.enqueued = append(f.enqueued, string(payload))
	return int64(len(f.enqueued)), nil
}

type rig struct {
	a, b     *Service
	aid, bid *hubid.Identity
	bLocal   *fakeLocal
	bSrv     *httptest.Server
}

// newRig builds two federated hubs: A (sender) peers with B (receiver).
func newRig(t *testing.T) *rig {
	t.Helper()
	dirA, dirB := t.TempDir(), t.TempDir()
	idA, err := hubid.LoadOrIncept(dirA)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := hubid.LoadOrIncept(dirB)
	if err != nil {
		t.Fatal(err)
	}
	bLocal := &fakeLocal{agent: "aid:bob"}

	// B's server: federation inbound + /hub/identity for KEL pinning.
	var bSvc *Service
	muxB := http.NewServeMux()
	muxB.Handle("/hub/identity", idB.Handler())
	muxB.HandleFunc("/fed/v1/forward", func(w http.ResponseWriter, r *http.Request) {
		bSvc.Handler().ServeHTTP(w, r)
	})
	bSrv := httptest.NewServer(muxB)
	t.Cleanup(bSrv.Close)

	muxA := http.NewServeMux()
	muxA.Handle("/hub/identity", idA.Handler())
	aSrv := httptest.NewServer(muxA)
	t.Cleanup(aSrv.Close)

	a, err := New(dirA, Config{Delivery: "allowlist", Peers: []Peer{{AID: idB.AID, Endpoint: bSrv.URL}}}, idA, &fakeLocal{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	bSvc, err = New(dirB, Config{Delivery: "allowlist", Peers: []Peer{{AID: idA.AID, Endpoint: aSrv.URL}}}, idB, bLocal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bSvc.Close() })
	return &rig{a: a, b: bSvc, aid: idA, bid: idB, bLocal: bLocal, bSrv: bSrv}
}

func TestForwardEndToEnd(t *testing.T) {
	r := newRig(t)
	ok, peer, err := r.a.TryForward("aid:bob", "aid:alice", "message", "i-1", []byte("hello bob"))
	if err != nil || !ok || peer != r.bid.AID {
		t.Fatalf("forward failed: ok=%v peer=%s err=%v", ok, peer, err)
	}
	if len(r.bLocal.enqueued) != 1 || r.bLocal.enqueued[0] != "hello bob" {
		t.Fatalf("payload not enqueued on B: %v", r.bLocal.enqueued)
	}
}

func TestIdempotentDuplicate(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 2; i++ {
		if ok, _, err := r.a.TryForward("aid:bob", "aid:alice", "message", "i-1", []byte("same bytes")); !ok || err != nil {
			t.Fatalf("attempt %d: %v %v", i, ok, err)
		}
	}
	if len(r.bLocal.enqueued) != 1 {
		t.Fatalf("duplicate must not double-enqueue: %d", len(r.bLocal.enqueued))
	}
}

func TestUnknownDestination(t *testing.T) {
	r := newRig(t)
	ok, _, err := r.a.TryForward("aid:nobody", "aid:alice", "message", "", []byte("x"))
	if ok {
		t.Fatal("unknown destination must not be accepted")
	}
	_ = err // all peers 404 → not forwarded, no hard error required
}

// post sends a raw envelope to B, bypassing A's signer.
func postRaw(t *testing.T, r *rig, env Envelope) (int, map[string]string) {
	t.Helper()
	b, _ := json.Marshal(env)
	resp, err := http.Post(r.bSrv.URL+"/fed/v1/forward", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func signedEnvelope(t *testing.T, r *rig, mutate func(*Envelope, []byte) []byte) Envelope {
	t.Helper()
	payload := []byte("payload-bytes")
	cid, _ := sumRawForTest(payload)
	env := Envelope{V: 1, OriginHubAID: r.aid.AID, DestAID: "aid:bob", FromAID: "aid:alice",
		Kind: "message", Payload: base64.StdEncoding.EncodeToString(payload), PayloadCID: cid,
		Hop: 1, SeenHubs: []string{r.aid.AID}, TS: nowMillisForTest()}
	if mutate != nil {
		payload = mutate(&env, payload)
	}
	pre, err := env.preimage(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig, seq := r.aid.Sign(pre)
	env.Sig, env.KeyStateSeq = base64.StdEncoding.EncodeToString(sig), seq
	return env
}

func TestRejectsStrangerHub(t *testing.T) {
	r := newRig(t)
	stranger, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := signedEnvelope(t, r, nil)
	env.OriginHubAID = stranger.AID
	code, out := postRaw(t, r, env)
	if code != 403 || out["error"] != "POLICY_REFUSED" {
		t.Fatalf("stranger hub must be POLICY_REFUSED: %d %v", code, out)
	}
}

func TestRejectsTamperedEnvelope(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, nil)
	env.DestAID = "aid:mallory" // tamper after signing
	code, out := postRaw(t, r, env)
	if code != 401 || out["error"] != "INVALID_SIGNATURE" {
		t.Fatalf("tampered envelope must be INVALID_SIGNATURE: %d %v", code, out)
	}
}

func TestHopAndLoopGuards(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, func(e *Envelope, p []byte) []byte {
		e.Hop = MaxHop + 1
		return p
	})
	if code, out := postRaw(t, r, env); code != 400 || out["error"] != "HOP_EXCEEDED" {
		t.Fatalf("hop guard: %d %v", code, out)
	}
	env = signedEnvelope(t, r, func(e *Envelope, p []byte) []byte {
		e.SeenHubs = []string{r.aid.AID, r.bid.AID} // B already saw it
		return p
	})
	if code, out := postRaw(t, r, env); code != 400 || out["error"] != "HOP_EXCEEDED" {
		t.Fatalf("loop guard: %d %v", code, out)
	}
}

func TestPayloadCIDMismatch(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, func(e *Envelope, p []byte) []byte {
		e.PayloadCID = "bafkreidoctoredcid"
		return p
	})
	code, out := postRaw(t, r, env)
	if code != 400 || out["error"] != "MALFORMED" {
		t.Fatalf("cid mismatch must be MALFORMED: %d %v", code, out)
	}
}

// Two hubs, one agent, and a directory that crosses between them.
//
// The property being tested is not "the card arrived" but that it arrived
// as the agent's own signed statement. A peer hub can decline to tell us
// about an agent — hiding is allowed and unavoidable — and this is what
// stops it inventing one.
func TestDirectoryFederation(t *testing.T) {
	dir := t.TempDir()

	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(agent.KEL())
	if err != nil {
		t.Fatal(err)
	}
	card := signedCardFor(t, agent, "RemoteNode", []string{"cas.put"})

	// Hub A publishes one opted-in card.
	source := &fakeDirectory{cards: []FedCardView{{
		Card: card, KEL: kel, Home: "https://hub-a.example", FedSeq: 7,
	}}}
	svcA := newDiscoveryService(t, filepath.Join(dir, "a"), Config{
		Discovery: "allowlist", Home: "https://hub-a.example",
		Peers: []Peer{{AID: "did:anet:b", Endpoint: "http://unused"}},
	}, source)
	srvA := httptest.NewServer(svcA.Handler())
	defer srvA.Close()

	// Hub B pulls from A.
	sink := &fakeDirectory{}
	svcB := newDiscoveryService(t, filepath.Join(dir, "b"), Config{
		Discovery: "allowlist", Home: "https://hub-b.example",
		Peers: []Peer{{AID: "did:anet:a", Endpoint: srvA.URL}},
	}, sink)
	admitted, refused := svcB.SyncOnce(context.Background())
	if admitted != 1 || refused != 0 {
		t.Fatalf("sync admitted=%d refused=%d, want 1/0", admitted, refused)
	}
	if len(sink.got) != 1 {
		t.Fatalf("hub B stored %d cards", len(sink.got))
	}
	if sink.got[0].home != "https://hub-a.example" {
		t.Errorf("routing hint lost: %q — B would not know where to deliver", sink.got[0].home)
	}

	// The cursor advances, so a second sync is not a second copy.
	admitted2, _ := svcB.SyncOnce(context.Background())
	if admitted2 != 0 {
		t.Errorf("re-syncing re-admitted %d cards; the cursor did not advance", admitted2)
	}
}

// Discovery is off by default and switches independently of delivery. A
// hub may carry a peer's traffic without publishing its directory.
func TestDiscoveryIsOffUnlessAskedFor(t *testing.T) {
	svc := newDiscoveryService(t, t.TempDir(), Config{
		Delivery: "allowlist", // delivery on…
		Peers:    []Peer{{AID: "did:anet:a", Endpoint: "http://unused"}},
	}, &fakeDirectory{})
	if svc.DiscoveryEnabled() {
		t.Error("discovery must not follow delivery — they are separate decisions about a peer")
	}
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/fed/v1/cards")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a hub with discovery off served its directory: %d", resp.StatusCode)
	}
}

// fakeDirectory stands in for the hub kernel.
type fakeDirectory struct {
	cards []FedCardView
	got   []storedCard
}

type storedCard struct {
	peer, home string
	card       []byte
}

func (f *fakeDirectory) CardsSince(cursor int64, limit int, home string) ([]FedCardView, int64, error) {
	out := []FedCardView{}
	next := cursor
	for _, c := range f.cards {
		if c.FedSeq > cursor {
			c.Home = home
			out = append(out, c)
			next = c.FedSeq
		}
	}
	return out, next, nil
}

func (f *fakeDirectory) AdmitFedCard(peerAID string, card, kel []byte, home string) error {
	f.got = append(f.got, storedCard{peer: peerAID, home: home, card: card})
	return nil
}

func newDiscoveryService(t *testing.T, dir string, cfg Config, d Directory) *Service {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(dir, cfg, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.SetDirectory(d)
	return svc
}

func signedCardFor(t *testing.T, c *identity.Controller, name string, caps []string) []byte {
	t.Helper()
	now := time.Now()
	card := &adp.AgentCard{
		SubjectDID: c.AID(), CardSchema: adp.CardSchema{Major: 1},
		Seq: uint64(now.UnixNano()), IssuedAt: now.Unix(),
		NotBefore:    now.Add(-time.Minute).Unix(),
		Capabilities: caps, CriticalExtensions: []string{}, Name: name,
	}
	if err := card.Sign(c); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
