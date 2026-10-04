package federation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ANetResearch/ANetCore/seal"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// fakeLocal is hub B's mailbox. It stands in for the hub kernel behind the
// LocalDelivery seam, so it has to offer the same things the kernel does
// and not just the happy path: membership that changes while federation
// is running (agents register and deregister), the kernel's refusals (a
// payload that is not a sealed envelope for the destination is
// ErrBadEnvelope, a full mailbox is ErrMailboxFull), an Enqueue that can
// fail for other reasons, and safety under concurrent inbound forwards. A
// fake pinned to one immutable agent hides every ordering defect that
// depends on an AID appearing after a forward for it was already refused.
type fakeLocal struct {
	mu       sync.Mutex
	agents   map[string]bool
	enqueued []string // envelopes received
	// quota, when positive, is how many envelopes the mailbox holds
	// before Enqueue answers ErrMailboxFull, as the kernel's quota does.
	quota int
	// enqueueErr, when set, makes Enqueue fail — the kernel's mailbox
	// write can fail (disk), and the caller has to unwind.
	enqueueErr error
	// hold, when non-nil, blocks the first Enqueue until it is closed and
	// reports entry on entered. Lets a test hold one forward inside the
	// mailbox write while a second forward of the same payload arrives.
	hold    chan struct{}
	entered chan struct{}
}

func newFakeLocal(agents ...string) *fakeLocal {
	f := &fakeLocal{agents: make(map[string]bool, len(agents))}
	for _, a := range agents {
		f.agents[a] = true
	}
	return f
}

func (f *fakeLocal) register(aid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents[aid] = true
}

// setEnqueueErr makes subsequent mailbox writes fail (or succeed again
// with nil). Guarded because the handler reads it on a server goroutine.
func (f *fakeLocal) setEnqueueErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enqueueErr = err
}

// holdFirstEnqueue parks the next Enqueue until release is called. entered
// is closed once that call is in flight, so a test can be certain one
// forward is inside the mailbox write when the next one arrives.
func (f *fakeLocal) holdFirstEnqueue() (release func(), entered <-chan struct{}) {
	hold, ent := make(chan struct{}), make(chan struct{})
	f.mu.Lock()
	f.hold, f.entered = hold, ent
	f.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(hold) }) }, ent
}

func (f *fakeLocal) delivered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.enqueued...)
}

func (f *fakeLocal) HasAgent(aid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.agents[aid]
}

func (f *fakeLocal) Enqueue(to string, envelope []byte) (int64, error) {
	f.mu.Lock()
	hold, entered := f.hold, f.entered
	f.hold, f.entered = nil, nil
	f.mu.Unlock()
	if hold != nil {
		close(entered)
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enqueueErr != nil {
		return 0, f.enqueueErr
	}
	outer, err := seal.ParseOuter(envelope)
	if err != nil || outer.To != to {
		return 0, fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	if f.quota > 0 && len(f.enqueued) >= f.quota {
		return 0, fmt.Errorf("%w: %d queued", ErrMailboxFull, len(f.enqueued))
	}
	f.enqueued = append(f.enqueued, string(envelope))
	return int64(len(f.enqueued)), nil
}

// setQuota bounds the fake mailbox.
func (f *fakeLocal) setQuota(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quota = n
}

// fedEnv is a structurally valid sealed envelope for "to". Hubs parse
// only the outer layer, so the ciphertext need not be real here.
func fedEnv(t *testing.T, to, ct string) []byte {
	t.Helper()
	env := &seal.SealedEnvelope{V: seal.EnvelopeVersion, To: to, Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte(ct),
		Access: &seal.Access{Kind: seal.AccessKindSession}}
	b, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type rig struct {
	a, b     *Service
	aid, bid *hubid.Identity
	bLocal   *fakeLocal
	bKeys    *fakeKeys
	bSrv     *httptest.Server
	// forwards holds the raw bodies B received on /fed/v1/forward, so a
	// test can inspect exactly what crossed between the hubs.
	mu       sync.Mutex
	forwards [][]byte
}

// fakeKeys is B's key source. It answers like the kernel's: a key set and
// KEL for a registered AID that published one, ErrNoKeys for any other
// AID, and a storage error when told to fail.
type fakeKeys struct {
	mu   sync.Mutex
	sets map[string][2][]byte
	err  error
}

func (k *fakeKeys) LocalKeys(aid string) ([]byte, []byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return nil, nil, k.err
	}
	v, ok := k.sets[aid]
	if !ok {
		return nil, nil, ErrNoKeys
	}
	return v[0], v[1], nil
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
	bLocal := newFakeLocal("aid:bob")

	// B's server: federation inbound + /hub/identity for KEL pinning.
	var bSvc *Service
	muxB := http.NewServeMux()
	muxB.Handle("/hub/identity", idB.Handler())
	r0 := &rig{}
	muxB.HandleFunc("/fed/v1/forward", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r0.mu.Lock()
		r0.forwards = append(r0.forwards, body)
		r0.mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		bSvc.Handler().ServeHTTP(w, r)
	})
	muxB.HandleFunc("/fed/v2/", func(w http.ResponseWriter, r *http.Request) {
		bSvc.Handler().ServeHTTP(w, r)
	})
	bSrv := httptest.NewServer(muxB)
	t.Cleanup(bSrv.Close)

	muxA := http.NewServeMux()
	muxA.Handle("/hub/identity", idA.Handler())
	aSrv := httptest.NewServer(muxA)
	t.Cleanup(aSrv.Close)

	a, err := New(dirA, Config{Delivery: "allowlist", Peers: []Peer{{AID: idB.AID, Endpoint: bSrv.URL}}}, idA, newFakeLocal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	bSvc, err = New(dirB, Config{Delivery: "allowlist", Peers: []Peer{{AID: idA.AID, Endpoint: aSrv.URL}}}, idB, bLocal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bSvc.Close() })
	bKeys := &fakeKeys{sets: map[string][2][]byte{}}
	bSvc.SetKeySource(bKeys)
	r0.a, r0.b, r0.aid, r0.bid, r0.bLocal, r0.bKeys, r0.bSrv = a, bSvc, idA, idB, bLocal, bKeys, bSrv
	return r0
}

func TestForwardEndToEnd(t *testing.T) {
	r := newRig(t)
	env := fedEnv(t, "aid:bob", "hello bob")
	ok, peer, err := r.a.TryForward("aid:bob", env)
	if err != nil || !ok || peer != r.bid.AID {
		t.Fatalf("forward failed: ok=%v peer=%s err=%v", ok, peer, err)
	}
	if len(r.bLocal.enqueued) != 1 || r.bLocal.enqueued[0] != string(env) {
		t.Fatalf("envelope not enqueued on B unchanged: %v", r.bLocal.enqueued)
	}
}

func TestIdempotentDuplicate(t *testing.T) {
	r := newRig(t)
	env := fedEnv(t, "aid:bob", "same bytes")
	for i := 0; i < 2; i++ {
		if ok, _, err := r.a.TryForward("aid:bob", env); !ok || err != nil {
			t.Fatalf("attempt %d: %v %v", i, ok, err)
		}
	}
	if len(r.bLocal.enqueued) != 1 {
		t.Fatalf("duplicate must not double-enqueue: %d", len(r.bLocal.enqueued))
	}
}

func TestUnknownDestination(t *testing.T) {
	r := newRig(t)
	ok, _, err := r.a.TryForward("aid:nobody", fedEnv(t, "aid:nobody", "x"))
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

// signedEnvelope builds a forward envelope from A to B, lets mutate change
// it (and return a different payload), and signs the result. A payload
// the mutation replaced is carried in Payload, and its CID is recomputed
// unless the mutation set PayloadCID itself.
func signedEnvelope(t *testing.T, r *rig, mutate func(*Envelope, []byte) []byte) Envelope {
	t.Helper()
	payload := fedEnv(t, "aid:bob", "payload-bytes")
	cid, _ := sumRawForTest(payload)
	env := Envelope{V: ForwardVersion, OriginHubAID: r.aid.AID, DestAID: "aid:bob",
		Payload: base64.StdEncoding.EncodeToString(payload), PayloadCID: cid,
		Hop: 1, SeenHubs: []string{r.aid.AID}, TS: nowMillisForTest()}
	if mutate != nil {
		np := mutate(&env, payload)
		if !bytes.Equal(np, payload) {
			env.Payload = base64.StdEncoding.EncodeToString(np)
			if env.PayloadCID == cid {
				env.PayloadCID, _ = sumRawForTest(np)
			}
		}
		payload = np
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
	resp, err := http.Get(srv.URL + "/fed/v2/cards")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a hub with discovery off served its directory: %d", resp.StatusCode)
	}
}

// The ADP card stream is gone with the signed ADP card it carried: a hub
// with discovery on serves its directory on /fed/v2/cards only.
func TestTheADPCardStreamIsGone(t *testing.T) {
	svc := newDiscoveryService(t, t.TempDir(), Config{
		Discovery: "allowlist", Home: "https://hub-a.example",
		Peers: []Peer{{AID: "did:anet:b", Endpoint: "http://unused"}},
	}, &fakeDirectory{})
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	for path, want := range map[string]int{"/fed/v1/cards": http.StatusNotFound, "/fed/v2/cards": http.StatusOK} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: %d, want %d", path, resp.StatusCode, want)
		}
	}
}

// fakeDirectory stands in for the hub kernel.
type fakeDirectory struct {
	reviews []json.RawMessage
	gotRevs []storedReview
	// a2a is the A2A card stream this directory serves; gotA2A what it
	// admitted from one. a2aRefuseForNow names the FedSeqs it will not
	// take TODAY — the shape of "that agent is registered here", which
	// stops applying the moment the agent moves; a2aRejectForever those
	// that are wrong for good (malformed, forged, mismatched), which the
	// stream should move past.
	a2a              []FedA2ACardView
	gotA2A           []FedA2ACardView
	a2aRefuseForNow  map[int64]bool
	a2aRejectForever map[int64]bool
}

func (f *fakeDirectory) A2ACardsSince(cursor int64, limit int, home string) ([]FedA2ACardView, int64, error) {
	out := []FedA2ACardView{}
	next := cursor
	for _, c := range f.a2a {
		if c.FedSeq > cursor && len(out) < limit {
			c.Home = home
			out = append(out, c)
			next = c.FedSeq
		}
	}
	return out, next, nil
}

func (f *fakeDirectory) AdmitFedA2ACard(peerAID string, e FedA2ACardView) error {
	if f.a2aRefuseForNow[e.FedSeq] {
		return fmt.Errorf("%w: registered here", ErrRefusedForNow)
	}
	if f.a2aRejectForever[e.FedSeq] {
		return fmt.Errorf("card is malformed")
	}
	f.gotA2A = append(f.gotA2A, e)
	return nil
}

type storedReview struct {
	peer string
	raw  json.RawMessage
}

func (f *fakeDirectory) ReviewsSince(cursor int64, limit int) ([]json.RawMessage, int64, error) {
	out := []json.RawMessage{}
	next := cursor
	for i, r := range f.reviews {
		if int64(i+1) > cursor {
			out = append(out, r)
			next = int64(i + 1)
		}
	}
	return out, next, nil
}

func (f *fakeDirectory) AdmitFedReview(peerAID string, raw json.RawMessage) error {
	f.gotRevs = append(f.gotRevs, storedReview{peer: peerAID, raw: raw})
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

// A permanent refusal must NOT hold the stream, or one bad card from one
// peer wedges that peer's directory for ever.
func TestAPermanentRefusalStillAdvances(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"bad"}`), KEL: []byte("k"), FedSeq: 1},
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"good"}`), KEL: []byte("k"), FedSeq: 2},
	}}
	sink := &fakeDirectory{a2aRejectForever: map[int64]bool{1: true}}
	_, svcB := discoveryPair(t, source, sink)
	if admitted, refused := svcB.SyncOnce(context.Background()); admitted != 1 || refused != 1 {
		t.Errorf("a permanently bad card stopped the stream: admitted %d refused %d, want 1 and 1",
			admitted, refused)
	}
	if c := svcB.peerA2ACursor("did:anet:a"); c != 2 {
		t.Errorf("cursor %d, want 2: past the card refused for good", c)
	}
}

// The cursor is an optimisation, and it can be wrong.
//
// Holding it at a transient refusal stops new entries being lost. It does
// nothing for the ones already lost — and in production there was already
// one: a card skipped before the fix existed, with the cursor sitting
// past it for ever. So a peer's directory is re-read from the start every
// so often, which heals that and every cause not yet thought of.
func TestTheDirectoryHealsWhatTheCursorSkipped(t *testing.T) {
	source := &fakeDirectory{a2a: []FedA2ACardView{
		{Format: FormatA2ACard, Card: json.RawMessage(`{"name":"a"}`), KEL: []byte("k"), FedSeq: 1},
	}}
	sink := &fakeDirectory{}
	_, svcB := discoveryPair(t, source, sink)

	svcB.SyncOnce(context.Background())
	if len(sink.gotA2A) != 1 {
		t.Fatalf("setup: admitted %d", len(sink.gotA2A))
	}
	// The entry is lost — a bad restore, an admission bug, anything. The
	// cursor is past it, so ordinary rounds will never ask again.
	sink.gotA2A = nil
	for i := 0; i < fullResyncEvery-2; i++ {
		svcB.SyncOnce(context.Background())
	}
	if len(sink.gotA2A) != 0 {
		t.Fatalf("re-read too eagerly: a full pass every round would make the cursor pointless")
	}
	// The scheduled full pass brings it back.
	svcB.SyncOnce(context.Background())
	if len(sink.gotA2A) != 1 {
		t.Errorf("the directory did not heal: admitted %d after a full resync round", len(sink.gotA2A))
	}
	if c := svcB.peerA2ACursor("did:anet:a"); c != 1 {
		t.Errorf("cursor %d after the full pass, want 1", c)
	}
}

// A chain with exactly one record must be witnessable.
//
// WitnessOnce tested head.Seq == 0 for "nothing to pin". An AEL's first
// record is seq 0, and the opening entry every upgraded hub starts with
// sits there — so a hub whose chain held only that was never witnessed.
// Live: host-e was witnessed zero times while witnessing host-f hourly.
func TestAOneRecordChainIsStillWitnessed(t *testing.T) {
	dir := t.TempDir()
	// A peer serving a head at seq 0.
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x402/issuance/head" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chain_did": "did:anet:peer", "seq": 0, "head_id": "bafy-opening"})
	}))
	defer peer.Close()

	svc := newDiscoveryService(t, dir, Config{
		Discovery: "allowlist", Home: "https://ours.example",
		Peers: []Peer{{AID: "did:anet:peer", Endpoint: peer.URL}},
	}, &fakeDirectory{})
	w := &fakeWitness{}
	svc.SetWitness(w)

	if n := svc.WitnessOnce(context.Background()); n != 1 {
		t.Fatalf("pinned %d heads, want 1 — a one-record chain was treated as having none", n)
	}
	if len(w.pinned) != 1 || w.pinned[0].seq != 0 || w.pinned[0].headID != "bafy-opening" {
		t.Errorf("pinned = %+v", w.pinned)
	}
}

// A peer that has issued nothing has no head, and must not be pinned.
func TestAPeerWithNoChainIsNotWitnessed(t *testing.T) {
	dir := t.TempDir()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"chain_did": "did:anet:peer"})
	}))
	defer peer.Close()
	svc := newDiscoveryService(t, dir, Config{
		Discovery: "allowlist", Home: "https://ours.example",
		Peers: []Peer{{AID: "did:anet:peer", Endpoint: peer.URL}},
	}, &fakeDirectory{})
	w := &fakeWitness{}
	svc.SetWitness(w)
	if n := svc.WitnessOnce(context.Background()); n != 0 {
		t.Errorf("pinned %d heads for a chain that has none", n)
	}
}

// Witnessing is on by default and can be turned off.
func TestWitnessingDefaultsOnAndCanBeDisabled(t *testing.T) {
	peers := []Peer{{AID: "did:anet:peer", Endpoint: "http://unused"}}
	if !(Config{Peers: peers}).WitnessEnabled() {
		t.Error("witnessing must default on for a hub that has peers")
	}
	if (Config{Peers: peers, Witness: "off"}).WitnessEnabled() {
		t.Error(`"witness":"off" did not disable it`)
	}
	if (Config{Witness: "on"}).WitnessEnabled() {
		t.Error("a hub with no peers has nobody to witness")
	}
}

type fakeWitness struct {
	pinned []struct {
		peerAID, headID string
		seq             uint64
	}
}

func (f *fakeWitness) Attest(peerAID, headID string, seq uint64) ([]byte, error) {
	f.pinned = append(f.pinned, struct {
		peerAID, headID string
		seq             uint64
	}{peerAID, headID, seq})
	return []byte("attestation"), nil
}
