package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The test hubs of this package: real hub identities, each served over
// HTTP under the wire-3 contract with its /hub/identity and the federation
// routes, and a fake kernel behind the Kernel seam. The kernel's own checks
// (the credential, the mailbox, the directory) are tested in
// internal/aghub with the real kernel; here the federation's part is: the
// peers, the signatures, the streams and the wire of the answers.

// stampWire serves f under the wire-3 contract, so its answers state the
// hub wire as a hub's do (a peer that does not is cut off, peerwire.go).
func stampWire(f func(http.ResponseWriter, *http.Request)) http.Handler {
	return wire3.Contract(http.HandlerFunc(f))
}

// testHub is one hub of a test: its identity, its HTTP server and, once
// started, its federation service.
type testHub struct {
	t   testing.TB
	dir string
	id  *hubid.Identity
	srv *httptest.Server
	svc *Service
	k   *fakeKernel
	mu  sync.Mutex
	h   http.Handler
	// hits counts the requests that reached the federation routes, by path.
	hits map[string]int
}

func newTestHub(t testing.TB) *testHub {
	t.Helper()
	dir := t.TempDir()
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := &testHub{t: t, dir: dir, id: id, hits: map[string]int{}}
	// Until it is started, the hub serves its /hub/identity and nothing
	// else, as a hub with federation off does.
	idOnly := http.NewServeMux()
	idOnly.Handle("/hub/identity", id.Handler())
	idOnly.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { wire3.Refuse(w, wire3.ReasonNotFound) }))
	h.h = wire3.Contract(idOnly)
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		hd := h.h
		h.hits[r.URL.Path]++
		h.mu.Unlock()
		hd.ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// peer is h as an entry of another hub's peer table.
func (h *testHub) peer() Peer { return Peer{AID: h.id.AID, Endpoint: h.srv.URL} }

// start opens h's federation service with cfg, d as its directory (nil for
// none) and a new fake kernel, and serves it.
func (h *testHub) start(cfg Config, d Directory) *Service {
	h.t.Helper()
	svc, err := New(h.dir, cfg, h.id)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = svc.Close() })
	if d != nil {
		svc.SetDirectory(d)
	}
	h.k = newFakeKernel()
	svc.SetKernel(h.k)
	mux := http.NewServeMux()
	mux.Handle("/hub/identity", h.id.Handler())
	mux.Handle("/fed/", svc.Handler())
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { wire3.Refuse(w, wire3.ReasonNotFound) }))
	h.mu.Lock()
	h.svc, h.h = svc, wire3.Contract(mux)
	h.mu.Unlock()
	return svc
}

// hitsOf is how many requests for path reached h.
func (h *testHub) hitsOf(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

// signedReq is a request to h signed by the hub as for action, at the time
// ts (0: now), over the body sent unless signedBody is set.
func (h *testHub) signedReq(as *hubid.Identity, action, method, path string, body []byte, ts uint64, signedBody []byte) *http.Request {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set(wire3.Header, strconv.Itoa(wire3.Version))
	if ts == 0 {
		ts = nextTS()
	}
	if signedBody == nil {
		signedBody = body
	}
	sig, seq := as.Ctrl.Sign(relayauth.PreimageV2(action, as.AID, h.id.AID, ts, method, req.URL.RequestURI(), signedBody))
	req.Header.Set(relayauth.HeaderAID, as.AID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	return req
}

// do sends req and returns the status, the body and the headers.
func do(t testing.TB, req *http.Request) (int, []byte, http.Header) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

// reasonOf is the reason of a wire-3 refusal body.
func reasonOf(b []byte) string {
	var r struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(b, &r)
	return r.Reason
}

var tsMu sync.Mutex
var tsLast int64

// nextTS is a signing time no test request has used: RC1 takes each of a
// signer's times once.
func nextTS() uint64 {
	tsMu.Lock()
	defer tsMu.Unlock()
	now := time.Now().UnixMilli()
	if now <= tsLast {
		now = tsLast + 1
	}
	tsLast = now
	return uint64(now)
}

// fakeKernel stands in for the hub kernel behind the Kernel seam: RC1 as a
// set of the times taken, a source bucket a test empties, and forwards and
// bucket requests recorded and answered as the kernel answers a good one.
type fakeKernel struct {
	mu          sync.Mutex
	taken       map[string]bool
	sourceEmpty bool
	maxEnvelope int64
	forwards    []forwardCall
	buckets     [][]byte
}

// forwardCall is one forward the kernel was handed.
type forwardCall struct {
	peer   string
	body   []byte
	access string
}

func newFakeKernel() *fakeKernel { return &fakeKernel{taken: map[string]bool{}, maxEnvelope: 1 << 20} }

func (k *fakeKernel) PeerRC1(w http.ResponseWriter, aid string, ts uint64) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := aid + "/" + strconv.FormatUint(ts, 10)
	if k.taken[key] {
		wire3.Refuse(w, wire3.ReasonReplayed)
		return false
	}
	k.taken[key] = true
	return true
}

func (k *fakeKernel) ForwardSourceEmpty(string) (bool, time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sourceEmpty, 3 * time.Second
}

func (k *fakeKernel) ServeForward(w http.ResponseWriter, r *http.Request, aid string, body []byte) {
	k.mu.Lock()
	k.forwards = append(k.forwards, forwardCall{aid, body, r.Header.Get(headerAccess)})
	k.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "queued", "rid": "AAAAAAAAAAAAAAAAAAAAAA", "recipient_quiet": false})
}

func (k *fakeKernel) ServeBucket(w http.ResponseWriter, body []byte) {
	k.mu.Lock()
	k.buckets = append(k.buckets, body)
	k.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"max_bits": 0, "entries": []any{}})
}

func (k *fakeKernel) MaxEnvelope() int64 { return k.maxEnvelope }

func (k *fakeKernel) forwarded() []forwardCall {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]forwardCall(nil), k.forwards...)
}

// fedEnv is a structurally valid sealed envelope for "to". Hubs parse
// only the outer layer, so the ciphertext need not be real here.
func fedEnv(t testing.TB, to, ct string) []byte {
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

// fakeDirectory stands in for the hub kernel behind the Directory seam.
type fakeDirectory struct {
	mu      sync.Mutex
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
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []json.RawMessage{}
	next := cursor
	for i, r := range f.reviews {
		if int64(i+1) > cursor && len(out) < limit {
			out = append(out, r)
			next = int64(i + 1)
		}
	}
	return out, next, nil
}

func (f *fakeDirectory) AdmitFedReview(peerAID string, raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotRevs = append(f.gotRevs, storedReview{peer: peerAID, raw: raw})
	return nil
}

// discoveryPair starts hubs A and B peered for discovery: A serves source,
// and B pulls from A into sink. It returns A and B's service.
func discoveryPair(t *testing.T, source, sink *fakeDirectory) (a *testHub, b *Service) {
	t.Helper()
	a, hb := newTestHub(t), newTestHub(t)
	a.start(Config{Discovery: "allowlist", Home: "https://hub-a.example", Peers: []Peer{hb.peer()}}, source)
	b = hb.start(Config{Discovery: "allowlist", Home: "https://hub-b.example", Peers: []Peer{a.peer()}}, sink)
	return a, b
}

// newDiscoveryService is a hub's service with cfg and d, not served.
func newDiscoveryService(t *testing.T, dir string, cfg Config, d Directory) *Service {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(dir, cfg, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.SetDirectory(d)
	svc.SetKernel(newFakeKernel())
	return svc
}

// pageOf asks hub a, as the hub b, for its card stream after cursor, and
// decodes the page.
func pageOf(t *testing.T, a *testHub, b *hubid.Identity, cursor int64) (int, FedA2ACardPage, []byte) {
	t.Helper()
	code, body, _ := do(t, a.signedReq(b, relayauth.ActionFedCards, http.MethodGet,
		fmt.Sprintf("/fed/v3/cards?cursor=%d", cursor), nil, 0, nil))
	var page FedA2ACardPage
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
	}
	return code, page, body
}

var _ = context.Background
