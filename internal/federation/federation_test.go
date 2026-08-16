package federation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
