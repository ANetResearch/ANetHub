package federation

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// ---- forward v2 ----

// What crosses between hubs names the destination and nothing about the
// sender: no from_aid, kind or interaction_id in the JSON, and none of the
// retired preimage keys in what the hub signs (A2A-DESIGN §3.9, SI-2).
func TestTheForwardEnvelopeCarriesNoSenderMetadata(t *testing.T) {
	r := newRig(t)
	env := fedEnv(t, "aid:bob", "sealed")
	if ok, _, err := r.a.TryForward("aid:bob", env); !ok || err != nil {
		t.Fatalf("forward: %v %v", ok, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.forwards) != 1 {
		t.Fatalf("B received %d forwards", len(r.forwards))
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(r.forwards[0], &fields); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"dest_aid", "hop", "key_state_seq", "origin_hub_aid", "payload", "payload_cid", "seen_hubs", "sig", "ts", "v"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("forward fields = %v, want %v", keys, want)
	}
	if string(fields["v"]) != "2" {
		t.Errorf("forward version = %s, want 2", fields["v"])
	}

	var sent Envelope
	_ = json.Unmarshal(r.forwards[0], &sent)
	pre, err := sent.preimage(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[uint64]any
	if err := coredet.Unmarshal(pre, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []uint64{4, 5, 6} {
		if _, ok := m[k]; ok {
			t.Errorf("the signed preimage still has retired key %d", k)
		}
	}
}

// A peer still on forward v1 is refused with an error that says what to
// do, and the forwarding side reports that explanation.
func TestAForwardV1PeerIsRefusedWithAClearError(t *testing.T) {
	r := newRig(t)
	env := signedEnvelope(t, r, func(e *Envelope, p []byte) []byte {
		e.V = 1
		return p
	})
	code, out := postRaw(t, r, env)
	if code != http.StatusBadRequest || out["error"] != "VERSION_UNSUPPORTED" ||
		!strings.Contains(out["detail"], "v2") || !strings.Contains(out["detail"], "upgraded") {
		t.Fatalf("a v1 envelope: %d %v", code, out)
	}
	if got := r.bLocal.delivered(); len(got) != 0 {
		t.Fatalf("a v1 envelope was enqueued: %v", got)
	}

	// The origin side, facing a peer that refuses v2 the same way.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fedErr(w, http.StatusBadRequest, "VERSION_UNSUPPORTED", "v=2")
	}))
	defer old.Close()
	a := newDeliveryService(t, []Peer{{AID: "did:anet:old", Endpoint: old.URL}}, newFakeLocal())
	ok, _, err := a.TryForward("aid:bob", fedEnv(t, "aid:bob", "x"))
	if ok || err == nil || !strings.Contains(err.Error(), "VERSION_UNSUPPORTED") {
		t.Fatalf("forward to an old peer: ok=%v err=%v; the peer's explanation must reach the caller", ok, err)
	}
}

// A payload that is not a sealed envelope for the destination is refused
// by the receiving hub and not stored.
func TestAForwardedNonEnvelopeIsRefused(t *testing.T) {
	r := newRig(t)
	for name, payload := range map[string][]byte{
		"plaintext":          []byte("a plaintext delegation"),
		"for someone else":   fedEnv(t, "aid:carol", "x"),
		"empty ciphertext":   fedEnv(t, "aid:bob", ""),
		"truncated envelope": fedEnv(t, "aid:bob", "abc")[:10],
	} {
		env := signedEnvelope(t, r, func(e *Envelope, p []byte) []byte { return payload })
		if code, out := postRaw(t, r, env); code != http.StatusBadRequest || out["error"] != "MALFORMED" {
			t.Errorf("%s: %d %v, want 400 MALFORMED", name, code, out)
		}
	}
	if got := r.bLocal.delivered(); len(got) != 0 {
		t.Fatalf("refused payloads were enqueued: %d", len(got))
	}
}

// A full mailbox at the destination hub is 507 there, and the forwarding
// hub reports it as ErrMailboxFull rather than as a generic failure.
func TestAFullMailboxAtThePeerIsReportedAsSuch(t *testing.T) {
	r := newRig(t)
	r.bLocal.setQuota(1)
	if ok, _, err := r.a.TryForward("aid:bob", fedEnv(t, "aid:bob", "one")); !ok || err != nil {
		t.Fatalf("first forward: %v %v", ok, err)
	}
	ok, _, err := r.a.TryForward("aid:bob", fedEnv(t, "aid:bob", "two"))
	if ok || !errors.Is(err, ErrMailboxFull) {
		t.Fatalf("forward into a full mailbox: ok=%v err=%v, want ErrMailboxFull", ok, err)
	}
	env := signedEnvelope(t, r, func(e *Envelope, p []byte) []byte { return fedEnv(t, "aid:bob", "three") })
	if code, out := postRaw(t, r, env); code != http.StatusInsufficientStorage || out["error"] != "MAILBOX_FULL" {
		t.Fatalf("direct forward into a full mailbox: %d %v", code, out)
	}
}

// newDeliveryService is a delivery-enabled service with the given peers.
func newDeliveryService(t *testing.T, peers []Peer, local LocalDelivery) *Service {
	t.Helper()
	dir := t.TempDir()
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(dir, Config{Delivery: "allowlist", Peers: peers}, id, local)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// ---- /fed/v2/keys ----

// A peer hub answers a signed lookup for an AID registered on it, whatever
// the AID's visibility, and 404 for anything else.
func TestAPeerAnswersAKeyLookup(t *testing.T) {
	r := newRig(t)
	r.bKeys.sets["aid:bob"] = [2][]byte{[]byte("keyset-bytes"), []byte("kel-bytes")}

	ks, kel, peer, err := r.a.LookupKeys(context.Background(), "aid:bob", nil)
	if err != nil || peer != r.bid.AID || string(ks) != "keyset-bytes" || string(kel) != "kel-bytes" {
		t.Fatalf("lookup: ks=%q kel=%q peer=%s err=%v", ks, kel, peer, err)
	}
	if _, _, _, err := r.a.LookupKeys(context.Background(), "aid:carol", nil); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("lookup of an AID the peer does not hold: %v, want ErrNoKeys", err)
	}
	// An answer the caller refuses is not returned.
	_, _, _, err = r.a.LookupKeys(context.Background(), "aid:bob", func(_, _ []byte) error {
		return errors.New("does not verify")
	})
	if err == nil || errors.Is(err, ErrNoKeys) {
		t.Fatalf("a refused answer: %v, want an error that is not ErrNoKeys", err)
	}
	// A storage failure at the peer is not "no keys".
	r.bKeys.err = errors.New("disk")
	if _, _, _, err := r.a.LookupKeys(context.Background(), "aid:bob", nil); err == nil || errors.Is(err, ErrNoKeys) {
		t.Fatalf("a peer failure: %v, want an error that is not ErrNoKeys", err)
	}
}

// The lookup is refused unless it is signed by a hub in the peer table,
// for this hub, for this exact request, once.
func TestAKeyLookupMustBeSignedByAPeer(t *testing.T) {
	r := newRig(t)
	r.bKeys.sets["aid:bob"] = [2][]byte{[]byte("ks"), []byte("kel")}
	stranger, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// signingTS is "now" for a signature, strictly after the previous one:
	// the control and the replay below sign the same lookup, and the same
	// lookup signed twice in one millisecond is the same (deterministic
	// Ed25519) signature, which the hub refuses the second time by design.
	var lastTS uint64
	signingTS := func() uint64 {
		ts := uint64(time.Now().UnixMilli())
		if ts <= lastTS {
			ts = lastTS + 1
		}
		lastTS = ts
		return ts
	}
	get := func(path string, signer *hubid.Identity, answering string, tamper func(*http.Request)) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, r.bSrv.URL+path, nil)
		if signer != nil {
			ts := signingTS()
			sig, seq := signer.Sign(relayauth.PreimageV2(actionFedKeys, signer.AID, answering, ts,
				http.MethodGet, req.URL.RequestURI(), nil))
			req.Header.Set(relayauth.HeaderAID, signer.AID)
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		}
		if tamper != nil {
			tamper(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out["error"]
	}
	if code, _ := get("/fed/v2/keys/aid:bob", r.aid, r.bid.AID, nil); code != http.StatusOK {
		t.Fatalf("control: a signed lookup from the peer: %d", code)
	}
	for _, tc := range []struct {
		name   string
		signer *hubid.Identity
		hub    string
		tamper func(*http.Request)
		code   int
	}{
		{"unsigned", nil, "", nil, http.StatusUnauthorized},
		{"stranger hub", stranger, r.bid.AID, nil, http.StatusForbidden},
		{"signed for another hub", r.aid, stranger.AID, nil, http.StatusUnauthorized},
		{"signed for another AID", r.aid, r.bid.AID, func(req *http.Request) {
			req.URL.Path = "/fed/v2/keys/aid:carol"
		}, http.StatusUnauthorized},
		{"bad signature", r.aid, r.bid.AID, func(req *http.Request) {
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(bytes.Repeat([]byte{1}, 64)))
		}, http.StatusUnauthorized},
	} {
		if code, label := get("/fed/v2/keys/aid:bob", tc.signer, tc.hub, tc.tamper); code != tc.code {
			t.Errorf("%s: %d %s, want %d", tc.name, code, label, tc.code)
		}
	}
	// Replay: the same signed request twice.
	req, _ := http.NewRequest(http.MethodGet, r.bSrv.URL+"/fed/v2/keys/aid:bob", nil)
	ts := signingTS()
	sig, seq := r.aid.Sign(relayauth.PreimageV2(actionFedKeys, r.aid.AID, r.bid.AID, ts, http.MethodGet, req.URL.RequestURI(), nil))
	for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		again, _ := http.NewRequest(http.MethodGet, r.bSrv.URL+"/fed/v2/keys/aid:bob", nil)
		again.Header.Set(relayauth.HeaderAID, r.aid.AID)
		again.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		again.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		again.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		resp, err := http.DefaultClient.Do(again)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("use %d of one signature: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
}

// ---- keys in the card sync stream ----

// A card entry carries the agent's key set to the pulling hub.
func TestTheCardStreamCarriesKeys(t *testing.T) {
	dir := t.TempDir()
	agent, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := identity.MarshalKEL(agent.KEL())
	source := &fakeDirectory{cards: []FedCardView{{
		Card: signedCardFor(t, agent, "Keyed", []string{"x.y"}), KEL: kel,
		Keys: []byte("signed-key-set"), FedSeq: 3,
	}, {
		Card: signedCardFor(t, agent, "Keyless", []string{"x.y"}), KEL: kel, FedSeq: 4,
	}}}
	svcA := newDiscoveryService(t, filepath.Join(dir, "a"), Config{
		Discovery: "allowlist", Home: "https://hub-a.example",
		Peers: []Peer{{AID: "did:anet:b", Endpoint: "http://unused"}},
	}, source)
	srvA := httptest.NewServer(svcA.Handler())
	defer srvA.Close()

	// The wire field.
	resp, err := http.Get(srvA.URL + "/fed/v1/cards")
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Cards []map[string]any `json:"cards"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&page)
	resp.Body.Close()
	if len(page.Cards) != 2 || page.Cards[0]["keys"] != base64.StdEncoding.EncodeToString([]byte("signed-key-set")) {
		t.Fatalf("the first entry does not carry its keys: %v", page.Cards)
	}
	if _, has := page.Cards[1]["keys"]; has {
		t.Errorf("an entry without keys carries a keys field: %v", page.Cards[1])
	}

	sink := &fakeDirectory{}
	svcB := newDiscoveryService(t, filepath.Join(dir, "b"), Config{
		Discovery: "allowlist", Home: "https://hub-b.example",
		Peers: []Peer{{AID: "did:anet:a", Endpoint: srvA.URL}},
	}, sink)
	if admitted, _ := svcB.SyncOnce(context.Background()); admitted != 2 {
		t.Fatalf("admitted %d", admitted)
	}
	if string(sink.got[0].keys) != "signed-key-set" || sink.got[1].keys != nil {
		t.Fatalf("keys handed to the kernel: %q, %q", sink.got[0].keys, sink.got[1].keys)
	}
}
