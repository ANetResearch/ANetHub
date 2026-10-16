package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// A hub served in process, for the tests of what the operator's delete does to the hub: its data
// directory, the store the hub process holds, and its HTTP surface. It signs as the conformance hub
// identity (identity.SuiteController), which the agents of newTestAgent name as their witness, so it
// takes their registrations (KEL H-1). Requests are signed the way a daemon signs them (relayauth v2,
// one signing time per request, always later than the last).

type testHub struct {
	t      *testing.T
	dir    string
	store  *aghub.Store
	srv    *httptest.Server
	hubAID string
}

func newTestHub(t *testing.T, mode string) *testHub {
	t.Helper()
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctrl := identity.SuiteController()
	store.SetHubKey(ctrl)
	if err := store.SetAdmissionMode(mode); err != nil {
		t.Fatal(err)
	}
	s := aghub.NewServer(store)
	s.SetHubAID(ctrl.AID())
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	return &testHub{t: t, dir: dir, store: store, srv: srv, hubAID: ctrl.AID()}
}

// admin is the operator plane on this hub's data directory, served in process.
func (h *testHub) admin() (http.Handler, *Store, *HubDB) {
	h.t.Helper()
	store, err := OpenStore(h.t.TempDir())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { store.Close() })
	hub, err := OpenHubDB(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { hub.Close() })
	return NewServer(store, hub, nil, NewVecClient(""), "test-token", "/admin").Handler(), store, hub
}

// lastKELTime is the last key event time kelTime handed out.
var lastKELTime atomic.Uint64

// kelTime is a time for a key event made now, after every one made before (each event of a key
// history is later than the one before it).
func kelTime() uint64 {
	for {
		last := lastKELTime.Load()
		ts := uint64(time.Now().UnixMilli())
		if ts <= last {
			ts = last + 1
		}
		if lastKELTime.CompareAndSwap(last, ts) {
			return ts
		}
	}
}

// newTestAgent is a new agent whose first rotation names the test hubs' identity as its witness
// (identitytest.Witness): icp and one rot.
func newTestAgent(t *testing.T) *identity.Controller {
	t.Helper()
	c, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.SwitchWitness(c, identitytest.Witness, kelTime()); err != nil {
		t.Fatal(err)
	}
	return c
}

// rotate makes one more planned rotation of c.
func rotate(t *testing.T, c *identity.Controller) {
	t.Helper()
	if err := identitytest.Rotate(c, kelTime()); err != nil {
		t.Fatal(err)
	}
}

// kelBytes is c's key history, encoded as a hub stores it.
func kelBytes(t *testing.T, c *identity.Controller) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tipID is the event id of the last event of c's key history.
func tipID(c *identity.Controller) string {
	kel := c.KEL()
	return kel[len(kel)-1].EventID
}

// lastSigned is the signing time of the last request these helpers signed.
var lastSigned atomic.Int64

// signingNow is a signing time after every one handed out before: a hub takes each of a signer's
// times once (RC1).
func signingNow() uint64 {
	for {
		last := lastSigned.Load()
		now := time.Now().UnixMilli()
		if now <= last {
			now = last + 1
		}
		if lastSigned.CompareAndSwap(last, now) {
			return uint64(now)
		}
	}
}

// signed sends a request to the hub signed by signer for action, with body.
func (h *testHub) signed(signer *identity.Controller, action, method, path string, body []byte) (int, map[string]any) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ANet-Wire", strconv.Itoa(aghub.WireVersion))
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	ts := signingNow()
	sig, seq := signer.Sign(relayauth.PreimageV2(action, signer.AID(), h.hubAID, ts, method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, signer.AID())
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["_raw"] = string(raw)
	return resp.StatusCode, out
}

// register sends c's registration (its key history as it stands), signed by c, with extra members
// (a proof of work).
func (h *testHub) register(c *identity.Controller, extra map[string]any) (int, map[string]any) {
	h.t.Helper()
	body := map[string]any{"aid": c.AID(), "name": "operator-test", "caps": []string{"work.do"},
		"kel": base64.RawURLEncoding.EncodeToString(kelBytes(h.t, c))}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return h.signed(c, relayauth.ActionRegister, http.MethodPost, "/register", raw)
}

// pow answers the hub's pow_required challenge for aid: it asks the hub (a registration without a
// proof of work), solves what it is told, and returns the member to register with. A proof of work
// is bound to the hub, the AID and the hour's seed, not to the key history, so one serves every
// registration of aid within the hour.
func (h *testHub) pow(c *identity.Controller) map[string]any {
	h.t.Helper()
	code, out := h.register(c, nil)
	if code != http.StatusForbidden || out["reason"] != "pow_required" {
		h.t.Fatalf("asking for the proof of work: %d %s", code, out["_raw"])
	}
	ch, _ := out["challenge"].(map[string]any)
	seedB, err := base64.RawURLEncoding.DecodeString(ch["seed"].(string))
	if err != nil || len(seedB) != 32 {
		h.t.Fatalf("the challenge's seed: %v", ch)
	}
	var seed [32]byte
	copy(seed[:], seedB)
	bits := int(ch["bits"].(float64))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	nonce, err := regpow.Solve(ctx, h.hubAID, c.AID(), seed, bits)
	if err != nil {
		h.t.Fatal(err)
	}
	return map[string]any{"pow": map[string]any{
		"seed": ch["seed"], "nonce": base64.RawURLEncoding.EncodeToString(nonce)}}
}

// noticeHeads is the head of every witness notice the hub keeps cached.
func (h *testHub) noticeHeads() []string {
	h.t.Helper()
	db := openRaw(h.t, h.dir)
	rows, err := db.Query(`SELECT head FROM notice_cache`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}
