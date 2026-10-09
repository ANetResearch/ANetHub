package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// ---- relayauth v2 on every signed route ----

// authRoute is one signed endpoint as the fuzzer reaches it.
type authRoute struct {
	method, action string
	path           func(aid string) string
}

var authRoutes = []authRoute{
	{http.MethodPost, relayauth.ActionPoll, func(string) string { return "/relay/poll" }},
	{http.MethodPost, relayauth.ActionAck, func(string) string { return "/relay/ack" }},
	{http.MethodPost, relayauth.ActionSession, func(string) string { return "/relay/session" }},
	{http.MethodPost, relayauth.ActionProfile, func(string) string { return "/profile" }},
	{http.MethodPost, relayauth.ActionKeys, func(a string) string { return "/agents/" + a + "/keys" }},
	{http.MethodGet, relayauth.ActionBalance, func(a string) string { return "/agents/" + a + "/balance" }},
	{http.MethodGet, relayauth.ActionLedger, func(a string) string { return "/agents/" + a + "/ledger" }},
	{http.MethodGet, relayauth.ActionRedemptions, func(a string) string { return "/agents/" + a + "/redemptions" }},
	{http.MethodPost, relayauth.ActionVisibility, func(a string) string { return "/agents/" + a + "/visibility" }},
}

// Tamper bits of FuzzHubRelayAuthV2.
const (
	tbAID    = 1 << iota // X-ANet-AID replaced
	tbTS                 // X-ANet-TS replaced
	tbSeq                // X-ANet-Seq replaced
	tbSig                // X-ANet-Sig replaced
	tbBody               // one body bit flipped after signing
	tbDup                // a header sent twice
	tbTarget             // signed for another request target
	tbAction             // signed for another action
)

// FuzzHubRelayAuthV2 signs a request to one of the signed routes, tampers
// with it as the input says, and checks the one property the scheme
// exists for: a request whose headers, body, target or action differ from
// what was signed is refused, and one that does not is accepted exactly
// when its time is inside the window and above every time signed for the
// signer before (RC1, hub-payment-privacy §4.2.5).
//
// "Accepted" means the answer is not the authentication refusal (401).
// The handlers may still refuse the body (400) or the state (404, 409).
//
// One signer signs every input, at the time the input says, so RC1 may
// refuse a correctly signed request inside the window: as replayed when
// an earlier input had the same time, as ts_stale when an earlier one was
// later. Either says so by its reason, and ts_stale names a floor at or
// above the time. A refused tampered request is unauthorized, never
// ts_stale or replayed, and carries no floor (PAY-R8).
//
// A replaced header that contains U+0000 never reaches the signature
// check: the wire-3 contract refuses it first as bad_request (core
// CORE-E9), so such a request must be answered 400 bad_request instead.
func FuzzHubRelayAuthV2(f *testing.F) {
	h := newFZ(f)
	a, _ := h.agent(f, "fuzz-auth", []string{"fuzz.auth"}, true)
	aKEL, _ := identity.MarshalKEL(a.KEL())
	_ = aKEL

	env := base64.StdEncoding.EncodeToString(fzEnvelope(f, a.AID(), nil))
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"limit":5,"after_id":0}`),
		[]byte(`{"ids":[1,2,3]}`),
		[]byte(`{"to_aid":"` + a.AID() + `","envelope":"` + env + `"}`),
		[]byte(`{"summary":"s","readme":"r","pricing":"p"}`),
		[]byte(`{"visibility":"hub-local"}`),
		[]byte(`{"addr":"/ip4/127.0.0.1/tcp/4001"}`),
		nil,
	}
	for i, b := range seeds {
		for _, tamper := range []uint8{0, tbAID, tbTS, tbSig, tbBody, tbDup, tbTarget, tbAction} {
			f.Add(uint8(i), b, tamper, "bafyreib", int64(0), "1", "0", "AAAA", uint16(3))
		}
	}
	f.Add(uint8(0), []byte(`{}`), uint8(0), "", int64(-relayauth.MaxSkewMillis-10_000), "", "", "", uint16(0))
	f.Add(uint8(5), []byte(nil), uint8(0), "", int64(relayauth.MaxSkewMillis+10_000), "", "", "", uint16(0))
	f.Add(uint8(0), []byte(`{}`), uint8(tbTS), "", int64(0), "18446744073709551615", "", "", uint16(0))

	f.Fuzz(func(t *testing.T, route uint8, body []byte, tamper uint8, aidStr string, skew int64,
		tsStr, seqStr, sigStr string, flip uint16) {
		body = clipB(body, 8<<10)
		rt := authRoutes[int(route)%len(authRoutes)]
		path := rt.path(a.AID())
		query := "fz=" + h.nonce()
		// skew spans a little over twice the window either side, so the
		// window's edges are inside the range the fuzzer explores.
		skew %= 2*relayauth.MaxSkewMillis + 60_000
		now := time.Now().UnixMilli()
		ts := uint64(now + skew)
		// Above everything signed for a before (and after the hub's RC1
		// state was made): RC1 has nothing to refuse it for.
		fresh := ts > h.lastSigned(a.AID()) && ts >= h.started

		signedQuery, signedAction := query, rt.action
		if tamper&tbTarget != 0 {
			signedQuery = query + "&x=1"
		}
		if tamper&tbAction != 0 {
			signedAction = rt.action + "x"
		}
		req := h.request(rt.method, path, signedQuery, body)
		h.sign(req, a, signedAction, body, ts)
		// The request is sent with the unsigned target.
		req.URL.RawQuery = query
		req.RequestURI = req.URL.RequestURI()

		tampered := tamper&(tbTarget|tbAction|tbDup) != 0
		if tamper&tbAID != 0 {
			req.Header.Set(relayauth.HeaderAID, aidStr)
			tampered = tampered || aidStr != a.AID()
		}
		if tamper&tbTS != 0 {
			req.Header.Set(relayauth.HeaderTS, tsStr)
			tampered = tampered || tsStr != strconv.FormatUint(ts, 10)
		}
		if tamper&tbSeq != 0 {
			req.Header.Set(relayauth.HeaderSeq, seqStr)
			tampered = tampered || seqStr != strconv.FormatUint(a.CurrentSeq(), 10)
		}
		if tamper&tbSig != 0 {
			old := req.Header.Get(relayauth.HeaderSig)
			req.Header.Set(relayauth.HeaderSig, sigStr)
			ob, _ := relayauth.DecodeSig(old)
			nb, err := relayauth.DecodeSig(sigStr)
			tampered = tampered || err != nil || string(ob) != string(nb)
		}
		if tamper&tbBody != 0 && len(body) > 0 {
			nb := append([]byte(nil), body...)
			nb[int(flip)%len(nb)] ^= 1 << (flip % 8)
			req = h.request(rt.method, path, query, nb)
			for k, v := range signedHeaders(t, h, a, signedAction, rt.method, path, signedQuery, body, ts) {
				req.Header[k] = v
			}
			tampered = true
		}
		if tamper&tbDup != 0 {
			req.Header.Add(relayauth.HeaderSig, req.Header.Get(relayauth.HeaderSig))
		}

		nul := wire3.CheckRequest(req) != nil
		rec := h.serve(req)
		code := rec.Code
		if !allowed(code, 200, 400, 401, 404, 409, 413, 429) {
			t.Fatalf("%s %s (tamper %08b): unexpected %d %s", rt.method, path, tamper, code, rec.Body.Bytes())
		}
		if nul {
			var refusal struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &refusal)
			if !tampered || code != http.StatusBadRequest || refusal.Reason != string(wire3.ReasonBadRequest) {
				t.Fatalf("%s %s: request with U+0000 in a header (tamper %08b, tampered %v) answered %d, not 400 bad_request: %s",
					rt.method, path, tamper, tampered, code, rec.Body.Bytes())
			}
			return
		}
		inWindow := skew > -relayauth.MaxSkewMillis+5_000 && skew < relayauth.MaxSkewMillis-5_000
		outWindow := skew < -relayauth.MaxSkewMillis-5_000 || skew > relayauth.MaxSkewMillis+5_000
		var refusal struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &refusal)
		floorHdr := rec.Header().Get("X-ANet-TS-Floor")
		rc1 := refusal.Reason == string(wire3.ReasonTSStale) || refusal.Reason == string(wire3.ReasonReplayed)
		switch {
		case tampered && code != http.StatusUnauthorized:
			t.Fatalf("%s %s: tampered request (bits %08b) answered %d, not 401: %s",
				rt.method, path, tamper, code, rec.Body.Bytes())
		case tampered && (rc1 || floorHdr != ""):
			t.Fatalf("%s %s: tampered request (bits %08b) told about RC1 (floor %q): %s",
				rt.method, path, tamper, floorHdr, rec.Body.Bytes())
		case !tampered && inWindow && code == http.StatusUnauthorized && (fresh || !rc1):
			t.Fatalf("%s %s: correctly signed request inside the window (skew %d ms, above every earlier time %v) refused: %s",
				rt.method, path, skew, fresh, rec.Body.Bytes())
		case refusal.Reason == string(wire3.ReasonTSStale) && !floorAtLeast(floorHdr, ts):
			t.Fatalf("%s %s: ts_stale for %d with the floor %q, not at or above it", rt.method, path, ts, floorHdr)
		case !tampered && outWindow && code != http.StatusUnauthorized:
			t.Fatalf("%s %s: request signed %d ms off answered %d, not 401", rt.method, path, skew, code)
		}
	})
}

// floorAtLeast reports whether hdr, an X-ANet-TS-Floor, is a number at or
// above ts.
func floorAtLeast(hdr string, ts uint64) bool {
	f, err := strconv.ParseUint(hdr, 10, 64)
	return err == nil && f >= ts
}

// signedHeaders signs a request with the given terms and returns its
// authentication headers.
func signedHeaders(t *testing.T, h *fz, c *identity.Controller, action, method, path, query string,
	body []byte, ts uint64) http.Header {
	t.Helper()
	req := h.request(method, path, query, body)
	h.sign(req, c, action, body, ts)
	out := http.Header{}
	for _, k := range []string{relayauth.HeaderAID, relayauth.HeaderTS, relayauth.HeaderSeq, relayauth.HeaderSig} {
		out[http.CanonicalHeaderKey(k)] = req.Header.Values(k)
	}
	return out
}

// ---- /relay/send ----
//
// The wire-3 send is fuzzed in the package's own tests
// (FuzzRelaySendV3, FuzzRelaySession, FuzzAccessHeader in
// relay_fuzz_internal_test.go), where the session and the credentials are
// at hand.

// polledMsg is one /relay/poll entry.
type polledMsg struct {
	ID       int64  `json:"id"`
	Envelope string `json:"envelope"`
}

// pollAll polls c's mailbox after afterID.
func pollAll(t *testing.T, h *fz, c *identity.Controller, afterID int64) []polledMsg {
	t.Helper()
	rec := h.signedDo(c, relayauth.ActionPoll, http.MethodPost, "/relay/poll", "",
		fzJSON(t, map[string]any{"after_id": afterID}))
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body.Bytes())
	}
	var out struct {
		Messages []polledMsg `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Messages
}

// ---- /relay/poll after_id and limit, /relay/ack ----

// FuzzHubRelayPollAck polls and acks with fuzzed bodies against a mailbox
// holding envelopes for the caller and for somebody else. Properties:
//
//   - poll answers 200 or 400 (400 exactly when the body does not decode
//     strictly, core CORE-E7, or after_id or limit is negative);
//   - a 200 lists only the caller's envelopes, ids strictly ascending and
//     above after_id, at most limit of them (100 when limit is not
//     positive);
//   - ack answers 200 or 400, deletes only ids in the caller's own
//     mailbox, reports exactly how many it deleted, and leaves the other
//     mailbox as it was.
func FuzzHubRelayPollAck(f *testing.F) {
	h := newFZ(f)
	me, _ := h.agent(f, "fuzz-mailbox", nil, true)
	other, _ := h.agent(f, "fuzz-other", nil, true)
	refill := func(tb testing.TB) {
		for _, c := range []*identity.Controller{me, other} {
			for n, _ := h.store.RelayPending(c.AID()); n < 8; n++ {
				if _, err := h.store.QueueEnvelope(c.AID(), fzEnvelope(tb, c.AID(), []byte(h.nonce()))); err != nil {
					tb.Fatal(err)
				}
			}
		}
	}
	refill(f)
	f.Add([]byte(`{}`), []byte(`{"ids":[]}`))
	f.Add([]byte(`{"limit":3,"after_id":2}`), []byte(`{"ids":[1,2,3]}`))
	f.Add([]byte(`{"limit":-1,"after_id":-1}`), []byte(`{"ids":[-1,0,9223372036854775807]}`))
	f.Add([]byte(`{"limit":1e3}`), []byte(`{"ids":null}`))
	f.Add([]byte(nil), []byte(`[1]`))
	f.Add([]byte(`{"after_id":9223372036854775807,"limit":2147483647}`), []byte(`{"ids":[9,9,9]}`))

	f.Fuzz(func(t *testing.T, pollBody, ackBody []byte) {
		pollBody, ackBody = clipB(pollBody, 4<<10), clipB(ackBody, 4<<10)
		refill(t)
		var preq struct {
			Limit   int   `json:"limit,omitempty"`
			AfterID int64 `json:"after_id,omitempty"`
		}
		perr := error(nil)
		if len(pollBody) > 0 {
			perr = json.Unmarshal(pollBody, &preq)
			if perr == nil {
				// The hub decodes the body strictly (core CORE-E7): a member it
				// does not take, a member given twice, U+0000 or invalid UTF-8
				// is refused although encoding/json accepts it.
				perr = wire3.DecodeStrict(pollBody, &aghub.RelayPollRequest{})
			}
		}
		rec := h.signedDo(me, relayauth.ActionPoll, http.MethodPost, "/relay/poll", "", pollBody)
		switch {
		case perr != nil || preq.AfterID < 0 || preq.Limit < 0:
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("poll %q: %d, want 400", pollBody, rec.Code)
			}
		case rec.Code != http.StatusOK:
			t.Fatalf("poll %q: %d %s", pollBody, rec.Code, rec.Body.Bytes())
		default:
			var out struct {
				Messages []polledMsg `json:"messages"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			max := preq.Limit
			if max <= 0 {
				max = 100
			}
			if len(out.Messages) > max {
				t.Fatalf("poll limit %d returned %d", preq.Limit, len(out.Messages))
			}
			last := preq.AfterID
			for _, m := range out.Messages {
				if m.ID <= last {
					t.Fatalf("poll after %d: ids not ascending above it: %+v", preq.AfterID, out.Messages)
				}
				last = m.ID
				raw, err := base64.RawURLEncoding.DecodeString(m.Envelope)
				if err != nil {
					t.Fatal(err)
				}
				if o, err := seal.ParseOuter(raw); err != nil || o.To != me.AID() {
					t.Fatalf("poll returned an envelope that is not the caller's: %v", err)
				}
			}
		}

		var areq struct {
			IDs []int64 `json:"ids"`
		}
		aerr := json.Unmarshal(ackBody, &areq)
		mine := map[int64]bool{}
		for _, m := range pollAll(t, h, me, 0) {
			mine[m.ID] = true
		}
		expect := 0
		seen := map[int64]bool{}
		for _, id := range areq.IDs {
			if mine[id] && !seen[id] {
				expect++
			}
			seen[id] = true
		}
		otherBefore, _ := h.store.RelayPending(other.AID())
		mineBefore, _ := h.store.RelayPending(me.AID())
		rec = h.signedDo(me, relayauth.ActionAck, http.MethodPost, "/relay/ack", "", ackBody)
		otherAfter, _ := h.store.RelayPending(other.AID())
		mineAfter, _ := h.store.RelayPending(me.AID())
		if otherAfter != otherBefore {
			t.Fatalf("ack %q changed another agent's mailbox: %d -> %d", ackBody, otherBefore, otherAfter)
		}
		if aerr != nil {
			if rec.Code != http.StatusBadRequest || mineAfter != mineBefore {
				t.Fatalf("ack %q: %d (mailbox %d -> %d), want 400 and nothing deleted", ackBody, rec.Code, mineBefore, mineAfter)
			}
			return
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("ack %q: %d %s", ackBody, rec.Code, rec.Body.Bytes())
		}
		var out struct {
			Acked int `json:"acked"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Acked != expect || mineBefore-mineAfter != expect {
			t.Fatalf("ack %q: reported %d, deleted %d, want %d", ackBody, out.Acked, mineBefore-mineAfter, expect)
		}
	})
}
