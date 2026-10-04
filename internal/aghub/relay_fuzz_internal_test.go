package aghub

// Fuzz targets of the wire-3 relay (sealed-sender §4.2.1, §4.2.3): the
// X-ANet-Access decoder against seal's own reading of outer key 7, the whole
// of /relay/send, and /relay/session.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// FuzzAccessHeader: decodeAccessHeader (step 1) accepts exactly the
// canonical encodings of the accesses seal.ParseOuter (step 4) accepts as
// outer key 7, and reads them the same. So a header step 1 lets through is
// refused at step 4 only for not being the body's key 7, never for being
// read otherwise.
func FuzzAccessHeader(f *testing.F) {
	sig := bytes.Repeat([]byte{1}, 64)
	for _, v := range []any{
		map[uint64]any{1: uint64(0)},
		map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("body"), 2: sig}, 3: sig},
		map[uint64]any{1: uint64(2)},
		map[uint64]any{1: uint64(0), 3: sig},
		map[uint64]any{1: uint64(1), 2: map[uint64]any{1: []byte("body"), 2: sig}},
	} {
		b, _ := coredet.Marshal(v)
		f.Add(b)
	}
	f.Add([]byte{0xf6})
	f.Add([]byte{0xa1, 0x01, 0x18, 0x00})
	head := func(raw cbor.RawMessage) []byte {
		enc := func(v any) cbor.RawMessage { b, _ := coredet.Marshal(v); return b }
		env, err := coredet.Marshal(map[uint64]cbor.RawMessage{1: enc(uint64(2)), 2: enc("bafy"), 3: enc(uint64(1)),
			4: enc(bytes.Repeat([]byte{7}, 16)), 5: enc(bytes.Repeat([]byte{9}, 32)), 6: enc([]byte("ct")), 7: raw})
		if err != nil {
			return nil
		}
		return env
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := decodeAccessHeader(raw)
		env := head(raw)
		var outer *seal.SealedEnvelope
		var perr error = errNotCBOR
		if env != nil {
			outer, perr = seal.ParseOuter(env)
		}
		if err == nil {
			if perr != nil {
				t.Fatalf("step 1 took %x, seal refuses it as key 7: %v", raw, perr)
			}
			back, _ := coredet.Marshal(outer.Access)
			if !bytes.Equal(back, raw) {
				t.Fatalf("seal reads %x as %x", raw, back)
			}
			if a.Kind != outer.Access.Kind {
				t.Fatalf("kind %d against seal's %d", a.Kind, outer.Access.Kind)
			}
			return
		}
		if perr == nil {
			if back, _ := coredet.Marshal(outer.Access); bytes.Equal(back, raw) {
				t.Fatalf("seal takes the canonical %x as key 7, step 1 refuses it: %v", raw, err)
			}
		}
	})
}

var errNotCBOR = errorString("not CBOR")

type errorString string

func (e errorString) Error() string { return string(e) }

// relayCounts is what a refused send must leave as it was: the relay rows
// and the redelivery counts.
func relayCounts(t testing.TB, h *relayHub) [4]int64 {
	var out [4]int64
	if err := h.store.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size),0) FROM relay_message`).Scan(&out[0], &out[1]); err != nil {
		t.Fatal(err)
	}
	if err := h.store.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(count),0) FROM relay_redelivery`).Scan(&out[2], &out[3]); err != nil {
		t.Fatal(err)
	}
	return out
}

// FuzzRelaySendV3 sends fuzzed envelopes and headers as first contacts
// (with a good session MAC over whatever the body is), under a delivery
// credential (with a good proof when the body is an envelope), or as they
// come, with headers added by the flags. Properties:
//
//   - the answer is 200 or one of the relay's refusals, never a 5xx, and an
//     error keeps the wire-3 contract (G1);
//   - 200 only for an envelope that seal.ParseOuter takes, whose outer key 7
//     is the header's bytes, addressed to an agent registered here; the
//     mailbox then holds exactly those bytes under the answered rid;
//   - a refusal writes no row and no count, and takes no token, but for a
//     403, which takes exactly one from the address bucket;
//   - every 403 is the same bytes.
func FuzzRelaySendV3(f *testing.F) {
	sc := newScene(f)
	h := sc.h
	opened := h.clock()
	good := sc.env()
	f.Add(uint8(0), uint8(0), good, []byte(nil))
	f.Add(uint8(1), uint8(0), good, []byte(nil))
	f.Add(uint8(1), uint8(0), envelope(f, sc.sender.aid, []byte("to the sender")), []byte(nil))
	f.Add(uint8(2), uint8(0), withCap(f, good, sc.stranger), accessRaw(f, withCap(f, good, sc.stranger)))
	f.Add(uint8(0), uint8(1), good, []byte(nil))
	f.Add(uint8(0), uint8(2), good, []byte(nil))
	f.Add(uint8(1), uint8(4), good, []byte(nil))
	f.Add(uint8(0), uint8(0), []byte("plaintext"), []byte{0xa1, 0x01, 0x00})
	f.Add(uint8(2), uint8(0), []byte{0xa0}, []byte{0xa1, 0x01, 0x02})
	var refusal403 []byte
	f.Fuzz(func(t *testing.T, mode, flags uint8, body, access []byte) {
		if len(body) > 64<<10 || len(access) > 2<<10 {
			return
		}
		h.t = t // the fixture reports to this input's test
		h.advance(5 * time.Second)
		if h.clock().Sub(opened) > 50*time.Minute {
			sc.ss, opened = h.openSession(sc.sender.c), h.clock()
		}
		var req *http.Request
		switch mode % 3 {
		case 0:
			req = h.kind0Request(sc.ss, body, kind0Opts{})
			if len(access) > 0 {
				req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(access))
			}
		case 1:
			if _, err := seal.ParseOuter(body); err == nil {
				g := sc.contact
				if flags&8 != 0 {
					g = sc.stranger
				}
				body = withCap(t, body, g)
			}
			req = kind1Request(t, body)
		default:
			req = kind1Request(t, body)
			req.Header.Set(HeaderAccess, base64.RawURLEncoding.EncodeToString(access))
		}
		if flags&1 != 0 {
			req.Header.Set(relayauth.HeaderAID, sc.sender.aid)
		}
		if flags&2 != 0 {
			req.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(sc.ss.sid))
		}
		if flags&4 != 0 {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		ip := "192.0.2.9"
		if flags&16 != 0 {
			ip = "192.0.2.10"
		}
		hdr, _ := base64.RawURLEncoding.DecodeString(req.Header.Get(HeaderAccess))
		before, beforeBuckets := relayCounts(t, h), h.buckets()
		rec := h.serve(req, ip)
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Fatalf("%s: %s", p, rec.Body)
		}
		switch rec.Code {
		case 200, 400, 401, 403, 404, 413, 429, 507:
		default:
			t.Fatalf("answered %d %s", rec.Code, rec.Body)
		}
		if rec.Code == http.StatusOK {
			outer, err := seal.ParseOuter(body)
			if err != nil {
				t.Fatalf("queued a body seal refuses: %v", err)
			}
			if !sameOuterAccess(body, hdr) {
				t.Fatal("queued an envelope whose key 7 is not the header")
			}
			if outer.To != sc.recip.aid && outer.To != sc.sender.aid {
				t.Fatalf("queued for %q, registered nowhere here", outer.To)
			}
			var out RelaySendResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			var payload []byte
			rid, _ := base64.RawURLEncoding.DecodeString(out.RID)
			if err := h.store.db.QueryRow(`SELECT payload FROM relay_message WHERE rid=?`, rid).Scan(&payload); err != nil {
				t.Fatalf("no row under the answered rid: %v", err)
			}
			if out.Status == RelayDuplicate {
				// The first copy's bytes: the same envelope, perhaps
				// under another access (env_digest leaves key 7 out).
				d1, _ := seal.EnvDigest(payload)
				d2, _ := seal.EnvDigest(body)
				if d1 != d2 {
					t.Fatal("a duplicate names a row of another envelope")
				}
			} else if !bytes.Equal(payload, body) {
				t.Fatal("the row holds other bytes than were sent")
			}
			if n := relayCounts(t, h); n[0] > 3000 {
				_, _ = h.store.db.Exec(`DELETE FROM relay_message`)
			}
			return
		}
		if after := relayCounts(t, h); after != before {
			t.Fatalf("a refusal (%d %s) changed the relay tables: %v -> %v", rec.Code, rec.Body, before, after)
		}
		afterBuckets := h.buckets()
		if rec.Code == http.StatusForbidden {
			k := "addr|" + rateKeyOfString(ip)
			was, ok := beforeBuckets[k]
			if !ok {
				was = rateAddrFailure.burst
			}
			beforeBuckets[k] = was - 1
			if refusal403 == nil {
				refusal403 = append([]byte(nil), rec.Body.Bytes()...)
			} else if !bytes.Equal(refusal403, rec.Body.Bytes()) {
				t.Fatalf("403 bodies differ: %s vs %s", rec.Body, refusal403)
			}
		}
		if d := (effects{buckets: beforeBuckets}).diff(effects{buckets: afterBuckets}); d != "" {
			t.Fatalf("a refusal (%d %s) took a token: %s", rec.Code, rec.Body, d)
		}
	})
}

// FuzzRelaySession opens sessions with fuzzed bodies, signed by a
// registered agent. Properties: 200 exactly for a body that is {epk} with a
// 32-byte base64url key a session key can be sealed to; a 200 names a
// 16-byte sid, an exp an hour on and an enc of 32 bytes; anything else is a
// 400 that opens no session and counts no opening; no AID ever holds more
// than MaxSessionsPerAID sessions.
func FuzzRelaySession(f *testing.F) {
	h := newRelayHub(f)
	a := h.agent()
	_, epk, _ := relayauth.NewSessionKey()
	f.Add([]byte(`{"epk":"` + base64.RawURLEncoding.EncodeToString(epk) + `"}`))
	f.Add([]byte(`{"epk":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`))
	f.Add([]byte(`{"epk":"` + base64.URLEncoding.EncodeToString(epk) + `"}`))
	f.Add([]byte(`{"epk":"` + base64.RawURLEncoding.EncodeToString(epk) + `","x":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > sessionBodyLimit {
			return
		}
		h.t = t // the fixture reports to this input's test
		// Slower than the hourly bound, so it never refuses.
		h.advance(3 * time.Minute)
		opensBefore := func() int {
			h.srv.relay.sessions.mu.Lock()
			defer h.srv.relay.sessions.mu.Unlock()
			return len(h.srv.relay.sessions.recentOpensLocked(a.aid, h.clock()))
		}()
		rec := h.serve(h.signed(a.c, relayauth.ActionSession, http.MethodPost, "/relay/session", body), relayClientIP)
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Fatalf("%s: %s", p, rec.Body)
		}
		var req SessionRequest
		strict := wire3StrictDecode(body, &req) == nil
		key, kerr := wire3.DecodeB64URLSize("epk", req.EPK, 32)
		usable := false
		if strict && kerr == nil {
			_, _, serr := relayauth.SealSessionKey(key, h.hubAID, make([]byte, 16), make([]byte, 32))
			usable = serr == nil
		}
		opensAfter := func() int {
			h.srv.relay.sessions.mu.Lock()
			defer h.srv.relay.sessions.mu.Unlock()
			return len(h.srv.relay.sessions.recentOpensLocked(a.aid, h.clock()))
		}()
		switch rec.Code {
		case http.StatusOK:
			if !usable {
				t.Fatalf("opened a session for %q", body)
			}
			var out SessionResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			sid, _ := base64.RawURLEncoding.DecodeString(out.SID)
			enc, _ := base64.RawURLEncoding.DecodeString(out.Enc)
			if len(sid) != 16 || len(enc) != 32 || out.Exp != uint64(h.clock().Add(SessionLifetime).UnixMilli()) {
				t.Fatalf("a session answer: %s", rec.Body)
			}
			if opensAfter != opensBefore+1 {
				t.Fatalf("openings %d -> %d", opensBefore, opensAfter)
			}
		case http.StatusBadRequest:
			if usable {
				t.Fatalf("refused a usable key: %s", rec.Body)
			}
			if opensAfter != opensBefore {
				t.Fatal("a refused body counted as an opening")
			}
		default:
			t.Fatalf("answered %d %s", rec.Code, rec.Body)
		}
		if n := h.srv.relay.sessions.count(a.aid, h.clock()); n > MaxSessionsPerAID {
			t.Fatalf("%d sessions held", n)
		}
	})
}
