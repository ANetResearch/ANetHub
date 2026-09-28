package federation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Fuzz targets for the federation plane's inbound routes (ANet
// docs/notes/0033-验证-模糊测试-hub.md). As in the kernel's targets, a
// fuzz input carries terms and the harness signs at run time, so the
// fuzzer mutates what a peer could send rather than signatures.

// fuzzFed is hub B receiving from peer A, served in process.
type fuzzFed struct {
	b        *Service
	h        http.Handler
	a        *hubid.Identity
	bid      *hubid.Identity
	stranger *hubid.Identity
	local    *fakeLocal
	keys     *fakeKeys
	n        atomic.Uint64
}

func newFuzzFed(tb testing.TB) *fuzzFed {
	tb.Helper()
	dirA, dirB := tb.TempDir(), tb.TempDir()
	idA, err := hubid.LoadOrIncept(dirA)
	if err != nil {
		tb.Fatal(err)
	}
	idB, err := hubid.LoadOrIncept(dirB)
	if err != nil {
		tb.Fatal(err)
	}
	stranger, err := hubid.LoadOrIncept(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	muxA := http.NewServeMux()
	muxA.Handle("/hub/identity", idA.Handler())
	aSrv := httptest.NewServer(muxA)
	tb.Cleanup(aSrv.Close)
	local := newFakeLocal("aid:bob", "aid:carol")
	b, err := New(dirB, Config{Delivery: "allowlist", Discovery: "allowlist",
		Peers: []Peer{{AID: idA.AID, Endpoint: aSrv.URL}}}, idB, local)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = b.Close() })
	keys := &fakeKeys{sets: map[string][2][]byte{"aid:bob": {[]byte("keyset"), []byte("kel")}}}
	b.SetKeySource(keys)
	b.SetDirectory(&fakeDirectory{})
	// Every fuzzed request signed by A is a new signature; the default
	// bound would turn the end of a long run into 503s.
	b.replay.max = 1 << 30
	// Pin A's KEL now, so no fuzz input waits on a fetch.
	if _, err := b.peerKEL(b.peer(idA.AID)); err != nil {
		tb.Fatal(err)
	}
	return &fuzzFed{b: b, h: b.Handler(), a: idA, bid: idB, stranger: stranger, local: local, keys: keys}
}

func (f *fuzzFed) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// FuzzFedForward posts /fed/v1/forward envelopes built from fuzzed fields
// (version, origin, destination, payload, payload CID, hop, seen hubs,
// time) and signed by the peer, by a stranger, or not at all, optionally
// changed after signing. Properties:
//
//   - the answer is 200, 202, 400, 401, 403, 404 or 413, never a 5xx;
//   - 202 only for a version-2 envelope from the configured peer, signed
//     by it over exactly what arrived, within the hop limit, not through
//     this hub already, whose payload hashes to its CID and parses as a
//     sealed envelope to a destination registered here; the mailbox then
//     holds exactly that payload, once;
//   - 200 (DUPLICATE) only for a payload CID accepted before.
func FuzzFedForward(f *testing.F) {
	ff := newFuzzFed(f)
	good, err := (&seal.SealedEnvelope{V: seal.EnvelopeVersion, To: "aid:bob", Suite: seal.SuiteX25519,
		KID: bytes.Repeat([]byte{7}, seal.KIDLen), Enc: bytes.Repeat([]byte{9}, 32), CT: []byte("hello")}).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(1), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(1), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(1), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(2), "aid:nobody", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", []byte("plaintext"), uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(1), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(9), "", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "self", int64(0), uint8(0), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(1), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(2), uint8(0), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(1), []byte(nil))
	f.Add(uint64(2), uint8(0), uint8(0), "", good, uint8(0), uint64(1), "", int64(0), uint8(0), uint8(0), []byte(`{"v":2}`))

	f.Fuzz(func(t *testing.T, v uint64, originSel, destSel uint8, destRaw string, payload []byte, cidMode uint8,
		hop uint64, seen string, tsDelta int64, sigMode, after uint8, raw []byte) {
		destRaw, seen, payload, raw = clip(destRaw, 256), clip(seen, 1024), clipB(payload, 64<<10), clipB(raw, 64<<10)
		destRaw, seen = strings.ToValidUTF8(destRaw, "?"), strings.ToValidUTF8(seen, "?")
		// A fresh payload each time unless the input asks for a repeat,
		// so DUPLICATE is not the only answer the fuzzer ever sees.
		if cidMode%4 != 3 && len(payload) > 0 {
			if o, err := seal.ParseOuter(payload); err == nil {
				o.CT = append(append([]byte(nil), o.CT...), []byte(strconv.FormatUint(ff.n.Add(1), 10))...)
				if b, err := o.Marshal(); err == nil {
					payload = b
				}
			}
		}
		origin := ff.a.AID
		switch originSel % 3 {
		case 1:
			origin = ff.stranger.AID
		case 2:
			origin = ff.bid.AID
		}
		dest := "aid:bob"
		switch destSel % 3 {
		case 1:
			dest = "aid:carol"
		case 2:
			dest = destRaw
		}
		cid, _ := sumRawForTest(payload)
		env := Envelope{V: v, OriginHubAID: origin, DestAID: dest,
			Payload: base64.StdEncoding.EncodeToString(payload), PayloadCID: cid, Hop: hop,
			TS: uint64(time.Now().UnixMilli() + tsDelta%(365*86_400_000))}
		if cidMode%4 == 1 {
			env.PayloadCID = cid + "x"
		}
		if seen != "" {
			for _, s := range strings.Split(seen, ",") {
				if s == "self" {
					s = ff.bid.AID
				}
				env.SeenHubs = append(env.SeenHubs, s)
			}
		}
		signer := ff.a
		if sigMode%3 == 1 {
			signer = ff.stranger
		}
		if sigMode%3 != 2 {
			pre, err := env.preimage(payload)
			if err != nil {
				t.Skip()
			}
			sig, seq := signer.Sign(pre)
			env.Sig, env.KeyStateSeq = base64.StdEncoding.EncodeToString(sig), seq
		} else {
			env.Sig = base64.StdEncoding.EncodeToString(raw)
		}
		changed := false
		switch after % 5 {
		case 1:
			env.DestAID += "x"
			changed = true
		case 2:
			env.Hop++
			changed = true
		case 3:
			env.TS++
			changed = true
		case 4:
			env.KeyStateSeq++
			changed = true
		}
		body, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 0 && sigMode%3 == 0 && after%5 == 0 && cidMode%4 == 2 {
			body = raw
		}
		before := len(ff.local.delivered())
		rec := ff.serve(httptest.NewRequest(http.MethodPost, "/fed/v1/forward", bytes.NewReader(body)))
		delivered := ff.local.delivered()
		if !allowed(rec.Code, 200, 202, 400, 401, 403, 404, 413) {
			t.Fatalf("forward: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		if rec.Code != http.StatusAccepted {
			if len(delivered) != before {
				t.Fatalf("a forward answered %d delivered something", rec.Code)
			}
			return
		}
		var sent Envelope
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Fatalf("an undecodable forward was accepted: %v", err)
		}
		p, _ := base64.StdEncoding.DecodeString(sent.Payload)
		o, perr := seal.ParseOuter(p)
		gotCID, _ := sumRawForTest(p)
		switch {
		case sent.V != ForwardVersion || sent.OriginHubAID != ff.a.AID:
			t.Fatalf("accepted a forward of version %d from %s", sent.V, sent.OriginHubAID)
		case sigMode%3 != 0 || changed:
			t.Fatalf("accepted a forward not signed by the peer over what arrived (sig %d, changed %v)", sigMode, changed)
		case sent.Hop > MaxHop:
			t.Fatalf("accepted a forward at hop %d", sent.Hop)
		case gotCID != sent.PayloadCID:
			t.Fatalf("accepted a forward whose payload does not hash to its CID")
		case perr != nil || o.To != sent.DestAID || !ff.local.HasAgent(sent.DestAID):
			t.Fatalf("accepted a forward to %s whose payload is not an envelope for it: %v", sent.DestAID, perr)
		case len(delivered) != before+1 || delivered[len(delivered)-1] != string(p):
			t.Fatalf("an accepted forward did not deliver its payload once")
		}
		for _, s := range sent.SeenHubs {
			if s == ff.bid.AID {
				t.Fatalf("accepted a forward that already passed through this hub")
			}
		}
	})
}

// FuzzFedKeysAndStreams fuzzes the signed key lookup GET
// /fed/v2/keys/{aid} (headers tampered after signing, signed time
// anywhere in a wide window) and the cursor of the three unauthenticated
// streams. Properties: the answers are in the expected sets; a key set is
// served only to a request the configured peer signed for exactly that
// target inside the skew window, once; a correctly signed request inside
// the window is not refused as unauthenticated.
func FuzzFedKeysAndStreams(f *testing.F) {
	ff := newFuzzFed(f)
	f.Add("aid:bob", uint8(0), int64(0), "", "", "0")
	f.Add("aid:nobody", uint8(0), int64(0), "", "", "-1")
	f.Add("aid:bob", uint8(1), int64(0), "x", "", "9223372036854775807")
	f.Add("aid:bob", uint8(2), int64(0), "", "1", "99999999999999999999")
	f.Add("aid:bob", uint8(4), int64(0), "", "", "abc")
	f.Add("aid:bob", uint8(8), int64(0), "", "", "")
	f.Add("aid:bob", uint8(16), int64(0), "", "", "1e3")
	f.Add("aid:bob", uint8(0), int64(relayauth.MaxSkewMillis+60_000), "", "", "")
	f.Add("aid:bob", uint8(32), int64(0), "", "", "")

	f.Fuzz(func(t *testing.T, aid string, tamper uint8, skew int64, aidStr, tsStr, cursor string) {
		aid, aidStr, tsStr, cursor = clip(aid, 256), clip(aidStr, 256), clip(tsStr, 64), clip(cursor, 64)
		skew %= 2*relayauth.MaxSkewMillis + 60_000
		ts := uint64(time.Now().UnixMilli() + skew)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = "/fed/v2/keys/" + aid
		req.URL.RawQuery = "n=" + strconv.FormatUint(ff.n.Add(1), 10)
		req.RequestURI = req.URL.RequestURI()
		signer := ff.a
		if tamper&32 != 0 {
			signer = ff.stranger
		}
		target := req.URL.RequestURI()
		if tamper&16 != 0 {
			target += "&x"
		}
		sig, seq := signer.Sign(relayauth.PreimageV2(actionFedKeys, ff.a.AID, ff.bid.AID, ts, http.MethodGet, target, nil))
		req.Header.Set(relayauth.HeaderAID, ff.a.AID)
		req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		tampered := tamper&(16|32) != 0
		if tamper&1 != 0 {
			req.Header.Set(relayauth.HeaderAID, aidStr)
			tampered = tampered || aidStr != ff.a.AID
		}
		if tamper&2 != 0 {
			req.Header.Set(relayauth.HeaderTS, tsStr)
			tampered = tampered || tsStr != strconv.FormatUint(ts, 10)
		}
		if tamper&4 != 0 {
			req.Header.Add(relayauth.HeaderSig, "x")
			tampered = true
		}
		if tamper&8 != 0 {
			req.Header.Del(relayauth.HeaderSeq)
			tampered = true
		}
		rec := ff.serve(req)
		if !allowed(rec.Code, 200, 301, 307, 400, 401, 403, 404) {
			t.Fatalf("keys: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		inWindow := skew > -relayauth.MaxSkewMillis+5_000 && skew < relayauth.MaxSkewMillis-5_000
		outWindow := skew < -relayauth.MaxSkewMillis-5_000 || skew > relayauth.MaxSkewMillis+5_000
		switch {
		case rec.Code == http.StatusOK && (tampered || outWindow):
			t.Fatalf("keys served to a request that was tampered (%08b) or signed %d ms off", tamper, skew)
		case rec.Code == http.StatusOK && aid != "aid:bob":
			t.Fatalf("keys served for %q, which has none", aid)
		case !tampered && inWindow && rec.Code == http.StatusUnauthorized:
			t.Fatalf("a correctly signed request inside the window was refused: %s", rec.Body.Bytes())
		}
		for _, path := range []string{"/fed/v1/cards", "/fed/v1/reviews", "/fed/v2/cards"} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.URL.Path = path
			req.URL.RawQuery = "cursor=" + cursor
			rec := ff.serve(req)
			if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) {
				t.Fatalf("%s?cursor=%q: %d %s", path, cursor, rec.Code, rec.Body.Bytes())
			}
		}
	})
}

// allowed reports whether code is one of set.
func allowed(code int, set ...int) bool {
	for _, c := range set {
		if code == c {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func clipB(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
