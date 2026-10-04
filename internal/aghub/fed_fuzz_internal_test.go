package aghub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// Fuzz targets of the kernel's half of federation v3: the three decoders
// of what a peer hub sends — a forward to this hub as the home, the answer
// of a home to a forward, a page of a peer's bucket.

// FuzzFedForwardV3 hands fuzzed forwards, signed by a peer, to the home's
// /fed/v3/forward: the envelope, X-ANet-Access, the Content-Type and a
// session header. Properties:
//
//   - the answer is a wire-3 answer and never a 5xx;
//   - a 200 queued or duplicate names a row of the relay table that holds
//     exactly the envelope, for the recipient its outer layer names, which
//     is registered here; under a credential, one that verifies under the
//     owner's mailbox key for exactly that envelope;
//   - a refusal is a G1 body.
func FuzzFedForwardV3(f *testing.F) {
	net := newFedNet(f, 2)
	a, b := net.nodes[0], net.nodes[1]
	owner := b.agent()
	g := b.issue(owner, seal.CapClassContact, 24*time.Hour)
	b64 := base64.RawURLEncoding.EncodeToString
	first := envelope(f, owner.aid, []byte("first"))
	capped := withCap(f, envelope(f, owner.aid, []byte("cap")), g)
	f.Add(first, accessRaw(f, first), true, false)
	f.Add(capped, accessRaw(f, capped), true, false)
	f.Add(capped, accessRaw(f, first), true, true)
	f.Add([]byte("not an envelope"), []byte{0xa1, 0x01, 0x00}, false, false)
	f.Fuzz(func(t *testing.T, env, access []byte, ctype, session bool) {
		a.relayHub.t, b.relayHub.t = t, t // the helpers report to this run
		b.srv.relay.fedSource.forget(a.hubAID)
		req := b.signedForwardThen(a, env, func(r *http.Request) {
			r.Header.Set(HeaderAccess, b64(access))
			if !ctype {
				r.Header.Set("Content-Type", "application/octet-stream")
			}
			if session {
				r.Header.Set(relayauth.HeaderSession, relayauth.EncodeSessionID(make([]byte, relayauth.SessionIDLen)))
			}
		}, nil)
		rec := b.fedServe(req)
		if rec.Code >= 500 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Fatalf("%s", p)
		}
		if rec.Code != http.StatusOK {
			return
		}
		var ans FedForwardResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
			t.Fatal(err)
		}
		rid, err := wire3.DecodeB64URLSize("rid", ans.RID, RIDLen)
		if err != nil {
			t.Fatalf("rid %q", ans.RID)
		}
		var to string
		var payload []byte
		if err := b.store.db.QueryRow(`SELECT to_aid, payload FROM relay_message WHERE rid=?`, rid).Scan(&to, &payload); err != nil {
			t.Fatalf("a 200 names no row: %v", err)
		}
		outer, err := seal.ParseOuter(env)
		if err != nil || !bytes.Equal(payload, env) || to != outer.To || to != owner.aid {
			t.Fatalf("the row is not the envelope forwarded: %v", err)
		}
		if outer.Access.Kind == seal.AccessKindCap {
			d, _ := seal.EnvDigest(env)
			if err := seal.VerifyAccess(outer.Access, d, owner.mbox, owner.aid, uint64(b.clock().UnixMilli())); err != nil {
				t.Fatalf("a credential that does not verify was queued: %v", err)
			}
		}
	})
}

// FuzzForwardAnswer has a home answer a forward with a fuzzed status,
// body and Retry-After, and checks the origin's answer to the sender
// (SSR-H13). Properties: it is a wire-3 answer with a G1 body for a
// refusal, never anything but 200, a status of the passed-through refusals,
// 404 recipient_unknown or 502 home_unreachable; a 200 only for a home's 200
// queued or duplicate with a 16-byte rid, with that rid and via_hub the
// home; 502 always with Retry-After.
func FuzzForwardAnswer(f *testing.F) {
	net := newFedNet(f, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	sender := a.agent()
	ss := a.openSession(sender.c)
	type answer struct {
		status int
		body   []byte
		retry  string
	}
	var cur answer
	b.mu.Lock()
	b.answer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(wire3.Header, "3")
		if cur.retry != "" {
			w.Header().Set("Retry-After", cur.retry)
		}
		w.WriteHeader(cur.status)
		_, _ = w.Write(cur.body)
	}
	b.mu.Unlock()
	rid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, RIDLen))
	f.Add(200, []byte(`{"status":"queued","rid":"`+rid+`","recipient_quiet":false}`), "")
	f.Add(429, []byte(`{"reason":"rate_limited","error":"x"}`), "9")
	f.Add(404, []byte(`{"reason":"unknown_destination","error":"x"}`), "")
	f.Add(403, []byte(`{"reason":"access_invalid","error":"x"}`), "")
	f.Add(200, []byte(`{"status":"queued","rid":"`+rid+`","recipient_quiet":false,"x":1}`), "")
	n := 0
	f.Fuzz(func(t *testing.T, status int, body []byte, retry string) {
		if status < 200 || status > 599 || status == http.StatusSwitchingProtocols {
			return
		}
		for _, c := range []byte(retry) {
			if c < 0x20 || c > 0x7e {
				return
			}
		}
		a.relayHub.t, b.relayHub.t = t, t // the helpers report to this run
		cur = answer{status, body, retry}
		a.srv.relay.sessionSend.forget(sender.aid)
		n++
		rec := a.send0(ss, envelope(t, recip.aid, []byte("fuzz "+strconv.Itoa(n))), kind0Opts{home: b.hubAID})
		for _, p := range wire3test.Contract(rec.Code, rec.Header(), rec.Body.Bytes()) {
			t.Fatalf("%s", p)
		}
		switch rec.Code {
		case 200:
			var out RelaySendResponse
			var home FedForwardResponse
			if status != 200 || wire3.DecodeStrict(body, &home) != nil || json.Unmarshal(rec.Body.Bytes(), &out) != nil ||
				out.RID != home.RID || out.ViaHub != b.hubAID || out.Status != home.Status {
				t.Fatalf("a 200 to the sender for the home's %d %q: %s", status, body, rec.Body)
			}
		case 502:
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("502 without Retry-After")
			}
		case 404:
			if reasonOf(rec) != "recipient_unknown" {
				t.Fatalf("404 %s", rec.Body)
			}
		default:
			if !passedThrough[wire3.Reason(reasonOf(rec))] || rec.Code != status {
				t.Fatalf("the origin answered %d %s for the home's %d", rec.Code, rec.Body, status)
			}
		}
	})
}

// FuzzFedBucketPage decodes a fuzzed page of a peer's answer for a bucket
// (decodeFedBucketPage). Properties: nothing panics; every entry it keeps is
// a directory hash in the bucket asked for, in ascending order, with a box no
// larger than a directory carries; a next page, when there is one, starts
// in the bucket at or after the last entry.
func FuzzFedBucketPage(f *testing.F) {
	h := bytes.Repeat([]byte{0x42}, dirbox.HashLen)
	b64 := base64.RawURLEncoding.EncodeToString
	f.Add([]byte(`{"max_bits":0,"entries":[{"h":"`+b64(h)+`","box":"AAAA"}],"next":"`+b64(h)+`"}`), []byte{0x40}, uint8(2))
	f.Add([]byte(`{"max_bits":3,"entries":[]}`), []byte{}, uint8(0))
	f.Add([]byte(`{"max_bits":1,"entries":[{"h":"x","box":"y"}],"partial":true}`), []byte{0x80}, uint8(1))
	f.Fuzz(func(t *testing.T, raw, prefix []byte, bits uint8) {
		b := int(bits)
		if dirbox.CheckPrefix(prefix, b) != nil {
			return
		}
		p, err := decodeFedBucketPage(raw, prefix, b)
		if err != nil {
			return
		}
		var last []byte
		for _, e := range p.entries {
			if !dirbox.InBucket(e.h, prefix, b) || len(e.box) > dirbox.MaxBoxLen {
				t.Fatalf("an entry outside the bucket or too large was kept")
			}
			if last != nil && bytes.Compare(e.h, last) < 0 {
				t.Fatalf("entries out of order")
			}
			last = e.h
		}
		if p.next != nil && (!dirbox.InBucket(p.next, prefix, b) || last == nil || bytes.Compare(p.next, last) < 0) {
			t.Fatalf("a next page outside the bucket or before the last entry")
		}
	})
}

