package aghub

// Fuzz targets of the delivery confirmations at the hub (p2p-receipts §2.4,
// §2.5): the anonymous status check, a peer's status check, and the reading
// of a peer's answer. /relay/ack with items is FuzzHubRelayPollAck
// (fuzz_relay_test.go).

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// statusModel is what a status check must answer for (rid, handle) on h:
// the rid in a mailbox, else the handle stored and its time not over.
func statusModel(t *testing.T, h *relayHub, rid, handle []byte) (string, []byte) {
	t.Helper()
	var one int
	if h.store.db.QueryRow(`SELECT 1 FROM relay_message WHERE rid=?`, rid).Scan(&one) == nil {
		return RelayStatusQueued, nil
	}
	var dack []byte
	if h.store.db.QueryRow(`SELECT dack FROM relay_dack WHERE handle=? AND exp>?`, handle, h.clock().UnixMilli()).Scan(&dack) == nil {
		return RelayStatusDone, dack
	}
	return RelayStatusUnknown, nil
}

// checkStatusAnswer checks a 200 of a status check of body against the
// model: one item per item asked, in order, each the model's answer.
// before are the model's answers taken before the check.
func checkStatusAnswer(t *testing.T, rec []byte, items []StatusItem, before [][2]any) {
	t.Helper()
	var out RelayStatusResponse
	if err := wire3.DecodeStrict(rec, &out); err != nil || len(out.Items) != len(items) {
		t.Fatalf("answer %s for %d items: %v", rec, len(items), err)
	}
	for i, it := range out.Items {
		state, dack := before[i][0].(string), before[i][1].([]byte)
		if it.State != state {
			t.Fatalf("item %d: %s, want %s", i, it.State, state)
		}
		if state == RelayStatusDone && it.DAck != b64u(dack) || state != RelayStatusDone && it.DAck != "" {
			t.Fatalf("item %d: %s with dack %q", i, it.State, it.DAck)
		}
	}
}

// FuzzHubRelayStatus sends fuzzed /relay/status bodies, with or without an
// identity header, to a hub whose mailbox and confirmations hold known rows.
// Properties: no 5xx; every refusal is 400 (bad_request, bad_status_query,
// identity_headers_not_allowed), 413 or 429 and changes nothing; a 200
// answers each item as the model (queued, done with the stored dack,
// unknown), in order, and only for a body whose items the route takes.
func FuzzHubRelayStatus(f *testing.F) {
	h := newRelayHub(f)
	r := h.agent()
	waiting, done := h.queue(r, "waiting"), h.queue(r, "done")
	c := newConfirmation(f)
	h.ack(r, ackItem(done.ID, &c))
	f.Add([]byte(statusBody("", [2][]byte{waiting.RID, c.handle})), false)
	f.Add([]byte(statusBody("", [2][]byte{done.RID, c.handle}, [2][]byte{waiting.RID, waiting.RID})), false)
	f.Add([]byte(statusBody(h.hubAID, [2][]byte{done.RID, c.handle})), false)
	f.Add([]byte(statusBody("did:anet:elsewhere", [2][]byte{done.RID, c.handle})), false)
	f.Add([]byte(`{"items":[{"rid":"`+b64u(done.RID)+`=","handle":"`+b64u(c.handle)+`"}]}`), false)
	f.Add([]byte(`{"items":[]}`), true)
	f.Add([]byte(`{"items":[{"rid":"","handle":"","via_hub":"\u0000"}]}`), false)
	f.Fuzz(func(t *testing.T, body []byte, identity bool) {
		body = clipBytes(body, StatusBodyLimit+64)
		var req RelayStatusRequest
		decoded := wire3.DecodeStrict(body, &req) == nil
		var items []StatusItem
		ok := false
		if decoded {
			items, ok = decodeStatusItems(len(req.Items), func(i int) (string, string) { return req.Items[i].RID, req.Items[i].Handle })
			for _, it := range req.Items {
				ok = ok && it.ViaHub == req.Items[0].ViaHub
			}
		}
		var before [][2]any
		for _, it := range items {
			s, d := statusModel(t, h, it.RID, it.Handle)
			before = append(before, [2]any{s, d})
		}
		dacks := dackRowsOf(t, h.store)
		hr := statusRequest(body)
		if identity {
			hr.Header.Set("X-ANet-Seq", "0")
		}
		// A second a check: the address's bucket refills and keeps nothing,
		// and the stored confirmations age as the model says.
		h.advance(time.Second)
		rec := h.serve(hr, "192.0.2.99")
		switch {
		case rec.Code >= 500:
			t.Fatalf("%d %s", rec.Code, rec.Body)
		case identity:
			if rec.Code != 400 || reasonOf(rec) != string(wire3.ReasonIdentityHeadersNotAllowed) || h.read.Load() != 0 {
				t.Fatalf("with an identity header: %d %s, %d bytes read", rec.Code, rec.Body, h.read.Load())
			}
		case rec.Code == 200:
			if !ok {
				t.Fatalf("a body the route does not take was answered: %q", body)
			}
			via := req.Items[0].ViaHub
			if via != "" && via != h.hubAID {
				for i := range before {
					before[i] = [2]any{RelayStatusUnknown, []byte(nil)}
				}
			}
			checkStatusAnswer(t, rec.Body.Bytes(), items, before)
		default:
			if ok && len(body) <= StatusBodyLimit {
				t.Fatalf("a body the route takes was refused: %d %s", rec.Code, rec.Body)
			}
			if rec.Code != 400 && rec.Code != 413 {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		}
		if rec.Code != 200 && dackRowsOf(t, h.store) != dacks {
			t.Fatal("a refused check changed the confirmations")
		}
	})
}

// FuzzFedRelayStatus sends fuzzed /fed/v3/relay-status bodies, signed by a
// peer, to a hub. Properties: no 5xx; a 200 only for a body the route takes
// (no via_hub), answered as the model; anything else 400 or 413.
func FuzzFedRelayStatus(f *testing.F) {
	net := newFedNet(f, 2)
	a, b := net.nodes[0], net.nodes[1]
	r := b.agent()
	waiting, done := b.queue(r, "waiting"), b.queue(r, "done")
	c := newConfirmation(f)
	b.ack(r, ackItem(done.ID, &c))
	f.Add(fedStatusBody([2][]byte{waiting.RID, c.handle}, [2][]byte{done.RID, c.handle}))
	f.Add(statusBody(b.hubAID, [2][]byte{done.RID, c.handle}))
	f.Add([]byte(`{"items":[]}`))
	f.Add([]byte(`{"items":[{"rid":"` + b64u(done.RID) + `","handle":"` + b64u(c.handle[:15]) + `"}]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, body []byte) {
		body = clipBytes(body, 20<<10)
		var req FedRelayStatusRequest
		var items []StatusItem
		ok := wire3.DecodeStrict(body, &req) == nil
		if ok {
			items, ok = decodeStatusItems(len(req.Items), func(i int) (string, string) { return req.Items[i].RID, req.Items[i].Handle })
		}
		var before [][2]any
		for _, it := range items {
			s, d := statusModel(t, b.relayHub, it.RID, it.Handle)
			before = append(before, [2]any{s, d})
		}
		// The bucket is the peer's; a fuzzer's many inputs are not a test of it.
		b.srv.delivery.byPeer.forget(a.hubAID)
		rec := b.fedServe(signedStatusTo(b.hubAID, a, body))
		switch {
		case rec.Code >= 500:
			t.Fatalf("%d %s", rec.Code, rec.Body)
		case rec.Code == 200:
			if !ok {
				t.Fatalf("a body the route does not take was answered: %q", body)
			}
			checkStatusAnswer(t, rec.Body.Bytes(), items, before)
		default:
			if ok && len(body) <= 16<<10 {
				t.Fatalf("a body the route takes was refused: %d %s", rec.Code, rec.Body)
			}
			if rec.Code != 400 && rec.Code != 413 {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		}
	})
}

// FuzzPeerStatusAnswer reads fuzzed peer answers to a status check of 1 to
// 64 items (decodePeerStatus). Properties: no panic; a result is exactly n
// items, each queued or unknown without a dack or done with one of
// seal.DAckLen bytes; and it is the answer re-encoded: what this hub tells
// its sender is what the peer said, nothing added.
func FuzzPeerStatusAnswer(f *testing.F) {
	d := b64u(bytes.Repeat([]byte{3}, seal.DAckLen))
	f.Add([]byte(`{"items":[{"state":"queued"}]}`), uint8(0))
	f.Add([]byte(`{"items":[{"state":"done","dack":"`+d+`"},{"state":"unknown"}]}`), uint8(1))
	f.Add([]byte(`{"items":[{"state":"done"}]}`), uint8(0))
	f.Add([]byte(`{"items":[{"state":"queued","dack":"`+d+`"}]}`), uint8(0))
	f.Add([]byte(`{"items":[{"state":"done","dack":"`+d+`="}]}`), uint8(0))
	f.Add([]byte(`{"items":[{"state":"unknown"}],"more":true}`), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, n uint8) {
		asked := int(n%MaxStatusItems) + 1 // a check asks 1 to 64 items
		results, err := decodePeerStatus(raw, asked)
		if err != nil {
			return
		}
		if len(results) != asked {
			t.Fatalf("%d results for %d items", len(results), asked)
		}
		for i, r := range results {
			switch r.State {
			case RelayStatusQueued, RelayStatusUnknown:
				if r.DAck != nil {
					t.Fatalf("item %d: %s with a dack", i, r.State)
				}
			case RelayStatusDone:
				if len(r.DAck) != seal.DAckLen {
					t.Fatalf("item %d: done with %d bytes", i, len(r.DAck))
				}
			default:
				t.Fatalf("item %d: state %q", i, r.State)
			}
		}
		back, _ := json.Marshal(encodeStatus(results))
		var a, b any
		_ = json.Unmarshal(raw, &a)
		_ = json.Unmarshal(back, &b)
		ab, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		if !bytes.Equal(ab, bb) {
			t.Fatalf("the peer said %s; this hub would say %s", ab, bb)
		}
	})
}

// clipBytes is b cut to at most n bytes.
func clipBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// dackRowsOf is how many confirmations store holds.
func dackRowsOf(t *testing.T, store *Store) int {
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM relay_dack`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
