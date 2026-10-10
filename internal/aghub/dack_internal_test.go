package aghub

// Delivery confirmations at the hub (p2p-receipts §2.4, §3.2, §4.2; DLV-H-1
// to DLV-H-10): /relay/ack with items, relay_dack, /relay/status, and the
// bounds and sweeps. The federated status check is in
// dack_fed_internal_test.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// confirmation is a handle and a dack a recipient hands in.
type confirmation struct{ handle, dack []byte }

func newConfirmation(t testing.TB) confirmation {
	return confirmation{randomBytes(t, seal.HandleLen), randomBytes(t, seal.DAckLen)}
}

// queue puts one envelope for a into its mailbox here and returns the row.
func (h *relayHub) queue(a *relayAgent, ct string) Queued {
	h.t.Helper()
	q, err := h.store.QueueEnvelope(a.aid, envelope(h.t, a.aid, []byte(ct)))
	if err != nil {
		h.t.Fatal(err)
	}
	return q
}

// ackItem is one /relay/ack item; c nil for none.
func ackItem(id int64, c *confirmation) map[string]any {
	it := map[string]any{"id": id}
	if c != nil {
		it["handle"], it["dack"] = b64u(c.handle), b64u(c.dack)
	}
	return it
}

// ackRaw sends a signed /relay/ack of body as a.
func (h *relayHub) ackRaw(a *relayAgent, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.serve(h.signed(a.c, relayauth.ActionAck, http.MethodPost, "/relay/ack", body), relayClientIP)
}

// ack sends a signed /relay/ack of items as a and decodes its 200.
func (h *relayHub) ack(a *relayAgent, items ...map[string]any) RelayAckResponse {
	h.t.Helper()
	body, _ := json.Marshal(map[string]any{"items": items})
	rec := h.ackRaw(a, body)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("ack: %d %s", rec.Code, rec.Body)
	}
	var out RelayAckResponse
	if err := wire3.DecodeStrict(rec.Body.Bytes(), &out); err != nil {
		h.t.Fatalf("ack answer %s: %v", rec.Body, err)
	}
	return out
}

// statusRequest is an anonymous /relay/status with body.
func statusRequest(body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/relay/status", bytes.NewReader(body))
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// statusBody is the JSON of a status check of (rid, handle) pairs, all via
// via ("" for none).
func statusBody(via string, pairs ...[2][]byte) []byte {
	items := make([]map[string]any, len(pairs))
	for i, p := range pairs {
		items[i] = map[string]any{"rid": b64u(p[0]), "handle": b64u(p[1])}
		if via != "" {
			items[i]["via_hub"] = via
		}
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	return b
}

// status asks the hub about pairs from ip and decodes its 200.
func (h *relayHub) status(ip, via string, pairs ...[2][]byte) []RelayStatusResult {
	h.t.Helper()
	rec := h.serve(statusRequest(statusBody(via, pairs...)), ip)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	var out RelayStatusResponse
	if err := wire3.DecodeStrict(rec.Body.Bytes(), &out); err != nil || len(out.Items) != len(pairs) {
		h.t.Fatalf("status answer %s: %v", rec.Body, err)
	}
	return out.Items
}

// dackOf is the stored dack and exp of handle, ok false when none.
func (h *relayHub) dackOf(handle []byte) (dack []byte, exp int64, ok bool) {
	h.t.Helper()
	err := h.store.db.QueryRow(`SELECT dack, exp FROM relay_dack WHERE handle=?`, handle).Scan(&dack, &exp)
	return dack, exp, err == nil
}

func (h *relayHub) dackCount() int {
	h.t.Helper()
	var n int
	if err := h.store.db.QueryRow(`SELECT COUNT(*) FROM relay_dack`).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// TestRelayDAckIsAHandleADackAndATime (DLV-ST-3, P4, SI-2, SI-23; M23):
// relay_dack has exactly the columns handle, dack and exp, and its only
// index besides the key is by exp: nothing names a recipient, a sender, a
// rid or another time.
func TestRelayDAckIsAHandleADackAndATime(t *testing.T) {
	h := newRelayHub(t)
	cols, err := tableColumns(h.store.db, "relay_dack")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for c := range cols {
		got = append(got, c)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "dack,exp,handle" {
		t.Fatalf("relay_dack has the columns %v, want exactly handle, dack and exp", got)
	}
	rows, err := h.store.db.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master WHERE tbl_name = 'relay_dack'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var typ, name, stmt string
		if err := rows.Scan(&typ, &name, &stmt); err != nil {
			t.Fatal(err)
		}
		switch {
		case typ == "table":
		case typ == "index" && strings.HasPrefix(name, "sqlite_autoindex_relay_dack"):
		case typ == "index" && name == "idx_relay_dack_exp":
		default:
			t.Errorf("relay_dack has the %s %s: %s", typ, name, stmt)
		}
	}
}

// TestAckStoresTheConfirmationsOfTheRowsItDeleted (DLV-H-3, DLV-W-15, T45;
// M31): in one request, the confirmation of a row this request deleted is
// stored for 7 days; one with another agent's row, a row acked before, a row
// that never was, or a second item for a row already named is dropped; acked
// and stored count what was done. A handle stored again has its dack and
// its time replaced.
func TestAckStoresTheConfirmationsOfTheRowsItDeleted(t *testing.T) {
	h := newRelayHub(t)
	r, other := h.agent(), h.agent()
	q1, q2, q3 := h.queue(r, "one"), h.queue(r, "two"), h.queue(r, "three")
	theirs := h.queue(other, "theirs")
	c1, cOther, cDup, cNone := newConfirmation(t), newConfirmation(t), newConfirmation(t), newConfirmation(t)
	out := h.ack(r, ackItem(q1.ID, &c1), ackItem(q2.ID, nil), ackItem(theirs.ID, &cOther),
		ackItem(q1.ID, &cDup), ackItem(q3.ID+1000, &cNone))
	if out.Acked != 2 || out.Stored != 1 {
		t.Fatalf("acked %d stored %d, want 2 and 1", out.Acked, out.Stored)
	}
	dack, exp, ok := h.dackOf(c1.handle)
	if !ok || !bytes.Equal(dack, c1.dack) || exp != h.clock().Add(DAckTTL).UnixMilli() {
		t.Fatalf("the confirmation of a deleted row: %v %x exp %d", ok, dack, exp)
	}
	for name, c := range map[string]confirmation{"another agent's row": cOther, "a second item for one row": cDup,
		"a row that never was": cNone} {
		if _, _, ok := h.dackOf(c.handle); ok {
			t.Errorf("the confirmation of %s was stored", name)
		}
	}
	if n := h.rows(other.aid); n != 1 {
		t.Fatalf("another agent's mailbox holds %d rows after r's ack", n)
	}
	if n := h.dackCount(); n != 1 {
		t.Fatalf("relay_dack holds %d rows, want 1", n)
	}
	// A row acked before: nothing deleted, nothing stored.
	cAgain := newConfirmation(t)
	if out := h.ack(r, ackItem(q1.ID, &cAgain)); out.Acked != 0 || out.Stored != 0 {
		t.Fatalf("an ack of a row acked before: %+v", out)
	}
	if _, _, ok := h.dackOf(cAgain.handle); ok {
		t.Fatal("the confirmation of a row acked before was stored")
	}
	// The same handle again, with a later row: replaced, its time restarted.
	h.advance(time.Hour)
	c1b := confirmation{c1.handle, randomBytes(t, seal.DAckLen)}
	if out := h.ack(r, ackItem(q3.ID, &c1b)); out.Acked != 1 || out.Stored != 1 {
		t.Fatalf("a handle stored again: %+v", out)
	}
	if dack, exp, _ := h.dackOf(c1.handle); !bytes.Equal(dack, c1b.dack) || exp != h.clock().Add(DAckTTL).UnixMilli() {
		t.Fatalf("a handle stored again kept %x, exp %d", dack, exp)
	}
	if n := h.dackCount(); n != 1 {
		t.Fatalf("relay_dack holds %d rows, want 1", n)
	}
	if got := h.srv.DeliveryCounters()["relay-dack-stored"]; got != 2 {
		t.Errorf("relay-dack-stored = %d, want 2", got)
	}
}

// TestAckItemsAreTakenWholeOrNotAtAll (DLV-W-14, CORE-E5, CORE-E7): an ack
// with no items, more than 1000, an item without an id, a handle without a
// dack or the other way round, a handle or dack of another length or not in
// base64url is refused whole, 400 bad_ack_item naming the item, and nothing
// is deleted or stored; a member the route does not take is 400 bad_request.
func TestAckItemsAreTakenWholeOrNotAtAll(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	q := h.queue(r, "kept")
	c := newConfirmation(t)
	good := fmt.Sprintf(`{"id":%d,"handle":"%s","dack":"%s"}`, q.ID, b64u(c.handle), b64u(c.dack))
	many := make([]string, MaxAckItems+1)
	for i := range many {
		many[i] = good
	}
	for _, tc := range []struct {
		name, body string
		reason     wire3.Reason
		item       int
	}{
		{"no items", `{"items":[]}`, wire3.ReasonBadAckItem, 0},
		{"no member", `{}`, wire3.ReasonBadAckItem, 0},
		{"1001 items", `{"items":[` + strings.Join(many, ",") + `]}`, wire3.ReasonBadAckItem, 1000},
		{"no id", `{"items":[` + good + `,{"handle":"` + b64u(c.handle) + `","dack":"` + b64u(c.dack) + `"}]}`, wire3.ReasonBadAckItem, 1},
		{"id 0", `{"items":[{"id":0}]}`, wire3.ReasonBadAckItem, 0},
		{"a handle alone", fmt.Sprintf(`{"items":[{"id":%d,"handle":"%s"}]}`, q.ID, b64u(c.handle)), wire3.ReasonBadAckItem, 0},
		{"a dack alone", fmt.Sprintf(`{"items":[{"id":%d,"dack":"%s"}]}`, q.ID, b64u(c.dack)), wire3.ReasonBadAckItem, 0},
		{"a 15-byte handle", fmt.Sprintf(`{"items":[{"id":%d,"handle":"%s","dack":"%s"}]}`, q.ID, b64u(c.handle[:15]), b64u(c.dack)), wire3.ReasonBadAckItem, 0},
		{"a 79-byte dack", fmt.Sprintf(`{"items":[{"id":%d,"handle":"%s","dack":"%s"}]}`, q.ID, b64u(c.handle), b64u(c.dack[:79])), wire3.ReasonBadAckItem, 0},
		{"a padded handle", fmt.Sprintf(`{"items":[{"id":%d,"handle":"%s","dack":"%s"}]}`, q.ID, base64.URLEncoding.EncodeToString(c.handle), b64u(c.dack)), wire3.ReasonBadAckItem, 0},
		{"a dack in the standard alphabet", fmt.Sprintf(`{"items":[{"id":%d,"handle":"%s","dack":"%s"}]}`, q.ID, b64u(c.handle),
			base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 80))), wire3.ReasonBadAckItem, 0},
		{"the wire-2 ids", fmt.Sprintf(`{"ids":[%d]}`, q.ID), wire3.ReasonBadRequest, -1},
		{"an unknown member of an item", fmt.Sprintf(`{"items":[{"id":%d,"outcome":1}]}`, q.ID), wire3.ReasonBadRequest, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := h.effects()
			rec := h.ackRaw(r, []byte(tc.body))
			expectRefusal(t, rec, 400, string(tc.reason))
			if tc.item >= 0 {
				want := fmt.Sprintf("Item %d: an id is required, handle (16 bytes) and dack (80 bytes) go together, and at most 1000 items are taken.", tc.item)
				var b struct{ Error string }
				_ = json.Unmarshal(rec.Body.Bytes(), &b)
				if b.Error != want {
					t.Errorf("error %q, want %q", b.Error, want)
				}
			}
			if d := before.diff(h.effects()); d != "" {
				t.Fatalf("a refused ack changed something: %s", d)
			}
		})
	}
	if out := h.ack(r, ackItem(q.ID, &c)); out.Acked != 1 || out.Stored != 1 {
		t.Fatalf("the good ack after them: %+v", out)
	}
}

// TestAStatusCheckAnswersByRIDThenHandle (§2.4.3, DLV-H-4; M16, M40): queued
// while the mailbox holds the rid, whatever is stored; else done, with the
// dack, when the handle is stored and its time is not over, and the time
// left is cut to 10 minutes; else unknown. A rid with another handle, or a
// handle with another rid, is answered by the handle alone.
func TestAStatusCheckAnswersByRIDThenHandle(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	queued, collected := h.queue(r, "queued"), h.queue(r, "collected")
	cq, cc := newConfirmation(t), newConfirmation(t)
	h.ack(r, ackItem(collected.ID, &cc))
	// A handle stored for a rid still queued (the recipient handed in the
	// confirmation of a copy it got another way).
	other := h.queue(r, "other")
	h.ack(r, ackItem(other.ID, &cq))
	randomRID, randomHandle := randomBytes(t, RIDLen), randomBytes(t, seal.HandleLen)
	got := h.status("192.0.2.10", "",
		[2][]byte{queued.RID, cq.handle},
		[2][]byte{collected.RID, cc.handle},
		[2][]byte{randomRID, randomHandle},
		[2][]byte{collected.RID, randomHandle},
		[2][]byte{randomRID, cc.handle},
	)
	want := []string{RelayStatusQueued, RelayStatusDone, RelayStatusUnknown, RelayStatusUnknown, RelayStatusDone}
	for i, w := range want {
		if got[i].State != w {
			t.Errorf("item %d: %s, want %s", i, got[i].State, w)
		}
		if (w == RelayStatusDone) != (got[i].DAck != "") {
			t.Errorf("item %d: %s with dack %q", i, got[i].State, got[i].DAck)
		}
	}
	if got[1].DAck != b64u(cc.dack) {
		t.Errorf("done answered the dack %q, want the stored one", got[1].DAck)
	}
	if _, exp, _ := h.dackOf(cc.handle); exp != h.clock().Add(DAckFetchedTTL).UnixMilli() {
		t.Fatalf("after done the confirmation expires at %d, want now + 10 minutes", exp)
	}
	if _, exp, _ := h.dackOf(cq.handle); exp != h.clock().Add(DAckTTL).UnixMilli() {
		t.Fatalf("a confirmation answered queued had its time cut: %d", exp)
	}
	// Asked again 5 minutes on: still done, and not lengthened.
	h.advance(5 * time.Minute)
	if got := h.status("192.0.2.10", "", [2][]byte{collected.RID, cc.handle}); got[0].State != RelayStatusDone {
		t.Fatalf("5 minutes after done: %s", got[0].State)
	}
	if _, exp, _ := h.dackOf(cc.handle); exp != h.clock().Add(5*time.Minute).UnixMilli() {
		t.Fatalf("a second done moved the time to %d", exp)
	}
	// Past its time: unknown, and the sweep deletes it.
	h.advance(5 * time.Minute)
	if got := h.status("192.0.2.10", "", [2][]byte{collected.RID, cc.handle}); got[0].State != RelayStatusUnknown {
		t.Fatalf("10 minutes after done: %s", got[0].State)
	}
	if got := h.srv.DeliveryCounters(); got["relay-status"] != 3 || got["relay-dack-fetched"] != 3 {
		t.Errorf("counters %v, want 3 status checks and 3 fetched", got)
	}
}

// TestTheConfirmationsExpireAndAreBounded (DLV-H-7, T45): the sweep deletes
// the confirmations whose time is over, in the round that sweeps the
// mailboxes; past MaxDAckRows the rows that expire first are evicted in the
// ack that went over, even when rows went away that this process did not
// count.
func TestTheConfirmationsExpireAndAreBounded(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	var cs []confirmation
	epoch := uint64(1)
	ackOne := func() AckResult {
		t.Helper()
		// A key set valid now, whatever time the test moved to.
		epoch++
		h.publish(r, epoch)
		c := newConfirmation(t)
		cs = append(cs, c)
		q := h.queue(r, fmt.Sprint("m", len(cs)))
		out := h.ack(r, ackItem(q.ID, &c))
		return AckResult{Acked: out.Acked, Stored: out.Stored}
	}
	ackOne()
	h.advance(DAckTTL / 2)
	ackOne()
	h.advance(DAckTTL / 2) // the first is over now
	n, err := h.store.PurgeExpiredDAcks(h.clock())
	if err != nil || n != 1 {
		t.Fatalf("the sweep deleted %d (%v), want 1", n, err)
	}
	if _, _, ok := h.dackOf(cs[0].handle); ok {
		t.Fatal("an expired confirmation is still stored")
	}
	if _, _, ok := h.dackOf(cs[1].handle); !ok {
		t.Fatal("the sweep deleted a confirmation whose time is not over")
	}
	// The janitor runs it with the mailbox sweep, and counts it.
	h.advance(DAckTTL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.srv.RunRelayJanitor(ctx, time.Hour)
	if h.dackCount() != 0 || h.srv.DeliveryCounters()["relay-dack-expired"] != 1 {
		t.Fatalf("after the janitor: %d rows, expired %d", h.dackCount(), h.srv.DeliveryCounters()["relay-dack-expired"])
	}
	// The bound: 3 rows here.
	h.store.mu.Lock()
	h.store.dack.max = 3
	h.store.mu.Unlock()
	cs = nil
	for i := 0; i < 3; i++ {
		ackOne()
		h.advance(time.Minute)
	}
	if h.dackCount() != 3 {
		t.Fatalf("%d rows under the bound", h.dackCount())
	}
	ackOne()
	ackOne()
	if h.dackCount() != 3 {
		t.Fatalf("%d rows past the bound, want 3", h.dackCount())
	}
	for i, c := range cs {
		_, _, ok := h.dackOf(c.handle)
		if ok != (i >= 2) {
			t.Errorf("confirmation %d stored %v; the two that expire first go", i, ok)
		}
	}
	if got := h.srv.DeliveryCounters()["relay-dack-evicted"]; got != 2 {
		t.Errorf("relay-dack-evicted = %d, want 2", got)
	}
	// Rows deleted behind the store's back: it counts again before it
	// evicts, and evicts nothing that fits.
	if _, err := h.store.db.Exec(`DELETE FROM relay_dack`); err != nil {
		t.Fatal(err)
	}
	ackOne()
	if h.dackCount() != 1 {
		t.Fatalf("an ack after the rows went: %d rows, want 1", h.dackCount())
	}
	if MaxDAckRows != 2_000_000 || DAckTTL != 7*24*time.Hour || DAckFetchedTTL != 10*time.Minute {
		t.Errorf("the constants are %d rows, %s, %s", MaxDAckRows, DAckTTL, DAckFetchedTTL)
	}
}

// TestStatusChecksFollowTheirOrder (DLV-W-16, DLV-H-5; T17; M30): the
// address's bucket and the identity headers are checked before the body is
// read; then its size, its decoding and its items. The bucket is 10 a
// second and 50 at once per address (an IPv6 /64 being one address).
func TestStatusChecksFollowTheirOrder(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	q := h.queue(r, "x")
	pair := [2][]byte{q.RID, randomBytes(t, seal.HandleLen)}
	good := statusBody("", pair)
	t.Run("identity headers", func(t *testing.T) {
		for _, hd := range []string{relayauth.HeaderAID, relayauth.HeaderSeq, relayauth.HeaderSig} {
			req := statusRequest(good)
			req.Header.Set(hd, "x")
			rec := h.serve(req, "192.0.2.21")
			expectRefusal(t, rec, 400, "identity_headers_not_allowed")
			if h.read.Load() != 0 {
				t.Fatalf("with %s the body was read", hd)
			}
		}
	})
	t.Run("the address's bucket", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			if rec := h.serve(statusRequest(good), "2001:db8:1:2::1"); rec.Code != 200 {
				t.Fatalf("check %d: %d %s", i, rec.Code, rec.Body)
			}
		}
		rec := h.serve(statusRequest(good), "2001:db8:1:2::ffff") // the same /64
		expectRefusal(t, rec, 429, "rate_limited")
		if ra, _ := strconv.Atoi(rec.Header().Get("Retry-After")); ra < 1 {
			t.Fatalf("Retry-After %q", rec.Header().Get("Retry-After"))
		}
		if h.read.Load() != 0 {
			t.Fatal("a check over the bucket had its body read")
		}
		if rec := h.serve(statusRequest(good), "2001:db8:1:3::1"); rec.Code != 200 {
			t.Fatalf("another /64: %d %s", rec.Code, rec.Body)
		}
		h.advance(time.Second / 10)
		if rec := h.serve(statusRequest(good), "2001:db8:1:2::1"); rec.Code != 200 {
			t.Fatalf("a tenth of a second later: %d %s", rec.Code, rec.Body)
		}
		if got := h.srv.DeliveryCounters()["relay-status-limited"]; got != 1 {
			t.Errorf("relay-status-limited = %d", got)
		}
	})
	t.Run("the body", func(t *testing.T) {
		big := []byte(`{"items":[],"pad":"` + strings.Repeat("a", StatusBodyLimit) + `"}`)
		expectRefusal(t, h.serve(statusRequest(big), "192.0.2.22"), 413, "too_large")
		expectRefusal(t, h.serve(statusRequest([]byte(`{"items":[],"x":1}`)), "192.0.2.22"), 400, "bad_request")
		expectRefusal(t, h.serve(statusRequest([]byte(`{"items":[{"rid":"`+b64u(q.RID)+`","handle":"`+b64u(pair[1])+`","outcome":"done"}]}`)), "192.0.2.22"), 400, "bad_request")
	})
	t.Run("the items", func(t *testing.T) {
		pairs := make([][2][]byte, MaxStatusItems+1)
		for i := range pairs {
			pairs[i] = pair
		}
		mixed := []byte(`{"items":[{"rid":"` + b64u(q.RID) + `","handle":"` + b64u(pair[1]) + `"},{"rid":"` + b64u(q.RID) +
			`","handle":"` + b64u(pair[1]) + `","via_hub":"` + h.hubAID + `"}]}`)
		for _, tc := range []struct {
			name string
			body []byte
		}{
			{"no items", []byte(`{"items":[]}`)},
			{"no member", []byte(`{}`)},
			{"65 items", statusBody("", pairs...)},
			{"a 15-byte rid", statusBody("", [2][]byte{q.RID[:15], pair[1]})},
			{"a 17-byte handle", statusBody("", [2][]byte{q.RID, append(append([]byte(nil), pair[1]...), 0)})},
			{"a padded rid", []byte(`{"items":[{"rid":"` + base64.URLEncoding.EncodeToString(q.RID) + `","handle":"` + b64u(pair[1]) + `"}]}`)},
			{"an empty rid", statusBody("", [2][]byte{nil, pair[1]})},
			{"no handle", []byte(`{"items":[{"rid":"` + b64u(q.RID) + `"}]}`)},
			{"two hubs in one", mixed},
		} {
			t.Run(tc.name, func(t *testing.T) {
				expectRefusal(t, h.serve(statusRequest(tc.body), "192.0.2.23"), 400, "bad_status_query")
			})
		}
		if got := h.status("192.0.2.23", "", pairs[:64]...); len(got) != 64 || got[0].State != RelayStatusQueued {
			t.Fatalf("64 items: %v", got)
		}
	})
}

// TestStatusGuessing (T17, SI-23): a random rid is unknown; the right rid of
// a row that was collected, with a wrong handle, is unknown; nothing of the
// answer depends on who asks or tells the recipient.
func TestStatusGuessing(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	q := h.queue(r, "guess me")
	c := newConfirmation(t)
	h.ack(r, ackItem(q.ID, &c))
	for i := 0; i < 20; i++ {
		got := h.status(fmt.Sprintf("198.51.100.%d", i), "",
			[2][]byte{randomBytes(t, RIDLen), randomBytes(t, seal.HandleLen)},
			[2][]byte{q.RID, randomBytes(t, seal.HandleLen)})
		if got[0].State != RelayStatusUnknown || got[1].State != RelayStatusUnknown || got[0].DAck+got[1].DAck != "" {
			t.Fatalf("guesses answered %v", got)
		}
	}
}

// TestADuplicateKeepsItsRID (DLV-H-1, DLV-H-2, T9 the hub's part; M10): the
// same envelope sent while its row waits is answered duplicate with the rid
// of that row, and no second row is written; a rid is 16 random bytes, new
// for each row.
func TestADuplicateKeepsItsRID(t *testing.T) {
	h := newRelayHub(t)
	r, sender := h.agent(), h.agent()
	ss := h.openSession(sender.c)
	env := envelope(t, r.aid, []byte("once"))
	first := decodeSent(t, h.send0(ss, env, kind0Opts{}))
	again := decodeSent(t, h.send0(ss, env, kind0Opts{}))
	if first.Status != RelayQueued || again.Status != RelayDuplicate || again.RID != first.RID {
		t.Fatalf("first %+v, again %+v", first, again)
	}
	if n := h.rows(r.aid); n != 1 {
		t.Fatalf("the mailbox holds %d rows", n)
	}
	if rid := mustB64(t, first.RID); len(rid) != RIDLen {
		t.Fatalf("a rid of %d bytes", len(rid))
	}
	q, err := h.store.QueueEnvelope(r.aid, env)
	if err != nil || !q.Duplicate || b64u(q.RID) != first.RID {
		t.Fatalf("queued again: %+v %v", q, err)
	}
	other := decodeSent(t, h.send0(ss, envelope(t, r.aid, []byte("another")), kind0Opts{}))
	if other.RID == first.RID {
		t.Fatal("two rows share a rid")
	}
	if got := h.status("192.0.2.30", "", [2][]byte{mustB64(t, first.RID), randomBytes(t, 16)}); got[0].State != RelayStatusQueued {
		t.Fatalf("the rid of a duplicate: %s", got[0].State)
	}
}

// TestPropStatusDependsOnRIDAndHandleAlone (P4): over random mailboxes and
// stored confirmations, each item's answer is queued exactly when the rid
// is in a mailbox, else done exactly when the handle is stored and its time
// is not over, with that dack, else unknown.
func TestPropStatusDependsOnRIDAndHandleAlone(t *testing.T) {
	h := newRelayHub(t)
	agents := []*relayAgent{h.agent(), h.agent(), h.agent()}
	type row struct {
		q      Queued
		owner  *relayAgent
		c      confirmation
		acked  bool
		expiry int64
	}
	var rows []*row
	for i := 0; i < 40; i++ {
		a := agents[i%len(agents)]
		rows = append(rows, &row{q: h.queue(a, fmt.Sprint("p", i)), owner: a, c: newConfirmation(t)})
	}
	pick := func() int { return int(randomBytes(t, 1)[0]) % len(rows) }
	for round := 0; round < 30; round++ {
		// Collect a few, with or without their confirmations.
		for k := 0; k < 3; k++ {
			rw := rows[pick()]
			if rw.acked {
				continue
			}
			var c *confirmation
			if randomBytes(t, 1)[0]&1 == 0 {
				c = &rw.c
			}
			h.ack(rw.owner, ackItem(rw.q.ID, c))
			rw.acked = true
			if c != nil {
				rw.expiry = h.clock().Add(DAckTTL).UnixMilli()
			} else {
				rw.expiry = -1
			}
		}
		h.advance(time.Duration(randomBytes(t, 1)[0]) * time.Hour)
		// Ask about a mix of rids and handles, as anybody.
		var pairs [][2][]byte
		var want []*row
		var wantHandleOf []*row
		for k := 0; k < 8; k++ {
			a, b := rows[pick()], rows[pick()]
			pairs = append(pairs, [2][]byte{a.q.RID, b.c.handle})
			want, wantHandleOf = append(want, a), append(wantHandleOf, b)
		}
		got := h.status(fmt.Sprintf("203.0.113.%d", round), "", pairs...)
		nowMS := h.clock().UnixMilli()
		for k := range pairs {
			a, b := want[k], wantHandleOf[k]
			exp := RelayStatusUnknown
			switch {
			case !a.acked:
				exp = RelayStatusQueued
			case b.acked && b.expiry > nowMS:
				exp = RelayStatusDone
			}
			if got[k].State != exp {
				t.Fatalf("round %d item %d: %s, want %s", round, k, got[k].State, exp)
			}
			if exp == RelayStatusDone {
				if got[k].DAck != b64u(b.c.dack) {
					t.Fatalf("round %d item %d: another dack", round, k)
				}
				// done cuts the time left.
				b.expiry = min(b.expiry, nowMS+DAckFetchedTTL.Milliseconds())
			}
		}
	}
}

// TestNoDeliveryConfirmationFlag (DLV-H-10, T51 the hub's part): the bounds
// of the delivery confirmations are constants of dack.go.
func TestDeliveryConfirmationBoundsAreConstants(t *testing.T) {
	for name, got := range map[string][2]float64{
		"/relay/status per address":    {rateRelayStatus.perSec, rateRelayStatus.burst},
		"/fed/v3/relay-status per hub": {rateFedRelayStatus.perSec, rateFedRelayStatus.burst},
	} {
		want := map[string][2]float64{"/relay/status per address": {10, 50}, "/fed/v3/relay-status per hub": {100, 500}}[name]
		if got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if MaxAckItems != MaxPollLimit || MaxPollLimit != 1000 || MaxStatusItems != 64 || StatusBodyLimit != 16<<10 ||
		StatusPeerTimeout != 5*time.Second || StatusPeerRetry != 10*time.Second || MaxPassedRetryAfter != time.Hour {
		t.Error("a delivery confirmation constant moved")
	}
	names := []string{}
	for n := range (&Server{delivery: newDeliveryState(time.Now)}).DeliveryCounters() {
		names = append(names, n)
	}
	sort.Strings(names)
	want := "fed-relay-status,fed-relay-status-limited,relay-dack-evicted,relay-dack-expired,relay-dack-fetched," +
		"relay-dack-stored,relay-status,relay-status-limited,relay-status-peer-error"
	if strings.Join(names, ",") != want {
		t.Errorf("counters %v", names)
	}
}

// TestARIDThatMeetsARowsIsDrawnAgain (DLV-H-1): a rid is drawn in the
// queueing transaction, and one that meets another row's is drawn again; the
// row is queued under the new one.
func TestARIDThatMeetsARowsIsDrawnAgain(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	first := h.queue(r, "first")
	fresh := randomBytes(t, RIDLen)
	draws := [][]byte{first.RID, first.RID, fresh}
	prev := newRID
	newRID = func() ([]byte, error) {
		d := draws[0]
		if len(draws) > 1 {
			draws = draws[1:]
		}
		return append([]byte(nil), d...), nil
	}
	t.Cleanup(func() { newRID = prev })
	q := h.queue(r, "second")
	if !bytes.Equal(q.RID, fresh) || q.Duplicate {
		t.Fatalf("queued under %x, want the third draw %x", q.RID, fresh)
	}
	if n := h.rows(r.aid); n != 2 {
		t.Fatalf("the mailbox holds %d rows", n)
	}
	if got := h.status("192.0.2.31", "", [2][]byte{first.RID, randomBytes(t, 16)}, [2][]byte{fresh, randomBytes(t, 16)}); got[0].State != RelayStatusQueued || got[1].State != RelayStatusQueued {
		t.Fatalf("the two rids: %v", got)
	}
}
