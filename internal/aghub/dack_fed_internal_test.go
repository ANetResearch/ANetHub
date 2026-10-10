package aghub

// The status check of an envelope queued at another hub (p2p-receipts
// §2.4.3, §2.5; DLV-W-18, DLV-W-19, DLV-H-8; T28, T44), a hub restored
// from a backup (T29), and what a hub never says (DLV-H-6, T46). Hubs are
// fedNet nodes: real kernels and federation modules over HTTP.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// forwardOne sends a first contact from a new agent at a to recip, whose
// home is b, and returns the rid and via_hub of the answer.
func forwardOne(t *testing.T, a, b *fedNode, recip *relayAgent, ct string) (rid []byte, via string) {
	t.Helper()
	rec := a.send0To(recip.aid, b.hubAID, ct)
	var out RelaySendResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.ViaHub != b.hubAID {
		t.Fatalf("a forwarded send: %d %s", rec.Code, rec.Body)
	}
	return mustB64(t, out.RID), out.ViaHub
}

// collect has recip take every envelope of its mailbox at nd and ack it,
// handing in c for the envelope whose rid is rid.
func collect(t *testing.T, nd *fedNode, recip *relayAgent, rid []byte, c confirmation) {
	t.Helper()
	var id int64
	if err := nd.store.db.QueryRow(`SELECT id FROM relay_message WHERE rid=?`, rid).Scan(&id); err != nil {
		t.Fatalf("the row of the rid at the home: %v", err)
	}
	if out := nd.ack(recip, ackItem(id, &c)); out.Acked != 1 || out.Stored != 1 {
		t.Fatalf("the recipient's ack at its home: %+v", out)
	}
}

// statusRec is the answer of nd to a status check of pairs via via, from
// ip.
func (nd *fedNode) statusRec(ip, via string, pairs ...[2][]byte) *httptest.ResponseRecorder {
	return nd.serve(statusRequest(statusBody(via, pairs...)), ip)
}

// signedStatus is a /fed/v3/relay-status request to nd, signed by the hub
// as for fed_status, with body.
func (nd *fedNode) signedStatus(as *fedNode, body []byte) *http.Request {
	return signedStatusTo(nd.hubAID, as, body)
}

// signedStatusTo is a /fed/v3/relay-status request to the hub to, signed by
// the hub as for fed_status, with body.
func signedStatusTo(to string, as *fedNode, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/fed/v3/relay-status", bytes.NewReader(body))
	req.Header.Set(wire3.Header, "3")
	req.Header.Set("Content-Type", "application/json")
	ts := relaySignTS()
	sig, seq := as.hubID.Ctrl.Sign(relayauth.PreimageV2(relayauth.ActionFedStatus, as.hubAID, to, ts,
		req.Method, req.URL.RequestURI(), body))
	req.Header.Set(relayauth.HeaderAID, as.hubAID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	return req
}

// fedStatusBody is a /fed/v3/relay-status body of pairs.
func fedStatusBody(pairs ...[2][]byte) []byte {
	items := make([]FedRelayStatusItem, len(pairs))
	for i, p := range pairs {
		items[i] = FedRelayStatusItem{RID: b64u(p[0]), Handle: b64u(p[1])}
	}
	b, _ := json.Marshal(FedRelayStatusRequest{Items: items})
	return b
}

func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder, n int) []RelayStatusResult {
	t.Helper()
	var out RelayStatusResponse
	if rec.Code != 200 || wire3.DecodeStrict(rec.Body.Bytes(), &out) != nil || len(out.Items) != n {
		t.Fatalf("a status answer: %d %s", rec.Code, rec.Body)
	}
	return out.Items
}

// TestStatusOfAForwardedEnvelope (T28 the hubs' part, DLV-W-12a, DLV-W-18,
// DLV-H-8; M32): A at hub A, B at hub B. A's send is queued at B: A is told
// B's rid and via_hub B. A's status check at hub A is asked of B, signed by
// hub A and naming nobody: queued, then done with the dack B's ack left
// (and B cuts its time). B not answering, or answering anything else than
// the contract, is 502 home_unreachable with Retry-After, B's own between a
// second and an hour, else 10 seconds; never unknown. A via_hub that is
// this hub is answered here; one that is no peer, unknown.
func TestStatusOfAForwardedEnvelope(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	rid, via := forwardOne(t, a, b, recip, "to B")
	c := newConfirmation(t)
	pair := [2][]byte{rid, c.handle}
	if got := decodeStatus(t, a.statusRec("192.0.2.40", via, pair), 1); got[0].State != RelayStatusQueued {
		t.Fatalf("before B's recipient collected it: %v", got)
	}
	if got := decodeStatus(t, a.statusRec("192.0.2.40", "", pair), 1); got[0].State != RelayStatusUnknown {
		t.Fatalf("asked without via_hub at the hub that did not queue it: %v", got)
	}
	collect(t, b, recip, rid, c)
	got := decodeStatus(t, a.statusRec("192.0.2.40", via, pair), 1)
	if got[0].State != RelayStatusDone || got[0].DAck != b64u(c.dack) {
		t.Fatalf("after the ack at B: %v", got)
	}
	if _, exp, _ := b.dackOf(c.handle); exp != b.clock().Add(DAckFetchedTTL).UnixMilli() {
		t.Fatalf("B did not cut the time of the confirmation it answered done: %d", exp)
	}
	// What crossed to B: rid and handle, signed by hub A, nothing of the
	// sender or of its address.
	b.mu.Lock()
	seen := append([][]byte(nil), b.statusSeen...)
	b.mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("hub A did not ask B")
	}
	for _, s := range seen {
		for _, bad := range []string{"192.0.2.40", "X-Real-Ip", "X-Forwarded-For", "via_hub"} {
			if bytes.Contains(s, []byte(bad)) {
				t.Fatalf("the status check hub A sent B carries %q:\n%s", bad, s)
			}
		}
		if !bytes.Contains(s, []byte("X-Anet-Aid: "+a.hubAID)) {
			t.Fatalf("the status check is not signed by hub A:\n%s", s)
		}
	}
	if n := a.srv.DeliveryCounters()["relay-dack-fetched"]; n != 1 {
		t.Errorf("hub A counted %d fetched", n)
	}
	if n := b.srv.DeliveryCounters()["fed-relay-status"]; n != 2 {
		t.Errorf("hub B counted %d peer status checks, want 2", n)
	}
	// This hub as via_hub: answered here.
	if got := decodeStatus(t, b.statusRec("192.0.2.41", b.hubAID, pair), 1); got[0].State != RelayStatusDone {
		t.Fatalf("via_hub naming the hub asked: %v", got)
	}
	// A hub that is no peer: unknown, and nobody is asked.
	asked := len(seen)
	stranger := newRelayHub(t)
	if got := decodeStatus(t, a.statusRec("192.0.2.40", stranger.hubAID, pair), 1); got[0].State != RelayStatusUnknown {
		t.Fatalf("via a hub that is no peer: %v", got)
	}
	// B's answers that are not the contract, and B down.
	answer := func(status int, retryAfter, body string) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.status = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(wire3.Header, "3")
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	done := `{"items":[{"state":"done","dack":"` + b64u(c.dack) + `"}]}`
	for i, tc := range []struct {
		status           int
		retryAfter, body string
		wantRetry        string
	}{
		{429, "7", `{"reason":"rate_limited","error":"x"}`, "7"},
		{429, "4294967295", `{"reason":"rate_limited","error":"x"}`, "3600"},
		{403, "", `{"reason":"not_peer","error":"x"}`, "10"},
		{500, "0", `{"reason":"internal","error":"x"}`, "1"},
		{200, "", `{"items":[]}`, "10"},
		{200, "", `{"items":[{"state":"done"}]}`, "10"},
		{200, "", `{"items":[{"state":"gone"}]}`, "10"},
		{200, "", `{"items":[{"state":"queued","dack":"` + b64u(c.dack) + `"}]}`, "10"},
		{200, "", `{"items":[{"state":"done","dack":"` + b64u(c.dack[:79]) + `"}]}`, "10"},
		{200, "", `{"items":[{"state":"unknown"}],"extra":1}`, "10"},
		{200, "", done[:len(done)-2], "10"},
	} {
		t.Run(fmt.Sprint(i, " ", tc.status), func(t *testing.T) {
			answer(tc.status, tc.retryAfter, tc.body)
			rec := a.statusRec(fmt.Sprintf("192.0.2.%d", 50+i), via, pair)
			expectRefusal(t, rec, 502, "home_unreachable")
			if got := rec.Header().Get("Retry-After"); got != tc.wantRetry {
				t.Errorf("Retry-After %q, want %q", got, tc.wantRetry)
			}
		})
	}
	b.mu.Lock()
	b.status = nil
	b.mu.Unlock()
	b.down.Store(true)
	rec := a.statusRec("192.0.2.70", via, pair)
	expectRefusal(t, rec, 502, "home_unreachable")
	if rec.Header().Get("Retry-After") != "10" {
		t.Errorf("B down: Retry-After %q, want 10", rec.Header().Get("Retry-After"))
	}
	if n := a.srv.DeliveryCounters()["relay-status-peer-error"]; n != 12 {
		t.Errorf("relay-status-peer-error = %d, want 12", n)
	}
	b.mu.Lock()
	n := len(b.statusSeen)
	b.mu.Unlock()
	if n != asked+11 {
		t.Errorf("B was asked %d more times, want 11 (the stranger's never)", n-asked)
	}
}

// TestAStatusCheckTimesOutAtFiveSeconds (DLV-W-18): a peer that does not
// answer a status check within 5 seconds is not waited for.
func TestAStatusCheckTimesOutAtFiveSeconds(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	rid, via := forwardOne(t, a, b, recip, "slow")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	b.mu.Lock()
	b.status = func(http.ResponseWriter, *http.Request) {
		select {
		case <-release:
		case <-time.After(30 * time.Second):
		}
	}
	b.mu.Unlock()
	start := time.Now()
	rec := a.statusRec("192.0.2.71", via, [2][]byte{rid, randomBytes(t, 16)})
	expectRefusal(t, rec, 502, "home_unreachable")
	if d := time.Since(start); d < StatusPeerTimeout-time.Second || d > StatusPeerTimeout+3*time.Second {
		t.Fatalf("answered after %s, want about %s", d, StatusPeerTimeout)
	}
}

// TestFedRelayStatusTakesOnlyAPeersQuery (T44, DLV-W-19, DLV-W-19a): a hub
// that is no peer is 403 not_peer; a bad signature 401 unauthorized; a
// via_hub in the body 400 bad_request; 65 items 400 bad_status_query; a
// good one 200; a peer past 100 a second and 500 at once is 429
// rate_limited with Retry-After, before its body is read.
func TestFedRelayStatusTakesOnlyAPeersQuery(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip := b.agent()
	rid, _ := forwardOne(t, a, b, recip, "asked")
	pair := [2][]byte{rid, randomBytes(t, 16)}
	stranger := &fedNode{relayHub: newRelayHub(t)}
	expectRefusal(t, b.fedServe(b.signedStatus(stranger, fedStatusBody(pair))), 403, "not_peer")
	bad := b.signedStatus(a, fedStatusBody(pair))
	bad.Body = io.NopCloser(bytes.NewReader(fedStatusBody([2][]byte{randomBytes(t, 16), pair[1]})))
	expectRefusal(t, b.fedServe(bad), 401, "unauthorized")
	withVia := []byte(`{"items":[{"rid":"` + b64u(rid) + `","handle":"` + b64u(pair[1]) + `","via_hub":"` + b.hubAID + `"}]}`)
	expectRefusal(t, b.fedServe(b.signedStatus(a, withVia)), 400, "bad_request")
	many := make([][2][]byte, 65)
	for i := range many {
		many[i] = pair
	}
	expectRefusal(t, b.fedServe(b.signedStatus(a, fedStatusBody(many...))), 400, "bad_status_query")
	expectRefusal(t, b.fedServe(b.signedStatus(a, fedStatusBody())), 400, "bad_status_query")
	if got := decodeStatus(t, b.fedServe(b.signedStatus(a, fedStatusBody(pair))), 1); got[0].State != RelayStatusQueued {
		t.Fatalf("a peer's status check: %v", got)
	}
	// The bucket: 500 at once (4 taken above), then 429 before the body.
	for i := 0; i < 500-4; i++ {
		if rec := b.fedServe(b.signedStatus(a, fedStatusBody(pair))); rec.Code != 200 {
			t.Fatalf("check %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	var reads int
	req := b.signedStatus(a, fedStatusBody(pair))
	req.Body = readCounter{req.Body, &reads}
	rec := b.fedServe(req)
	expectRefusal(t, rec, 429, "rate_limited")
	if reads != 0 {
		t.Fatal("a check past the peer's bucket had its body read")
	}
	b.advance(10 * time.Millisecond)
	if rec := b.fedServe(b.signedStatus(a, fedStatusBody(pair))); rec.Code != 200 {
		t.Fatalf("a hundredth of a second later: %d %s", rec.Code, rec.Body)
	}
	if got := b.srv.DeliveryCounters()["fed-relay-status-limited"]; got != 1 {
		t.Errorf("fed-relay-status-limited = %d", got)
	}
	// The route follows the delivery switch, as the forward does.
	var errBody struct{ Reason string }
	off := newFedNet(t, 1).nodes[0]
	rec = off.fedServe(off.signedStatus(a, fedStatusBody(pair)))
	if _ = json.Unmarshal(rec.Body.Bytes(), &errBody); rec.Code != 403 || errBody.Reason != "not_peer" {
		t.Fatalf("a hub with no peers: %d %s", rec.Code, rec.Body)
	}
}

// readCounter counts the reads of a request body.
type readCounter struct {
	r io.ReadCloser
	n *int
}

func (c readCounter) Read(p []byte) (int, error) { *c.n++; return c.r.Read(p) }
func (c readCounter) Close() error               { return c.r.Close() }

// TestAStatusCheckAfterARestore (T29 the hub's part, DLV-ST-5): a hub
// restored from a backup holds neither the mailbox nor the confirmations;
// a status check is answered unknown, never queued or done from the copy;
// the sender sends again, gets a new rid, and its confirmation once
// collected.
func TestAStatusCheckAfterARestore(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	waiting, collected := h.queue(r, "waiting"), h.queue(r, "collected")
	c := newConfirmation(t)
	h.ack(r, ackItem(collected.ID, &c))
	backup := filepath.Join(t.TempDir(), "backup.db")
	if _, err := h.store.db.Exec(`VACUUM INTO ?`, backup); err != nil {
		t.Fatal(err)
	}
	h.store.Close()
	if _, err := Restore(h.dir, backup, h.clock()); err != nil {
		t.Fatal(err)
	}
	store, err := Open(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	store.SetHubKey(h.hubID.Ctrl)
	store.clock = h.clock
	h.store = store
	h.restart()
	cw := newConfirmation(t)
	got := h.status("192.0.2.80", "", [2][]byte{waiting.RID, cw.handle}, [2][]byte{collected.RID, c.handle})
	if got[0].State != RelayStatusUnknown || got[1].State != RelayStatusUnknown {
		t.Fatalf("after the restore: %v, want unknown for both", got)
	}
	again := h.queue(r, "waiting")
	if again.Duplicate || bytes.Equal(again.RID, waiting.RID) {
		t.Fatalf("sent again after the restore: %+v", again)
	}
	h.ack(r, ackItem(again.ID, &cw))
	if got := h.status("192.0.2.80", "", [2][]byte{again.RID, cw.handle}); got[0].State != RelayStatusDone || got[0].DAck != b64u(cw.dack) {
		t.Fatalf("the envelope sent again, collected: %v", got)
	}
}

// logCapture collects what the hub logs while a test runs.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// TestNothingOfAConfirmationIsLogged (DLV-H-6, T46): across acks with
// confirmations, refused acks, status checks here and at a peer, refused
// checks, peers' checks and the sweep, no handle and no dack appears in a
// log line or in any answer, except the dack of an item answered done; no
// log line names a rid together with a recipient.
func TestNothingOfAConfirmationIsLogged(t *testing.T) {
	var logs logCapture
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	local, remote := a.agent(), b.agent()
	var answers []*httptest.ResponseRecorder
	var secrets [][]byte
	var rids [][]byte
	var dones []string
	keep := func(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		answers = append(answers, rec)
		return rec
	}
	conf := func() confirmation {
		c := newConfirmation(t)
		secrets = append(secrets, c.handle, c.dack)
		return c
	}
	// Here.
	q := a.queue(local, "local")
	rids = append(rids, q.RID)
	c1 := conf()
	body, _ := json.Marshal(map[string]any{"items": []map[string]any{ackItem(q.ID, &c1)}})
	keep(a.ackRaw(local, body))
	cBad := conf()
	body, _ = json.Marshal(map[string]any{"items": []map[string]any{{"id": q.ID, "handle": b64u(cBad.handle)}}})
	keep(a.ackRaw(local, body))
	rec := keep(a.statusRec("192.0.2.90", "", [2][]byte{q.RID, c1.handle}, [2][]byte{randomBytes(t, 16), cBad.handle}))
	dones = append(dones, decodeStatus(t, rec, 2)[0].DAck)
	keep(a.serve(statusRequest([]byte(`{"items":[{"rid":"`+b64u(q.RID)+`","handle":"`+b64u(cBad.handle)+`=="}]}`)), "192.0.2.91"))
	// At a peer.
	rid, via := forwardOne(t, a, b, remote, "remote")
	rids = append(rids, rid)
	c2 := conf()
	collect(t, b, remote, rid, c2)
	rec = keep(a.statusRec("192.0.2.92", via, [2][]byte{rid, c2.handle}))
	dones = append(dones, decodeStatus(t, rec, 1)[0].DAck)
	keep(b.fedServe(b.signedStatus(a, fedStatusBody([2][]byte{rid, cBad.handle}))))
	b.down.Store(true)
	keep(a.statusRec("192.0.2.93", via, [2][]byte{rid, c2.handle}))
	b.down.Store(false)
	// The sweep.
	a.advance(DAckTTL)
	if _, err := a.store.PurgeExpiredDAcks(a.clock()); err != nil {
		t.Fatal(err)
	}

	logged := logs.String()
	for _, s := range secrets {
		for _, form := range [][]byte{s, []byte(b64u(s)), []byte(fmt.Sprintf("%x", s))} {
			if strings.Contains(logged, string(form)) {
				t.Fatalf("a log line holds a handle or a dack:\n%s", logged)
			}
		}
	}
	for _, line := range strings.Split(logged, "\n") {
		for _, r := range rids {
			for _, form := range []string{b64u(r), fmt.Sprintf("%x", r)} {
				if strings.Contains(line, form) && (strings.Contains(line, local.aid) || strings.Contains(line, remote.aid)) {
					t.Fatalf("a log line names a rid and its recipient: %s", line)
				}
			}
		}
	}
	for i, rec := range answers {
		out := rec.Body.String()
		for _, d := range dones {
			out = strings.Replace(out, `"dack":"`+d+`"`, `"dack":""`, 1)
		}
		for _, s := range secrets {
			if strings.Contains(out, b64u(s)) || strings.Contains(out, string(s)) {
				t.Fatalf("answer %d holds a handle or a dack outside a done item: %s", i, rec.Body)
			}
		}
	}
	if len(dones) != 2 || dones[0] == "" || dones[1] == "" {
		t.Fatalf("the checks answered done %v", dones)
	}
}

// A status check's sender reads nothing of the envelope (SI-23): a hub's
// answer for an envelope whose recipient refused it is the same as for one
// it processed; only the 80 opaque bytes differ.
func TestTheHubReadsNothingOfADAck(t *testing.T) {
	h := newRelayHub(t)
	r := h.agent()
	var answers []RelayStatusResult
	for _, first := range []byte{0x00, 0xff} {
		q := h.queue(r, fmt.Sprint("outcome ", first))
		c := confirmation{randomBytes(t, seal.HandleLen), bytes.Repeat([]byte{first}, seal.DAckLen)}
		h.ack(r, ackItem(q.ID, &c))
		answers = append(answers, h.status("192.0.2.95", "", [2][]byte{q.RID, c.handle})[0])
	}
	if answers[0].State != answers[1].State || len(answers[0].DAck) != len(answers[1].DAck) {
		t.Fatalf("two dacks answered differently: %+v", answers)
	}
}

// TestAForwardedDuplicateKeepsItsRID (DLV-H-2, DLV-W-12, DLV-W-12a; M10):
// the same envelope sent twice to a recipient registered at a peer is
// answered both times with the rid of the one row its home queued, and with
// via_hub the home; the home holds one row and the origin none.
func TestAForwardedDuplicateKeepsItsRID(t *testing.T) {
	net := newFedNet(t, 2)
	a, b := net.nodes[0], net.nodes[1]
	recip, sender := b.agent(), a.agent()
	ss := a.openSession(sender.c)
	env := envelope(t, recip.aid, []byte("twice"))
	var rids []string
	for _, want := range []string{RelayQueued, RelayDuplicate} {
		rec := a.send0(ss, env, kind0Opts{home: b.hubAID})
		var out RelaySendResponse
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Status != want || out.ViaHub != b.hubAID {
			t.Fatalf("want %s via B: %d %s", want, rec.Code, rec.Body)
		}
		rids = append(rids, out.RID)
	}
	if rids[0] != rids[1] {
		t.Fatalf("the duplicate was answered another rid: %v", rids)
	}
	var n int
	if err := b.store.db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE rid=? AND to_aid=?`,
		mustB64(t, rids[0]), recip.aid).Scan(&n); err != nil || n != 1 || b.queued(recip.aid) != 1 {
		t.Fatalf("the home holds %d rows with the rid, %d in all", n, b.queued(recip.aid))
	}
	if a.queued(recip.aid) != 0 {
		t.Fatal("the origin queued the envelope")
	}
}
