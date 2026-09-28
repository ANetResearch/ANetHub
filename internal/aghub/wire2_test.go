package aghub_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// newHubAt is newHubWithStore with a data directory the test can inspect.
func newHubAt(t *testing.T, dir string) (*httptest.Server, *aghub.Store, *aghub.Server) {
	t.Helper()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); store.Close() })
	testHubAID.Store(srv.URL, id.AID)
	testHubStores.Store(srv.URL, store)
	testHubCtrl.Store(srv.URL, id.Ctrl)
	testHubServers.Store(srv.URL, s)
	return srv, store, s
}

// openDB opens a hub data directory's database directly, as an operator
// or an attacker with the disk would.
func openDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---- 426 for wire-1 relay callers ----

// A daemon that does not declare wire 2 is refused on /relay/* with 426
// and told which anet release it needs; other routes stay readable.
func TestTheRelayRefusesAnOlderWireWith426(t *testing.T) {
	srv := newHub(t)
	for _, tc := range []struct {
		name, wire string
	}{{"absent", ""}, {"wire 1", "1"}, {"garbage", "two"}} {
		for _, path := range []string{"/relay/send", "/relay/poll", "/relay/ack"} {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(`{}`))
			if tc.wire != "" {
				req.Header.Set("X-ANet-Wire", tc.wire)
			}
			code, body, hdr := send(t, req)
			if code != http.StatusUpgradeRequired {
				t.Errorf("%s %s: got %d, want 426", tc.name, path, code)
				continue
			}
			var out struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(body, &out)
			if !strings.Contains(out.Error, "anet >= 0.2.0") {
				t.Errorf("%s %s: the refusal does not name the required release: %s", tc.name, path, body)
			}
			if hdr.Get("X-ANet-Wire") != "2" {
				t.Errorf("%s %s: the 426 does not state the hub's wire version", tc.name, path)
			}
		}
	}
	// A directory read without the header is still served.
	resp, err := http.Get(srv.URL + "/agents")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /agents without a wire header: %d", resp.StatusCode)
	}
}

// ---- relayauth v2 failures ----

// Every way a v2 signature can be wrong is refused with 401, and the
// correctly signed control request is accepted, so the refusals are not
// passing for an unrelated reason.
func TestRelayAuthV2RefusesEveryBrokenSignature(t *testing.T) {
	srv := newHub(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	stranger, _ := identity.Incept() // never registered
	hubAID := hubAIDOf(t, srv)
	env := testEnvelope(t, recip.AID(), nil)
	body := rawBody(t, map[string]any{"to_aid": recip.AID(), "envelope": base64.StdEncoding.EncodeToString(env)})

	sendReq := func(sign func(req *http.Request)) int {
		req := newRequest(t, srv, http.MethodPost, "/relay/send", body)
		sign(req)
		code, _, _ := send(t, req)
		return code
	}

	if code := sendReq(func(req *http.Request) {
		signV2(t, req, sender, relayauth.ActionSend, hubAID, body, signingNow())
	}); code != http.StatusOK {
		t.Fatalf("control: a correctly signed send was refused: %d", code)
	}

	cases := []struct {
		name string
		sign func(req *http.Request)
	}{
		{"no headers", func(req *http.Request) {}},
		{"bad signature", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionSend, hubAID, body, signingNow())
			junk := make([]byte, 64)
			_, _ = rand.Read(junk)
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(junk))
		}},
		{"wrong action", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionPoll, hubAID, body, signingNow())
		}},
		{"too old", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionSend, hubAID, body, time.Now().Add(-6*time.Minute))
		}},
		{"from the future", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionSend, hubAID, body, time.Now().Add(6*time.Minute))
		}},
		{"body tampered", func(req *http.Request) {
			other := rawBody(t, map[string]any{"to_aid": recip.AID(), "envelope": base64.StdEncoding.EncodeToString(testEnvelope(t, recip.AID(), []byte("other")))})
			signV2(t, req, sender, relayauth.ActionSend, hubAID, other, signingNow())
		}},
		{"signed for another hub", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionSend, "bafyreianotherhub", body, signingNow())
		}},
		{"signer not registered", func(req *http.Request) {
			signV2(t, req, stranger, relayauth.ActionSend, hubAID, body, signingNow())
		}},
		{"claims another AID", func(req *http.Request) {
			signV2(t, req, stranger, relayauth.ActionSend, hubAID, body, signingNow())
			req.Header.Set(relayauth.HeaderAID, sender.AID())
		}},
		{"non-canonical ts", func(req *http.Request) {
			signV2(t, req, sender, relayauth.ActionSend, hubAID, body, signingNow())
			req.Header.Set(relayauth.HeaderTS, "0"+req.Header.Get(relayauth.HeaderTS))
		}},
	}
	for _, tc := range cases {
		if code := sendReq(tc.sign); code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", tc.name, code)
		}
	}

	// Replay: the same signed request twice.
	req := newRequest(t, srv, http.MethodPost, "/relay/send", body)
	signV2(t, req, sender, relayauth.ActionSend, hubAID, body, signingNow())
	hdr := req.Header.Clone()
	if code, b, _ := send(t, req); code != http.StatusOK {
		t.Fatalf("first use: %d %s", code, b)
	}
	again := newRequest(t, srv, http.MethodPost, "/relay/send", body)
	again.Header = hdr
	if code, b, _ := send(t, again); code != http.StatusUnauthorized || !strings.Contains(string(b), "already used") {
		t.Errorf("replayed request: %d %s, want 401 already used", code, b)
	}

	// Query tampered: signed for one query string, sent with another. The
	// control first: a request signed with its query string is accepted.
	pollBody := rawBody(t, map[string]any{})
	ok := newRequest(t, srv, http.MethodPost, "/relay/poll?cursor=1", pollBody)
	signV2(t, ok, recip, relayauth.ActionPoll, hubAID, pollBody, signingNow())
	if code, b, _ := send(t, ok); code != http.StatusOK {
		t.Fatalf("control: a signed request with a query string: %d %s", code, b)
	}
	q := newRequest(t, srv, http.MethodPost, "/relay/poll?cursor=1", pollBody)
	signV2(t, q, recip, relayauth.ActionPoll, hubAID, pollBody, signingNow())
	q.URL.RawQuery = "cursor=2"
	if code, b, _ := send(t, q); code != http.StatusUnauthorized {
		t.Errorf("query tampered: %d %s, want 401", code, b)
	}
	// Path tampered: signed for one request target, sent with another
	// spelling that routes to the same handler and the same agent. The
	// signature covers the target as sent, so it no longer verifies.
	pb := rawBody(t, map[string]any{"addr": "tcp://10.0.0.1:1"})
	p := newRequest(t, srv, http.MethodPost, "/agents/"+sender.AID()+"/p2p", pb)
	signV2(t, p, sender, relayauth.ActionP2P, hubAID, pb, signingNow())
	p.URL.RawPath = "/agents/%" + strconv.FormatInt(int64(sender.AID()[0]), 16) + sender.AID()[1:] + "/p2p"
	if code, b, _ := send(t, p); code != http.StatusUnauthorized {
		t.Errorf("path tampered: %d %s, want 401", code, b)
	}
}

// ---- /relay/send structural checks and limits ----

// Only a sealed envelope addressed to to_aid is stored.
func TestTheRelayRefusesAnythingButASealedEnvelopeForTheRecipient(t *testing.T) {
	srv := newHub(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)

	outer := func(mut func(m map[uint64]any)) []byte {
		m := map[uint64]any{1: uint64(1), 2: recip.AID(), 3: uint64(1),
			4: bytes.Repeat([]byte{7}, 16), 5: bytes.Repeat([]byte{9}, 32), 6: []byte("ct")}
		mut(m)
		b, err := coredet.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		env  []byte
	}{
		{"plaintext payload", []byte("a plaintext delegation")},
		{"addressed to someone else", testEnvelope(t, sender.AID(), nil)},
		{"version 2", outer(func(m map[uint64]any) { m[1] = uint64(2) })},
		{"unknown suite", outer(func(m map[uint64]any) { m[3] = uint64(2) })},
		{"enc of the wrong length", outer(func(m map[uint64]any) { m[5] = bytes.Repeat([]byte{9}, 31) })},
		{"empty ciphertext", outer(func(m map[uint64]any) { m[6] = []byte{} })},
		{"unknown critical key", outer(func(m map[uint64]any) { m[7] = []byte("access") })},
	} {
		code, b, _ := relaySend(t, srv, sender, recip.AID(), tc.env)
		if code != http.StatusBadRequest {
			t.Errorf("%s: got %d %s, want 400", tc.name, code, b)
		}
	}
	if p := relayPoll(t, srv, recip); len(p.Messages) != 0 {
		t.Fatalf("%d refused payloads were stored", len(p.Messages))
	}
	// The control: a structurally valid envelope is accepted.
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), nil)); code != http.StatusOK {
		t.Fatalf("a valid envelope was refused: %d %s", code, b)
	}
}

// An unknown recipient with no federation is 404.
func TestSendingToAnUnknownRecipientIs404(t *testing.T) {
	srv := newHub(t)
	sender, nobody := twoAgents(t)
	register(t, srv, sender, "Sender", nil)
	if code, b, _ := relaySend(t, srv, sender, nobody.AID(), testEnvelope(t, nobody.AID(), nil)); code != http.StatusNotFound {
		t.Fatalf("unknown recipient: %d %s, want 404", code, b)
	}
}

// One sender cannot exceed its bucket; another sender is unaffected.
func TestThePerSenderBucketAnswers429WithRetryAfter(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.SendRate, l.SendBurst = 0.5, 2
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	recip, sender := twoAgents(t)
	other, _ := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	register(t, srv, other, "Other", nil)
	env := func(i int) []byte { return testEnvelope(t, recip.AID(), []byte{byte(i)}) }
	for i := 0; i < 2; i++ {
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), env(i)); code != http.StatusOK {
			t.Fatalf("send %d within the burst: %d %s", i, code, b)
		}
	}
	code, b, hdr := relaySend(t, srv, sender, recip.AID(), env(3))
	if code != http.StatusTooManyRequests {
		t.Fatalf("send past the burst: %d %s, want 429", code, b)
	}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", hdr.Get("Retry-After"))
	}
	if code, b, _ := relaySend(t, srv, other, recip.AID(), env(4)); code != http.StatusOK {
		t.Errorf("another sender was limited by the first one's bucket: %d %s", code, b)
	}
}

// A recipient's mailbox is bounded by count and by bytes, and an ack
// makes room.
func TestAFullMailboxAnswers507(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.MailboxMessages = 2
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	for i := 0; i < 2; i++ {
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte{byte(i)})); code != 200 {
			t.Fatalf("send %d: %d %s", i, code, b)
		}
	}
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte("third"))); code != http.StatusInsufficientStorage {
		t.Fatalf("third send into a two-message mailbox: %d %s, want 507", code, b)
	}
	p := relayPoll(t, srv, recip)
	relayAck(t, srv, recip, p.Messages[0].ID)
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte("after ack"))); code != 200 {
		t.Fatalf("an ack did not make room: %d %s", code, b)
	}

	// The byte bound, separately.
	l.MailboxMessages, l.MailboxBytes = 100, 300
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	big := testEnvelope(t, recip.AID(), bytes.Repeat([]byte("x"), 200))
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), big); code != http.StatusInsufficientStorage {
		t.Fatalf("a send past the byte bound: %d %s, want 507", code, b)
	}
}

// An envelope over the limit is 413.
func TestAnOversizedEnvelopeIs413(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.MaxEnvelope = 1024
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), bytes.Repeat([]byte("x"), 900))); code != 200 {
		t.Fatalf("an envelope under the limit: %d %s", code, b)
	}
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), bytes.Repeat([]byte("x"), 1100))); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an envelope over the limit: %d %s, want 413", code, b)
	}
}

// ---- storage: what a relay row holds, and for how long ----

// The relay table holds the recipient, the size, the time and the
// envelope, and nothing that names the sender (SI-2).
func TestTheRelayDoesNotStoreTheSender(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), nil)); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	db := openDB(t, dir)
	rows, err := db.Query(`SELECT name FROM pragma_table_info('relay_message')`)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		cols = append(cols, c)
	}
	rows.Close()
	sort.Strings(cols)
	if want := []string{"created_at", "id", "payload", "size", "to_aid"}; strings.Join(cols, ",") != strings.Join(want, ",") {
		t.Fatalf("relay_message columns = %v, want %v", cols, want)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM relay_message
		WHERE instr(CAST(to_aid AS BLOB), ?) > 0 OR instr(payload, ?) > 0 OR instr(CAST(created_at AS BLOB), ?) > 0`,
		[]byte(sender.AID()), []byte(sender.AID()), []byte(sender.AID())).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d relay rows contain the sender AID", n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM relay_message WHERE to_aid=?`, recip.AID()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the envelope was not stored for its recipient: %d %v", n, err)
	}
}

// An ack deletes the row, for the acking recipient only, and a deleted id
// is never handed out again.
func TestAnAckDeletesTheRow(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	for i := 0; i < 2; i++ {
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte{byte(i)})); code != 200 {
			t.Fatalf("send: %d %s", code, b)
		}
	}
	p := relayPoll(t, srv, recip)
	if len(p.Messages) != 2 {
		t.Fatalf("polled %d", len(p.Messages))
	}
	// Somebody else acking the recipient's ids deletes nothing.
	if n := relayAck(t, srv, sender, p.Messages[0].ID, p.Messages[1].ID); n != 0 {
		t.Fatalf("a stranger's ack deleted %d rows", n)
	}
	last := p.Messages[1].ID
	if n := relayAck(t, srv, recip, p.Messages[0].ID, last); n != 2 {
		t.Fatalf("acked %d, want 2", n)
	}
	db := openDB(t, dir)
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM relay_message`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("after ack %d rows remain (%v); an ack deletes", rows, err)
	}
	// A repeated ack is harmless and a new message gets a fresh id.
	if n := relayAck(t, srv, recip, last); n != 0 {
		t.Fatalf("a repeated ack deleted %d", n)
	}
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), []byte("next"))); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	if next := relayPoll(t, srv, recip); len(next.Messages) != 1 || next.Messages[0].ID <= last {
		t.Fatalf("a deleted id was reused: %+v (last %d)", next.Messages, last)
	}
}

// An envelope nobody collects is deleted after the TTL, by the janitor.
func TestUndeliveredEnvelopesExpire(t *testing.T) {
	srv, store := newHubWithStore(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), testEnvelope(t, recip.AID(), nil)); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	// Inside the TTL nothing is purged.
	if n, err := store.PurgeExpiredRelay(time.Hour, time.Now()); err != nil || n != 0 {
		t.Fatalf("a fresh envelope was purged: %d %v", n, err)
	}
	// The janitor with a TTL that has passed.
	l := aghub.DefaultLimits()
	l.UndeliveredTTL = time.Millisecond
	s := serverOf(t, srv)
	if err := s.SetLimits(l); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.RunRelayJanitor(ctx, time.Hour) // one pass, then ctx is done
	if n, _ := store.RelayPending(recip.AID()); n != 0 {
		t.Fatalf("%d expired envelopes survived the janitor", n)
	}
}

// With secure_delete an acked envelope's bytes are gone from the database
// file, not only unreachable through SQL.
func TestAnAckedEnvelopeLeavesNoBytesOnDisk(t *testing.T) {
	dir := t.TempDir()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	recip, _ := twoAgents(t)
	kel, _ := identity.MarshalKEL(recip.KEL())
	if err := store.PutAgent(recip.AID(), "Recipient", nil, kel); err != nil {
		t.Fatal(err)
	}
	canary := []byte("CANARY-" + strings.Repeat("7f3a", 64))
	id, err := store.RelayEnqueue(recip.AID(), testEnvelope(t, recip.AID(), canary))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := store.RelayAck(recip.AID(), []int64{id}); err != nil || n != 1 {
		t.Fatalf("ack: %d %v", n, err)
	}
	// While the hub is running, after the WAL checkpoint that
	// deploy/hub-db-roll.sh runs. Until that checkpoint the WAL still holds
	// the frame the insert wrote; the checkpoint copies the zeroed page
	// into hub.db and truncates the WAL. Reading only after Close would
	// not test the WAL at all: closing the last connection checkpoints and
	// deletes it.
	db := openDB(t, dir)
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"hub.db", "hub.db-wal"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if bytes.Contains(b, canary) {
			t.Errorf("%s still holds the acked envelope's bytes after the checkpoint", f)
		}
	}
	db.Close()
	store.Close()
	b, err := os.ReadFile(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, canary) {
		t.Error("hub.db still holds the acked envelope's bytes after the store closed")
	}
}

// A wire-1 relay table is rebuilt empty: no wire-1 row survives, delivered
// or not, because each is a plaintext payload no wire-2 daemon can open
// (SI-1; 05-hub H5). The migration records what it dropped in hub_meta,
// neither payload is left in the files, and new ids continue above the
// old ones.
func TestAWire1RelayTableIsMigrated(t *testing.T) {
	dir := t.TempDir()
	old, err := sql.Open("sqlite", filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	recip, sender := twoAgents(t)
	delivered := []byte("DELIVERED-CANARY-" + strings.Repeat("9c", 128))
	waiting := []byte("UNDELIVERED-CANARY-" + strings.Repeat("7e", 128))
	for _, q := range []string{
		`CREATE TABLE relay_message (id INTEGER PRIMARY KEY AUTOINCREMENT, to_aid TEXT NOT NULL,
		   from_aid TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL, interaction_id TEXT NOT NULL DEFAULT '',
		   payload BLOB NOT NULL, created_at TEXT NOT NULL, delivered_at TEXT)`,
		`CREATE INDEX idx_relay_mailbox ON relay_message(to_aid, delivered_at, id)`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ins := `INSERT INTO relay_message(id,to_aid,from_aid,kind,interaction_id,payload,created_at,delivered_at) VALUES(?,?,?,?,?,?,?,?)`
	if _, err := old.Exec(ins, 12, recip.AID(), sender.AID(), "delegate", "ix-old", delivered,
		"2026-09-01T10:00:00.123456789Z", "2026-09-01T10:01:00Z"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{9, 10} {
		if _, err := old.Exec(ins, id, recip.AID(), sender.AID(), "message", "ix-old", waiting,
			"2026-09-20T08:00:00.5Z", nil); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	before := time.Now().UnixMilli()
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatalf("open migrates: %v", err)
	}
	// While the hub is running: the migration checkpointed the WAL into
	// the main file, whose freed pages secure_delete zeroed.
	if b, err := os.ReadFile(filepath.Join(dir, "hub.db")); err != nil || bytes.Contains(b, delivered) || bytes.Contains(b, waiting) {
		t.Errorf("hub.db still holds a wire-1 payload while the migrated hub runs (%v)", err)
	}
	db := openDB(t, dir)
	var cols []string
	rows, _ := db.Query(`SELECT name FROM pragma_table_info('relay_message')`)
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		cols = append(cols, c)
	}
	rows.Close()
	sort.Strings(cols)
	if strings.Join(cols, ",") != "created_at,id,payload,size,to_aid" {
		t.Fatalf("columns after migration: %v", cols)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM relay_message`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows after migration: %d %v, want none: an undelivered wire-1 row is plaintext", n, err)
	}
	// The record the operator reads afterwards.
	for key, want := range map[string]string{
		aghub.MetaRelayV2DroppedUndelivered: "2",
		aghub.MetaRelayV2DroppedDelivered:   "1",
	} {
		if v, ok, err := store.Meta(key); err != nil || !ok || v != want {
			t.Errorf("hub_meta %s = %q (set %v, %v), want %q", key, v, ok, err, want)
		}
	}
	at, ok, err := store.Meta(aghub.MetaRelayV2MigratedAt)
	if ms, perr := strconv.ParseInt(at, 10, 64); err != nil || !ok || perr != nil || ms < before || ms > time.Now().UnixMilli() {
		t.Errorf("hub_meta %s = %q (set %v, %v), want the migration instant in unix ms",
			aghub.MetaRelayV2MigratedAt, at, ok, err)
	}
	kel, _ := identity.MarshalKEL(recip.KEL())
	if err := store.PutAgent(recip.AID(), "Recipient", nil, kel); err != nil {
		t.Fatal(err)
	}
	next, err := store.RelayEnqueue(recip.AID(), testEnvelope(t, recip.AID(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if next <= 12 {
		t.Fatalf("a new envelope got id %d, reusing the pre-migration id space (highest was 12)", next)
	}
	store.Close()
	db.Close()
	// A second open finds nothing to migrate and leaves the record as it is.
	again, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _ := again.Meta(aghub.MetaRelayV2MigratedAt); v != at {
		t.Errorf("reopening rewrote %s: %q, was %q", aghub.MetaRelayV2MigratedAt, v, at)
	}
	again.Close()
	for _, f := range []string{"hub.db", "hub.db-wal"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		if bytes.Contains(b, delivered) {
			t.Errorf("%s still holds a delivered wire-1 payload after migration", f)
		}
		if bytes.Contains(b, waiting) {
			t.Errorf("%s still holds an undelivered wire-1 payload after migration", f)
		}
		if bytes.Contains(b, []byte("ix-old")) {
			t.Errorf("%s still holds a wire-1 interaction id after migration", f)
		}
	}
}

// ---- KEL extension on /register ----

// The KEL a hub holds may only grow: a shorter or forked KEL for a
// registered AID is refused with 409, and the same or a longer one is
// accepted.
func TestRegistrationRefusesAKELThatDoesNotExtendTheStoredOne(t *testing.T) {
	srv := newHub(t)
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	before, err := identity.Restore(blob) // the same identity, not yet rotated
	if err != nil {
		t.Fatal(err)
	}
	forked, err := identity.Restore(blob)
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, c, "Agent", nil)
	if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
		t.Fatal(err)
	}
	if code, b := registerWithCard(t, srv, c, "Agent", nil, nil); code != 200 {
		t.Fatalf("a longer KEL was refused: %d %s", code, b)
	}
	if code, b := registerWithCard(t, srv, c, "Agent", nil, nil); code != 200 {
		t.Fatalf("the same KEL again was refused: %d %s", code, b)
	}
	// Rollback: the pre-rotation KEL, signed by the pre-rotation key.
	code, b := registerWithCard(t, srv, before, "Agent", nil, nil)
	if code != http.StatusConflict || !strings.Contains(string(b), "rollback") {
		t.Errorf("a rolled-back KEL: %d %s, want 409 naming the rollback", code, b)
	}
	// Fork: the same pre-rotation state rotated differently.
	if err := forked.Rotate(uint64(time.Now().UnixMilli()) + 1); err != nil {
		t.Fatal(err)
	}
	code, b = registerWithCard(t, srv, forked, "Agent", nil, nil)
	if code != http.StatusConflict || !strings.Contains(string(b), "fork") {
		t.Errorf("a forked KEL: %d %s, want 409 naming the fork", code, b)
	}
	// The stored KEL is still the rotated one.
	defer func() {
		// An agent that left keeps its KEL as evidence; coming back with a
		// shorter one is the same rollback.
		if code, b := leave(t, srv, c); code != 200 {
			t.Fatalf("leave: %d %s", code, b)
		}
		if code, b := registerWithCard(t, srv, before, "Agent", nil, nil); code != http.StatusConflict {
			t.Errorf("re-registering after leaving with a rolled-back KEL: %d %s, want 409", code, b)
		}
	}()
	resp, err := http.Get(srv.URL + "/agents/" + c.AID() + "/kel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		KEL string `json:"kel"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	raw, _ := base64.StdEncoding.DecodeString(out.KEL)
	events, _ := identity.UnmarshalKEL(raw)
	if len(events) != 2 {
		t.Errorf("stored KEL has %d events, want the rotated 2", len(events))
	}
}

// ---- encryption keys ----

// The publisher rule: strictly greater seq stores, the same set again is
// a 200 no-op, anything else is 409; a set that does not verify for the
// agent is 400.
func TestKeyPublisherRules(t *testing.T) {
	srv := newHub(t)
	c, other := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	register(t, srv, other, "Other", nil)

	status := func(code int, b []byte) string {
		var out struct {
			KeysStatus string `json:"keys_status"`
		}
		_ = json.Unmarshal(b, &out)
		return strconv.Itoa(code) + " " + out.KeysStatus
	}
	k10, _ := mintKeySet(t, c, 10)
	if got := status(publishKeys(t, srv, c, k10)); got != "200 ok" {
		t.Fatalf("first set: %s", got)
	}
	if got := status(publishKeys(t, srv, c, k10)); got != "200 unchanged" {
		t.Fatalf("the same set again: %s, want 200 unchanged", got)
	}
	k9, _ := mintKeySet(t, c, 9)
	if code, b := publishKeys(t, srv, c, k9); code != http.StatusConflict {
		t.Errorf("a lower seq: %d %s, want 409", code, b)
	}
	k10b, _ := mintKeySet(t, c, 10)
	if code, b := publishKeys(t, srv, c, k10b); code != http.StatusConflict {
		t.Errorf("the stored seq with other content: %d %s, want 409", code, b)
	}
	// A set for another AID, and a set signed by another key, are refused
	// even when their seq would advance.
	foreign, _ := mintKeySet(t, other, 20)
	if code, b := publishKeys(t, srv, c, foreign); code != http.StatusBadRequest {
		t.Errorf("another AID's set: %d %s, want 400", code, b)
	}
	if code, b := publishKeys(t, srv, c, []byte("not a key set")); code != http.StatusBadRequest {
		t.Errorf("garbage: %d %s, want 400", code, b)
	}
	k11, _ := mintKeySet(t, c, 11)
	if got := status(publishKeys(t, srv, c, k11)); got != "200 ok" {
		t.Fatalf("a higher seq: %s", got)
	}
	// The agent cannot publish for somebody else.
	if code, b := signedDo(t, srv, c, relayauth.ActionKeys, http.MethodPost, "/agents/"+other.AID()+"/keys",
		map[string]any{"keyset": base64.StdEncoding.EncodeToString(k11)}); code != http.StatusUnauthorized {
		t.Errorf("publishing on another agent's path: %d %s, want 401", code, b)
	}
	// GET returns the stored set with the KEL it verifies against.
	code, b := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys")
	if code != 200 {
		t.Fatalf("get keys: %d %s", code, b)
	}
	var view aghub.KeysView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(view.KeySet)
	if !bytes.Equal(raw, k11) {
		t.Error("GET does not return the newest set")
	}
	kelRaw, _ := base64.StdEncoding.DecodeString(view.KEL)
	events, err := identity.UnmarshalKEL(kelRaw)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := seal.UnmarshalSignedEncKeySet(raw)
	if _, err := seal.VerifyEncKeySet(signed, c.AID(), events, uint64(time.Now().UnixMilli())); err != nil {
		t.Errorf("the served set does not verify against the served KEL: %v", err)
	}
}

// /register carries the key set and the A2A card as optional fields
// whose problems are reported, not fatal.
func TestRegisterReportsKeysAndCardPerField(t *testing.T) {
	srv := newHub(t)
	c, other := twoAgents(t)
	regWith := func(extra map[string]any) (int, aghub.RegisterResponse) {
		body := registerBody(t, c, "Agent", nil)
		for k, v := range extra {
			body[k] = v
		}
		code, b := signedDo(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register", body)
		var out aghub.RegisterResponse
		_ = json.Unmarshal(b, &out)
		return code, out
	}
	k5, _ := mintKeySet(t, c, 5)
	// A card that does not verify is reported and does not fail the
	// registration or the key set beside it (registry_test.go covers
	// admission itself).
	card := json.RawMessage(`{"name":"Agent","signatures":[{"protected":"x","signature":"y"}]}`)
	code, out := regWith(map[string]any{"enc_keys": base64.StdEncoding.EncodeToString(k5), "a2a_card": card})
	if code != 200 || out.KeysStatus != aghub.KeysStatusOK || out.CardStatus != aghub.CardStatusInvalid || out.CardError == "" {
		t.Fatalf("first registration: %d %+v", code, out)
	}
	// A restarted daemon re-registers with the same set.
	if code, out = regWith(map[string]any{"enc_keys": base64.StdEncoding.EncodeToString(k5)}); code != 200 || out.KeysStatus != aghub.KeysStatusUnchanged {
		t.Fatalf("re-registration with the same set: %d %+v", code, out)
	}
	// A stale set does not fail the registration.
	k4, _ := mintKeySet(t, c, 4)
	if code, out = regWith(map[string]any{"enc_keys": base64.StdEncoding.EncodeToString(k4)}); code != 200 || out.KeysStatus != aghub.KeysStatusConflict || out.KeysError == "" {
		t.Fatalf("stale set: %d %+v", code, out)
	}
	foreign, _ := mintKeySet(t, other, 50)
	if code, out = regWith(map[string]any{"enc_keys": base64.StdEncoding.EncodeToString(foreign), "a2a_card": json.RawMessage(`"not an object"`)}); code != 200 ||
		out.KeysStatus != aghub.KeysStatusInvalid || out.CardStatus != aghub.CardStatusInvalid {
		t.Fatalf("foreign set and a non-object card: %d %+v", code, out)
	}
	if code, out = regWith(nil); code != 200 || out.KeysStatus != aghub.KeysStatusAbsent || out.CardStatus != aghub.CardStatusAbsent {
		t.Fatalf("no optional fields: %d %+v", code, out)
	}
	// The stored set is still the seq-5 one.
	_, b := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys")
	var view aghub.KeysView
	_ = json.Unmarshal(b, &view)
	if raw, _ := base64.StdEncoding.DecodeString(view.KeySet); !bytes.Equal(raw, k5) {
		t.Error("a refused set replaced the stored one")
	}
}

// Keys are 404 for an agent that has published none and for an AID
// nobody knows, and a registered agent's keys come from its registration.
func TestKeysLookupSources(t *testing.T) {
	srv := newHub(t)
	c, nobody := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	if code, b := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("an agent without keys: %d %s, want 404", code, b)
	}
	if code, b := getJSON(t, srv.URL+"/agents/"+nobody.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("an unknown AID: %d %s, want 404", code, b)
	}
}

// Leaving removes the key set with the rest of the routing.
func TestLeavingRemovesTheKeySet(t *testing.T) {
	dir := t.TempDir()
	srv, _, _ := newHubAt(t, dir)
	c, _ := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	k, _ := mintKeySet(t, c, 1)
	if code, b := publishKeys(t, srv, c, k); code != 200 {
		t.Fatalf("publish: %d %s", code, b)
	}
	if code, b := leave(t, srv, c); code != 200 {
		t.Fatalf("leave: %d %s", code, b)
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("a departed agent's keys are still served: %d", code)
	}
	var n int
	if err := openDB(t, dir).QueryRow(`SELECT COUNT(*) FROM agent_keys WHERE aid=?`, c.AID()).Scan(&n); err != nil || n != 0 {
		t.Errorf("a departed agent's key set is still stored: %d %v", n, err)
	}
}

// ---- end to end: a real sealed message through the relay ----

// A real sealed envelope goes through send, poll and ack unchanged, and the
// recipient opens it with the key it published. The hub never held a key
// that opens it.
func TestARealSealedMessageCrossesTheRelay(t *testing.T) {
	srv := newHub(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	recipKeys, kp := mintKeySet(t, recip, 1)
	if code, b := publishKeys(t, srv, recip, recipKeys); code != 200 {
		t.Fatalf("publish: %d %s", code, b)
	}
	senderKeys, _ := mintKeySet(t, sender, 1)

	// The sender resolves the recipient's key as a daemon does.
	_, b := getJSON(t, srv.URL+"/agents/"+recip.AID()+"/keys")
	var view aghub.KeysView
	_ = json.Unmarshal(b, &view)
	raw, _ := base64.StdEncoding.DecodeString(view.KeySet)
	kelRaw, _ := base64.StdEncoding.DecodeString(view.KEL)
	events, _ := identity.UnmarshalKEL(kelRaw)
	signed, _ := seal.UnmarshalSignedEncKeySet(raw)
	set, err := seal.VerifyEncKeySet(signed, recip.AID(), events, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	key, err := seal.SelectKey(set, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	env := sealFrom(t, sender, senderKeys, recip.AID(), key, []byte("the task text"))
	if code, b, _ := relaySend(t, srv, sender, recip.AID(), env); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	p := relayPoll(t, srv, recip)
	got, _ := base64.StdEncoding.DecodeString(p.Messages[0].Envelope)
	opened, err := seal.Open(got, recip.AID(), seal.StaticKeyRing{kp})
	if err != nil {
		t.Fatalf("the recipient cannot open what the relay delivered: %v", err)
	}
	if string(opened.Inner.Body) != "the task text" || opened.Inner.From != sender.AID() {
		t.Fatalf("opened %+v", opened.Inner)
	}
}

// /register is limited per client address, so a caller cannot mint new
// senders faster than the limit to get fresh send buckets ([C15f]). Behind
// the loopback reverse proxy the address is X-Real-IP.
func TestRegistrationIsRateLimitedPerClientIP(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.RegisterPerMinute, l.RegisterBurst = 1, 2
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	reg := func(ip string) (int, http.Header) {
		c, _ := identity.Incept()
		req := signedRequest(t, srv, c, relayauth.ActionRegister, http.MethodPost, "/register",
			registerBody(t, c, "Fresh", nil))
		req.Header.Set("X-Real-IP", ip)
		code, _, hdr := send(t, req)
		return code, hdr
	}
	for i := 0; i < 2; i++ {
		if code, _ := reg("203.0.113.1"); code != 200 {
			t.Fatalf("registration %d within the burst: %d", i, code)
		}
	}
	code, hdr := reg("203.0.113.1")
	if code != http.StatusTooManyRequests {
		t.Fatalf("registration past the burst: %d, want 429", code)
	}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q", hdr.Get("Retry-After"))
	}
	if code, _ := reg("203.0.113.2"); code != 200 {
		t.Errorf("another address was limited by the first one's bucket: %d", code)
	}
}

// Naming another sender in the header does not spend that sender's
// tokens: an unauthenticated request takes nothing from the bucket.
func TestAForgedSenderHeaderDoesNotDrainTheBucket(t *testing.T) {
	srv := newHub(t)
	l := aghub.DefaultLimits()
	l.SendRate, l.SendBurst = 0.01, 2
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	recip, victim := twoAgents(t)
	attacker, _ := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, victim, "Victim", nil)
	// The victim spends one of its two tokens, so its bucket exists and
	// holds one.
	if code, b, _ := relaySend(t, srv, victim, recip.AID(), testEnvelope(t, recip.AID(), []byte("first"))); code != 200 {
		t.Fatalf("the victim's first send: %d %s", code, b)
	}
	for i := 0; i < 3; i++ {
		env := testEnvelope(t, recip.AID(), []byte{byte(i)})
		body := rawBody(t, map[string]any{"to_aid": recip.AID(), "envelope": base64.StdEncoding.EncodeToString(env)})
		req := newRequest(t, srv, http.MethodPost, "/relay/send", body)
		signV2(t, req, attacker, relayauth.ActionSend, hubAIDOf(t, srv), body, signingNow())
		req.Header.Set(relayauth.HeaderAID, victim.AID())
		if code, _, _ := send(t, req); code != http.StatusUnauthorized {
			t.Fatalf("forged send %d: %d, want 401", i, code)
		}
	}
	if code, b, _ := relaySend(t, srv, victim, recip.AID(), testEnvelope(t, recip.AID(), []byte("mine"))); code != 200 {
		t.Fatalf("the victim's own send after forged ones: %d %s", code, b)
	}
	// And its bucket is now empty: the next one is refused before the body
	// is read.
	if code, _, _ := relaySend(t, srv, victim, recip.AID(), testEnvelope(t, recip.AID(), []byte("again"))); code != http.StatusTooManyRequests {
		t.Fatalf("third send with a two-token bucket: %d, want 429", code)
	}
}

// /relay/poll with after_id (A2A-DESIGN §3.7, decision Q1): only envelopes
// queued after the cursor, oldest first, under the same limit and byte
// budget; no after_id is the whole mailbox, as before. The cursor is what
// lets a daemon read past envelopes it has to leave in the mailbox for now
// (§3.6 class T) instead of being handed the same oldest page forever.
func TestAPollAfterACursorReturnsOnlyLaterEnvelopes(t *testing.T) {
	srv := newHub(t)
	recip, sender := twoAgents(t)
	register(t, srv, recip, "Recipient", nil)
	register(t, srv, sender, "Sender", nil)
	for i := 0; i < 5; i++ {
		env := testEnvelope(t, recip.AID(), []byte{byte('a' + i)})
		if code, b, _ := relaySend(t, srv, sender, recip.AID(), env); code != 200 {
			t.Fatalf("send %d: %d %s", i, code, b)
		}
	}
	poll := func(body map[string]any) (int, polled) {
		t.Helper()
		code, b := signedDo(t, srv, recip, relayauth.ActionPoll, http.MethodPost, "/relay/poll", body)
		var p polled
		if code == http.StatusOK {
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatal(err)
			}
		}
		return code, p
	}
	idsOf := func(p polled) []int64 {
		out := make([]int64, 0, len(p.Messages))
		for _, m := range p.Messages {
			out = append(out, m.ID)
		}
		return out
	}
	equal := func(a, b []int64) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// No cursor, and a zero cursor: the whole mailbox, oldest first.
	all := idsOf(relayPoll(t, srv, recip))
	if len(all) != 5 {
		t.Fatalf("a poll without after_id returned %d envelopes, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i] <= all[i-1] {
			t.Fatalf("ids not ascending: %v", all)
		}
	}
	if _, p := poll(map[string]any{"after_id": 0}); !equal(idsOf(p), all) {
		t.Fatalf("after_id 0 returned %v, want the whole mailbox %v", idsOf(p), all)
	}

	// After the second id: the last three, still oldest first.
	if _, p := poll(map[string]any{"after_id": all[1]}); !equal(idsOf(p), all[2:]) {
		t.Fatalf("after_id %d returned %v, want %v", all[1], idsOf(p), all[2:])
	}
	// The limit counts from the cursor.
	if _, p := poll(map[string]any{"after_id": all[0], "limit": 2}); !equal(idsOf(p), all[1:3]) {
		t.Fatalf("after_id %d limit 2 returned %v, want %v", all[0], idsOf(p), all[1:3])
	}
	// Past the tail: nothing, and nothing was removed by asking.
	if code, p := poll(map[string]any{"after_id": all[4]}); code != 200 || len(p.Messages) != 0 {
		t.Fatalf("after the last id: %d, %d envelopes; want 200 and none", code, len(p.Messages))
	}
	// A cursor that names an id already acked still works: ids are never
	// reused, so "above it" is still "queued after it".
	if n := relayAck(t, srv, recip, all[2]); n != 1 {
		t.Fatalf("ack: %d rows", n)
	}
	if _, p := poll(map[string]any{"after_id": all[2]}); !equal(idsOf(p), all[3:]) {
		t.Fatalf("after an acked id returned %v, want %v", idsOf(p), all[3:])
	}
	if got := idsOf(relayPoll(t, srv, recip)); !equal(got, []int64{all[0], all[1], all[3], all[4]}) {
		t.Fatalf("the rows before the cursor were touched: %v", got)
	}
	// A negative cursor is a malformed request.
	if code, _ := poll(map[string]any{"after_id": -1}); code != http.StatusBadRequest {
		t.Fatalf("after_id -1: %d, want 400", code)
	}

	// The byte budget counts from the cursor too, and the first envelope
	// after it is returned even when it alone is over the budget.
	l := aghub.DefaultLimits()
	l.PollBudget = 1000
	if err := serverOf(t, srv).SetLimits(l); err != nil {
		t.Fatal(err)
	}
	var big []int64
	for i, n := range []int{1500, 300} {
		env := testEnvelope(t, recip.AID(), bytes.Repeat([]byte{byte('p' + i)}, n))
		code, b, _ := relaySend(t, srv, sender, recip.AID(), env)
		if code != 200 {
			t.Fatalf("send big %d: %d %s", i, code, b)
		}
		var out struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		big = append(big, out.ID)
	}
	if _, p := poll(map[string]any{"after_id": all[4]}); !equal(idsOf(p), big[:1]) {
		t.Fatalf("after_id %d under a 1000-byte budget returned %v, want only %v", all[4], idsOf(p), big[:1])
	}
	if _, p := poll(map[string]any{"after_id": big[0]}); !equal(idsOf(p), big[1:]) {
		t.Fatalf("after_id %d returned %v, want %v", big[0], idsOf(p), big[1:])
	}
}
