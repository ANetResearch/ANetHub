package aghub_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// capIDFor is a 16-byte capability id that differs for each n and tag.
func capIDFor(tag byte, n int) []byte {
	id := make([]byte, seal.CapIDLen)
	id[0] = tag
	binary.BigEndian.PutUint64(id[8:], uint64(n))
	return id
}

func b64ids(ids ...[]byte) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = base64.RawURLEncoding.EncodeToString(id)
	}
	return out
}

// revoke posts /mailbox/revoke as c with body.
func revoke(t *testing.T, srv *httptest.Server, c *identity.Controller, body any) (int, []byte, http.Header) {
	t.Helper()
	return send(t, signedRequest(t, srv, c, relayauth.ActionRevoke, http.MethodPost, "/mailbox/revoke", body))
}

// revoked posts cap ids as c and wants 200 with the given counts.
func revoked(t *testing.T, srv *httptest.Server, c *identity.Controller, ids []string, wantRevoked, wantTotal uint64) {
	t.Helper()
	code, b, _ := revoke(t, srv, c, map[string]any{"cap_ids": ids})
	if code != http.StatusOK {
		t.Fatalf("revoke %d ids: %d %s", len(ids), code, b)
	}
	var out aghub.MailboxRevokeResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Revoked != wantRevoked || out.Total != wantTotal {
		t.Fatalf("revoke %d ids: %s, want revoked %d and total %d", len(ids), b, wantRevoked, wantTotal)
	}
}

func refusedWith(t *testing.T, code int, b []byte, wantCode int, reason string) {
	t.Helper()
	var out struct {
		Reason string `json:"reason"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(b, &out); err != nil || code != wantCode || out.Reason != reason || out.Error == "" {
		t.Fatalf("got %d %s, want %d %s", code, b, wantCode, reason)
	}
}

func revocationCount(t *testing.T, store *aghub.Store, aid string) int {
	t.Helper()
	n, err := store.RevocationCount(aid)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func capRevoked(t *testing.T, store *aghub.Store, owner string, id []byte) bool {
	t.Helper()
	v, err := store.CapRevoked(owner, id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestMailboxRevoke (sealed-sender SSR-H10, core §2.12.2): an owner revokes
// 1 to 1000 capability ids per request; an id given again, in the same
// request or a later one, counts once; revoked is what is new and total
// what the owner has now, which a registration answers as revocations.
// Anything else in the body is 400 bad_request and writes nothing; only a
// registered agent's own signature for "revoke" is accepted.
func TestMailboxRevoke(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, other := twoAgents(t)
	register(t, srv, c, "Owner", nil)
	register(t, srv, other, "Other", nil)

	id1, id2, id3 := capIDFor(1, 1), capIDFor(1, 2), capIDFor(1, 3)
	revoked(t, srv, c, b64ids(id1, id2), 2, 2)
	// A new id given twice and an old one given twice: each counts once.
	revoked(t, srv, c, b64ids(id1, id3, id3, id1), 1, 3)
	revoked(t, srv, c, b64ids(id1), 0, 3)
	var batch [][]byte
	for i := 0; i < aghub.MaxRevokeBatch; i++ {
		batch = append(batch, capIDFor(2, i))
	}
	revoked(t, srv, c, b64ids(batch...), aghub.MaxRevokeBatch, aghub.MaxRevokeBatch+3)

	// What is revoked is the owner's: the same id is not revoked for another.
	if !capRevoked(t, store, c.AID(), id3) || !capRevoked(t, store, c.AID(), batch[999]) {
		t.Error("a revoked id does not read as revoked")
	}
	if capRevoked(t, store, c.AID(), capIDFor(9, 9)) || capRevoked(t, store, other.AID(), id1) {
		t.Error("an id nobody revoked reads as revoked")
	}

	// The registration answer carries the total (SSR-D21).
	_, b := registerFunded(t, srv, c, registerBody(t, c, "Owner", nil))
	var reg aghub.RegisterResponse
	if err := json.Unmarshal(b, &reg); err != nil || reg.Revocations != aghub.MaxRevokeBatch+3 {
		t.Errorf("/register: %s, want revocations %d", b, aghub.MaxRevokeBatch+3)
	}
	_, b = registerFunded(t, srv, other, registerBody(t, other, "Other", nil))
	if !strings.Contains(string(b), `"revocations":0`) {
		t.Errorf("/register of an agent that revoked nothing: %s, want revocations 0", b)
	}

	before := revocationCount(t, store, c.AID())
	tooMany := append(append([][]byte{}, batch...), capIDFor(3, 0))
	for _, bad := range []struct {
		name string
		body any
	}{
		{"1001 ids", map[string]any{"cap_ids": b64ids(tooMany...)}},
		{"no ids", map[string]any{"cap_ids": []string{}}},
		{"no member", map[string]any{}},
		{"a padded id after a good one", map[string]any{"cap_ids": []string{b64ids(capIDFor(4, 0))[0], b64ids(id1)[0] + "=="}}},
		{"an id in the standard alphabet", map[string]any{"cap_ids": []string{base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 16))}}},
		{"a 15-byte id", map[string]any{"cap_ids": []string{base64.RawURLEncoding.EncodeToString(make([]byte, 15))}}},
		{"a 17-byte id", map[string]any{"cap_ids": []string{base64.RawURLEncoding.EncodeToString(make([]byte, 17))}}},
		{"an id that is not a string", map[string]any{"cap_ids": []any{7}}},
		{"an unknown member", map[string]any{"cap_ids": b64ids(capIDFor(4, 1)), "owner": other.AID()}},
	} {
		code, b, _ := revoke(t, srv, c, bad.body)
		refusedWith(t, code, b, http.StatusBadRequest, "bad_request")
		if n := revocationCount(t, store, c.AID()); n != before {
			t.Fatalf("%s: the total went from %d to %d", bad.name, before, n)
		}
	}

	// Authentication: the owner's own signature for "revoke".
	unsigned := newRequest(t, srv, http.MethodPost, "/mailbox/revoke", rawBody(t, map[string]any{"cap_ids": b64ids(capIDFor(5, 0))}))
	code, b, _ := send(t, unsigned)
	refusedWith(t, code, b, http.StatusUnauthorized, "unauthorized")
	code, b, _ = send(t, signedRequest(t, srv, c, relayauth.ActionPoll, http.MethodPost, "/mailbox/revoke",
		map[string]any{"cap_ids": b64ids(capIDFor(5, 0))}))
	refusedWith(t, code, b, http.StatusUnauthorized, "unauthorized")
	stranger, _ := twoAgents(t)
	code, b, _ = revoke(t, srv, stranger, map[string]any{"cap_ids": b64ids(capIDFor(5, 0))})
	refusedWith(t, code, b, http.StatusUnauthorized, "unauthorized")
	if n := revocationCount(t, store, stranger.AID()); n != 0 {
		t.Errorf("an unregistered signer has %d revocations", n)
	}
}

// fillRevocations writes n unexpired revocations for owner straight into the
// table, as n requests would have.
func fillRevocations(t *testing.T, store *aghub.Store, owner string, n int, at time.Time) {
	t.Helper()
	// The ids are capIDFor(0xf0, i) for i in [0, n).
	if _, err := store.DBForTest().Exec(`WITH RECURSIVE k(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM k WHERE i+1 < ?)
	    INSERT INTO cap_revocation(owner, cap_id, revoked_at)
	    SELECT ?, unhex('F000000000000000' || printf('%016X', i)), ? FROM k`, n, owner, at.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	var got int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM cap_revocation WHERE owner=? AND cap_id=?`,
		owner, capIDFor(0xf0, n-1)).Scan(&got); err != nil || got != 1 {
		t.Fatalf("the filled ids are not capIDFor(0xf0, i): %d %v", got, err)
	}
}

// TestRevocationListFull (sealed-sender SSR-H11): an owner has at most
// 100 000 unexpired revocations. A request that would go past them is 429
// revocation_list_full (a wait, with Retry-After) and writes nothing of its
// batch, not even the ids that would fit; ids already revoked do not count
// again; expired revocations do not count.
func TestRevocationListFull(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Owner", nil)
	fillRevocations(t, store, c.AID(), aghub.MaxRevocationsPerOwner-1, time.Now())

	code, b, h := revoke(t, srv, c, map[string]any{"cap_ids": b64ids(capIDFor(1, 1), capIDFor(1, 2))})
	refusedWith(t, code, b, http.StatusTooManyRequests, "revocation_list_full")
	if h.Get("Retry-After") == "" {
		t.Error("revocation_list_full without Retry-After")
	}
	if n := revocationCount(t, store, c.AID()); n != aghub.MaxRevocationsPerOwner-1 {
		t.Fatalf("a refused batch wrote: the total is %d", n)
	}
	if capRevoked(t, store, c.AID(), capIDFor(1, 1)) {
		t.Fatal("an id of the refused batch reads as revoked")
	}
	// One already revoked and one new: exactly at the bound.
	revoked(t, srv, c, b64ids(capIDFor(0xf0, 7), capIDFor(1, 1)), 1, aghub.MaxRevocationsPerOwner)
	revoked(t, srv, c, b64ids(capIDFor(0xf0, 8)), 0, aghub.MaxRevocationsPerOwner)
	code, b, _ = revoke(t, srv, c, map[string]any{"cap_ids": b64ids(capIDFor(1, 2))})
	refusedWith(t, code, b, http.StatusTooManyRequests, "revocation_list_full")

	// Another owner's list is its own.
	d, _ := twoAgents(t)
	register(t, srv, d, "Other", nil)
	revoked(t, srv, d, b64ids(capIDFor(1, 2)), 1, 1)

	// Expired revocations free their places.
	e, _ := twoAgents(t)
	register(t, srv, e, "Expired", nil)
	fillRevocations(t, store, e.AID(), aghub.MaxRevocationsPerOwner, time.Now().Add(-aghub.RevocationKeep))
	revoked(t, srv, e, b64ids(capIDFor(1, 3)), 1, 1)
}

// TestRevocationJanitor31Days (sealed-sender SSR-H10): a revocation counts
// and refuses for 31 days from when it was made, to the millisecond; then it
// no longer counts, the janitor deletes it, and revoking the id again starts
// a new 31 days.
func TestRevocationJanitor31Days(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Owner", nil)
	t0 := time.Now().Truncate(time.Millisecond)
	now := t0
	store.SetClockForTest(func() time.Time { return now })
	id, id2 := capIDFor(1, 1), capIDFor(1, 2)
	if n, total, err := store.RevokeCaps(c.AID(), [][]byte{id, id2}); err != nil || n != 2 || total != 2 {
		t.Fatalf("revoke: %d %d %v", n, total, err)
	}
	purge := func() int64 {
		t.Helper()
		n, err := store.PurgeExpiredRevocations()
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	now = t0.Add(aghub.RevocationKeep - time.Millisecond)
	if !capRevoked(t, store, c.AID(), id) || revocationCount(t, store, c.AID()) != 2 || purge() != 0 {
		t.Fatal("a revocation one millisecond short of 31 days old is not in force")
	}
	// Revoking id2 again inside the 31 days does not restart them.
	if n, _, err := store.RevokeCaps(c.AID(), [][]byte{id2}); err != nil || n != 0 {
		t.Fatalf("revoking a revoked id again: %d %v", n, err)
	}

	now = t0.Add(aghub.RevocationKeep)
	if capRevoked(t, store, c.AID(), id) {
		t.Error("a revocation 31 days old still refuses")
	}
	if n := revocationCount(t, store, c.AID()); n != 0 {
		t.Errorf("31-day-old revocations still count: %d", n)
	}
	// id2 expired too but is revoked again before the sweep: a new 31 days.
	if n, total, err := store.RevokeCaps(c.AID(), [][]byte{id2}); err != nil || n != 1 || total != 1 {
		t.Fatalf("revoking an expired id again: %d %d %v", n, total, err)
	}
	if got := purge(); got != 1 {
		t.Errorf("the sweep deleted %d, want the 1 expired", got)
	}
	var left int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM cap_revocation WHERE owner=?`, c.AID()).Scan(&left); err != nil || left != 1 {
		t.Errorf("rows left after the sweep: %d %v, want only the renewed one", left, err)
	}
	now = t0.Add(2*aghub.RevocationKeep - time.Millisecond)
	if !capRevoked(t, store, c.AID(), id2) {
		t.Error("the renewed revocation lapsed early")
	}
	now = t0.Add(2 * aghub.RevocationKeep)
	if capRevoked(t, store, c.AID(), id2) || purge() != 1 {
		t.Error("the renewed revocation outlived its 31 days")
	}

	// The janitor the hub process runs sweeps at start.
	if _, _, err := store.RevokeCaps(c.AID(), [][]byte{capIDFor(1, 3)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(aghub.RevocationKeep)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { store.RunRevocationJanitor(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		_ = store.DBForTest().QueryRow(`SELECT COUNT(*) FROM cap_revocation`).Scan(&n)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the janitor did not sweep at start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// A send asks CapRevoked through the cache in front of the table: a
// revocation is seen at once, and a deregistration, which deletes the
// owner's revocations (deregSteps), is seen at once in the hub process.
func TestCapRevokedFollowsRevocationsAndDeregistration(t *testing.T) {
	srv, store := newHubWithStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	c, _ := twoAgents(t)
	register(t, srv, c, "Owner", nil)
	id := capIDFor(1, 1)
	for i := 0; i < 3; i++ { // cached as not revoked
		if capRevoked(t, store, c.AID(), id) {
			t.Fatal("revoked before anything was revoked")
		}
	}
	revoked(t, srv, c, b64ids(id), 1, 1)
	if !capRevoked(t, store, c.AID(), id) {
		t.Fatal("a revocation is not seen by the next send")
	}
	if _, err := store.Deregister(c.AID(), aghub.DeregSelf); err != nil {
		t.Fatal(err)
	}
	if capRevoked(t, store, c.AID(), id) {
		t.Error("the revocations of a deregistered owner are still in force")
	}
	if n := revocationCount(t, store, c.AID()); n != 0 {
		t.Errorf("a deregistered owner still has %d revocations", n)
	}
}
