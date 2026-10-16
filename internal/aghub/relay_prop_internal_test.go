package aghub

// The relay's properties under random traffic (sealed-sender §7.2):
//
//	P-SS-1 no mail is swallowed (SI-15)
//	P-SS-2 no holder is starved by somebody else's refusals (SI-16)
//	P-SS-3 non-contact traffic never keeps contact mail out (SI-14)
//
// and what a send leaves in the logs and the database (SSR-H7, SSR-H19, M13).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/seal"
)

// propSeeds is how many random histories each property runs.
const propSeeds = 12

// P-SS-1: every 2xx leaves the envelope in the mailbox until the recipient
// takes it; every refused send succeeds once what refused it is over. The
// history mixes sends of a few envelopes (so that copies meet), acks, a full
// non-contact share, a mailbox that fills, the process dying between the
// redelivery count and the row, and a restore from a backup without the
// relay tables.
func TestPropertyNoMailIsSwallowed(t *testing.T) {
	for seed := int64(1); seed <= propSeeds; seed++ {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) { propNoSwallow(t, seed) })
	}
}

func propNoSwallow(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	sc := newScene(t)
	h := sc.h
	pool := make([][]byte, 8)
	digests := make([][32]byte, len(pool))
	for i := range pool {
		pool[i] = envelope(t, sc.recip.aid, []byte(fmt.Sprintf("pool %d %d", seed, i)))
		digests[i], _ = seal.EnvDigest(pool[i])
	}
	// What the hub said about each envelope: queued (or duplicate) and
	// not yet taken by the recipient, or refused.
	owed := map[int]bool{}
	refused := map[int]bool{}
	fault := false
	enqueueFault = func() error {
		if fault {
			return errors.New("the process died here")
		}
		return nil
	}
	defer func() { enqueueFault = nil }()
	send := func(i int) {
		var rec *httptest.ResponseRecorder
		switch rng.Intn(3) {
		case 0:
			rec = h.send0(sc.ss, pool[i], kind0Opts{})
		case 1:
			rec = sc.send1(pool[i], sc.contact)
		default:
			rec = sc.send1(pool[i], sc.stranger)
		}
		switch {
		case rec.Code == 200:
			owed[i], refused[i] = true, false
		case rec.Code >= 500 && rec.Code != http.StatusInsufficientStorage:
			if !fault {
				t.Fatalf("send %d: %d %s", i, rec.Code, rec.Body)
			}
			if !owed[i] {
				refused[i] = true
			}
		default:
			if !owed[i] {
				refused[i] = true
			}
		}
	}
	for step := 0; step < 120; step++ {
		fault = false
		switch op := rng.Intn(10); {
		case op < 5:
			send(rng.Intn(len(pool)))
		case op == 5: // the recipient takes its mail
			msgs, _, err := h.store.RelayPoll(sc.recip.aid, 0, 1000, 1<<30)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range msgs {
				if rng.Intn(2) == 0 {
					continue
				}
				d, _ := seal.EnvDigest(m.Payload)
				if _, err := h.store.RelayAck(sc.recip.aid, []int64{m.ID}); err != nil {
					t.Fatal(err)
				}
				for i := range digests {
					if digests[i] == d {
						owed[i] = false
					}
				}
			}
		case op == 6: // the mailbox fills up, or has room again
			l := DefaultLimits()
			if rng.Intn(2) == 0 {
				n, _ := h.store.RelayPending(sc.recip.aid)
				l.MailboxMessages = n + rng.Intn(2)
				if l.MailboxMessages == 0 {
					l.MailboxMessages = 1
				}
			}
			if err := h.srv.SetLimits(l); err != nil {
				t.Fatal(err)
			}
		case op == 7: // non-contact mail from others fills the share
			for k := 0; k < rng.Intn(3)*250; k++ {
				_, _ = h.store.QueueEnvelope(sc.recip.aid, envelope(t, sc.recip.aid, []byte(fmt.Sprintf("noise %d %d", step, k))))
			}
		case op == 8: // the process dies between the count and the row
			fault = true
			send(rng.Intn(len(pool)))
		case op == 9: // restored from a backup without the relay tables
			if rng.Intn(4) == 0 {
				for _, q := range []string{`DELETE FROM relay_message`, `DELETE FROM relay_redelivery`} {
					if _, err := h.store.db.Exec(q); err != nil {
						t.Fatal(err)
					}
				}
				h.restart()
				sc.ss = h.openSession(sc.sender.c)
				// What was owed is gone with the backup: the sender learns
				// it is unknown and sends again (ENG-D8).
				for i := range owed {
					if owed[i] {
						owed[i], refused[i] = false, true
					}
				}
			} else {
				h.advance(time.Duration(rng.Intn(120)) * time.Second)
			}
		}
		// Every envelope the hub took and the recipient has not is there.
		for i, o := range owed {
			if !o {
				continue
			}
			if _, ok, err := h.store.RelayQueued(sc.recip.aid, digests[i]); err != nil || !ok {
				t.Fatalf("step %d: envelope %d was answered 2xx and is not in the mailbox (%v)", step, i, err)
			}
		}
	}
	// Whatever refused a send is over: the mailbox has room, a day has
	// passed (the buckets are full, the redelivery windows closed), and the
	// noise was taken. Every refused envelope goes through now.
	fault = false
	if err := h.srv.SetLimits(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`DELETE FROM relay_message WHERE to_aid=?`, sc.recip.aid); err != nil {
		t.Fatal(err)
	}
	h.advance(RedeliveryWindow + time.Hour)
	sc.ss = h.openSession(sc.sender.c)
	sc.contact = h.issue(sc.recip, seal.CapClassContact, 7*24*time.Hour)
	for i, r := range refused {
		if !r {
			continue
		}
		if rec := sc.send1(pool[i], sc.contact); rec.Code != 200 {
			t.Fatalf("envelope %d, refused before, is refused again once nothing stands in its way: %d %s", i, rec.Code, rec.Body)
		}
	}
}

// P-SS-2: random forged proofs, replays, credentials of an old epoch and
// genuine sends, from a few addresses. The genuine holder's bucket goes down
// only by its own sends that were queued; a refusal takes no token; an
// address's failure bucket goes down only by the 403s it was answered; and
// an address whose failure bucket is empty is answered 429, never 403.
func TestPropertyNoHolderIsStarved(t *testing.T) {
	for seed := int64(1); seed <= propSeeds; seed++ {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) { propNoStarve(t, seed) })
	}
}

func propNoStarve(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	sc := newScene(t)
	h := sc.h
	old := h.issue(sc.recip, seal.CapClassContact, 7*24*time.Hour)
	h.publish(sc.recip, 2)
	holder := h.issue(sc.recip, seal.CapClassContact, 7*24*time.Hour)
	addrs := []string{"192.0.2.1", "192.0.2.2", "2001:db8:5::1", "2001:db8:5::2"} // the last two share a /64
	key := func(ip string) string { return rateKeyOfString(ip) }
	failures := map[string]int{}
	queued := 0
	var lastGenuine []byte
	for step := 0; step < 160; step++ {
		ip := addrs[rng.Intn(len(addrs))]
		before := h.srv.relay.caps.tokens(capKey(&holder.body), rateContactCap)
		emptyBefore := h.srv.relay.addrFailure.tokens(key(ip), rateAddrFailure) < 1
		var rec *httptest.ResponseRecorder
		genuine := false
		switch rng.Intn(5) {
		case 0, 1: // the genuine holder
			body := withCap(t, sc.env(), holder)
			rec, genuine = h.send1(body, ip), true
			lastGenuine = body
		case 2: // a proof by another key for the holder's credential
			g := holder
			_, g.holder, _ = ed25519.GenerateKey(nil)
			rec = h.send1(withCap(t, sc.env(), g), ip)
		case 3: // a credential of the old epoch
			rec = h.send1(withCap(t, sc.env(), old), ip)
		default: // a replay of the holder's last request: the holder's
			// own send, if the first copy did not get through
			if lastGenuine == nil {
				continue
			}
			rec, genuine = h.send1(lastGenuine, ip), true
		}
		after := h.srv.relay.caps.tokens(capKey(&holder.body), rateContactCap)
		switch {
		case rec.Code == 200 && genuine && decodeSent(t, rec).Status == RelayQueued:
			queued++
			if after != before-1 {
				t.Fatalf("step %d: a queued send took %v tokens", step, before-after)
			}
		case after != before:
			t.Fatalf("step %d: %d %s changed the holder's bucket %v -> %v", step, rec.Code, rec.Body, before, after)
		}
		if rec.Code == http.StatusForbidden {
			if emptyBefore {
				t.Fatalf("step %d: an address with no refusals left was answered 403", step)
			}
			failures[key(ip)]++
		}
		if emptyBefore && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("step %d: an address with no refusals left was answered %d", step, rec.Code)
		}
		for _, a := range addrs {
			want := rateAddrFailure.burst - float64(failures[key(a)])
			if got := h.srv.relay.addrFailure.tokens(key(a), rateAddrFailure); got != want {
				t.Fatalf("step %d: the failure bucket of %s holds %v, want %v", step, a, got, want)
			}
		}
	}
	if got := h.srv.relay.caps.tokens(capKey(&holder.body), rateContactCap); got != rateContactCap.burst-float64(queued) {
		t.Fatalf("the holder's bucket holds %v after %d sends of its own", got, queued)
	}
}

// P-SS-3: whatever the non-contact traffic (first contacts from several
// senders, stranger credentials, a full non-contact share), contact mail is
// queued while the mailbox as a whole has room.
func TestPropertyContactsGetThrough(t *testing.T) {
	for seed := int64(1); seed <= propSeeds; seed++ {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) { propContacts(t, seed) })
	}
}

func propContacts(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	sc := newScene(t)
	h := sc.h
	var sessions []session
	for i := 0; i < 3; i++ {
		sessions = append(sessions, h.openSession(h.agent().c))
	}
	var strangers, contacts []grant
	for i := 0; i < 4; i++ {
		strangers = append(strangers, h.issue(sc.recip, seal.CapClassStranger, 7*24*time.Hour))
		contacts = append(contacts, h.issue(sc.recip, seal.CapClassContact, 7*24*time.Hour))
	}
	for step := 0; step < 300; step++ {
		switch op := rng.Intn(6); {
		case op == 0:
			h.send0(sessions[rng.Intn(len(sessions))], sc.env(), kind0Opts{})
		case op == 1:
			sc.send1(sc.env(), strangers[rng.Intn(len(strangers))])
		case op == 2:
			for k := 0; k < rng.Intn(200); k++ {
				_, _ = h.store.QueueEnvelope(sc.recip.aid, envelope(t, sc.recip.aid, []byte(fmt.Sprintf("noise %d %d", step, k))))
			}
		case op == 3:
			h.advance(time.Duration(rng.Intn(30)) * time.Second)
		default:
			rec := sc.send1(sc.env(), contacts[rng.Intn(len(contacts))])
			if rec.Code == http.StatusTooManyRequests && reasonOf(rec) == "rate_limited" {
				continue // the contact credential's own bucket, not the strangers'
			}
			if rec.Code != 200 {
				t.Fatalf("step %d: contact mail refused with the mailbox not full: %d %s", step, rec.Code, rec.Body)
			}
		}
	}
}

// TestSendsLeaveNoSenderBehind (SSR-H7, SSR-H19, SI-2, M13): sends of both
// kinds, and their refusals, write no AID, no session id or key, no
// credential id and no holder key to the log; the database holds no session
// id or key and no holder key, and its relay tables do not name the sender.
func TestSendsLeaveNoSenderBehind(t *testing.T) {
	var logged bytes.Buffer
	var mu sync.Mutex
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logged.Write(p) }))
	defer log.SetOutput(os.Stderr)

	sc := newScene(t)
	h := sc.h
	decodeSent(t, h.send0(sc.ss, sc.env(), kind0Opts{}))
	decodeSent(t, sc.send1(sc.env(), sc.contact))
	decodeSent(t, sc.send1(sc.env(), sc.stranger))
	h.send0(sc.ss, sc.env(), kind0Opts{macBody: []byte("x")}) // 401
	g := sc.contact
	_, g.holder, _ = ed25519.GenerateKey(nil)
	sc.send1(sc.env(), g)                                            // 403
	h.send0(sc.ss, envelope(t, sc.sender.aid+"x", nil), kind0Opts{}) // 404
	enqueueFault = func() error { return errors.New("a store failure") }
	h.send0(sc.ss, sc.env(), kind0Opts{}) // 500
	enqueueFault = nil
	// The relay tables do not name the sender.
	for _, q := range []string{
		`SELECT COUNT(*) FROM relay_message WHERE instr(payload, ?) > 0 OR instr(CAST(to_aid AS BLOB), ?) > 0`,
		`SELECT COUNT(*) FROM relay_redelivery WHERE instr(env_digest, ?) > 0 OR instr(env_digest, ?) > 0`,
	} {
		var n int
		if err := h.store.db.QueryRow(q, []byte(sc.sender.aid), []byte(sc.sender.aid)).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows name the sender (%v)", q, n, err)
		}
	}
	// The recipient takes its mail: the envelopes, which carry the
	// credentials, are gone from the files (secure_delete).
	msgs, _, _ := h.store.RelayPoll(sc.recip.aid, 0, 1000, 1<<30)
	for _, m := range msgs {
		if _, err := h.store.RelayAck(sc.recip.aid, []int64{m.ID}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}

	secrets := map[string][]byte{
		"the sender's AID":    []byte(sc.sender.aid),
		"the recipient's AID": []byte(sc.recip.aid),
		"the session id":      sc.ss.sid,
		"the session key":     sc.ss.key,
		"a credential id":     sc.contact.body.CapID,
		"a holder key":        sc.contact.body.Holder,
	}
	spellings := func(b []byte) [][]byte {
		return [][]byte{b, []byte(base64.RawURLEncoding.EncodeToString(b)), []byte(base64.StdEncoding.EncodeToString(b)),
			[]byte(hex.EncodeToString(b)), []byte(fmt.Sprintf("%x", b)), []byte(fmt.Sprintf("%v", b))}
	}
	mu.Lock()
	out := logged.Bytes()
	mu.Unlock()
	for what, b := range secrets {
		for _, sp := range spellings(b) {
			if bytes.Contains(out, sp) {
				t.Errorf("the log holds %s (%q)", what, sp)
			}
		}
	}
	// The database: no session, and once the mail is taken no credential.
	var files []byte
	for _, f := range []string{"hub.db", "hub.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(h.dir, f))
		files = append(files, b...)
	}
	for _, what := range []string{"the session id", "the session key", "a holder key", "a credential id"} {
		for _, sp := range spellings(secrets[what]) {
			if bytes.Contains(files, sp) {
				t.Errorf("hub.db holds %s", what)
			}
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
