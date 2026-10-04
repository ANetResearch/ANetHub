package aghub

// P-PAY-11 (hub-payment-privacy §7.2): the admission gate of POST /register
// over the whole matrix
//
//	{registered, on the list, window open with room, window full, open, closed}
//	× {proof of work good, bad, missing}
//	× {today's quota of the client's network free, full}
//	× {check_only, not}
//
// Every cell answers with the code PAY-A1 gives it; no refusal writes a row;
// check_only never writes a row; and a registration that passes the gate
// and then fails a later step gives back what the gate reserved.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// gateBits is the proof of work the gate tests ask for, so a test solves
// one in microseconds. TestThePowIsTheConstant pins what production asks.
const gateBits = 8

// gateHub is one hub for gate tests: its store and server, served in
// process.
type gateHub struct {
	t      testing.TB
	dir    string
	store  *Store
	srv    *Server
	h      http.Handler
	hubAID string
	now    time.Time
}

func newGateHub(t testing.TB) *gateHub {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := NewServer(store)
	s.SetHubAID(id.AID)
	l := DefaultLimits()
	l.RegisterPerMinute, l.RegisterBurst = 1e9, 1<<30
	if err := s.SetLimits(l); err != nil {
		t.Fatal(err)
	}
	g := &gateHub{t: t, dir: dir, store: store, srv: s, h: s.Handler(), hubAID: id.AID, now: time.Now()}
	store.clock = func() time.Time { return g.now }
	store.gate().bits = gateBits
	t.Cleanup(func() { store.Close() })
	return g
}

// clientIP is the address every gate request comes from (through the
// loopback proxy's X-Real-IP).
const gateClientIP = "203.0.113.7"

// register sends a /register for c with extra members, signed as signer
// (c when nil), and returns the status and the decoded body.
func (g *gateHub) register(c, signer *identity.Controller, extra map[string]any) (int, map[string]any) {
	g.t.Helper()
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		g.t.Fatal(err)
	}
	body := map[string]any{"aid": c.AID(), "name": "n", "kel": base64.RawURLEncoding.EncodeToString(kel)}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return g.post(c.AID(), signer, raw)
}

var gateSigned int64

// post sends raw to /register with relayauth headers for aid made by signer.
func (g *gateHub) post(aid string, signer *identity.Controller, raw []byte) (int, map[string]any) {
	g.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://hub.test/register", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Real-IP", gateClientIP)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	gateSigned++
	ts := uint64(time.Now().UnixMilli()) + uint64(gateSigned%1000)
	sig, seq := signer.Sign(relayauth.PreimageV2(relayauth.ActionRegister, signer.AID(), g.hubAID, ts,
		req.Method, req.URL.RequestURI(), raw))
	req.Header.Set(relayauth.HeaderAID, aid)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out == nil {
		out = map[string]any{}
	}
	out["_raw"] = rec.Body.String()
	return rec.Code, out
}

// pow is a proof of work for aid: good (solved for this hub and hour), bad
// (a well-formed nonce that does not reach the bits) or missing.
func (g *gateHub) pow(aid, kind string) map[string]any {
	g.t.Helper()
	if kind == "missing" {
		return nil
	}
	seed := g.store.gate().powSeed(regpow.Hour(uint64(g.now.UnixMilli())))
	var nonce []byte
	if kind == "good" {
		n, err := regpow.Solve(context.Background(), g.hubAID, aid, seed, gateBits)
		if err != nil {
			g.t.Fatal(err)
		}
		nonce = n
	} else {
		for i := uint64(0); ; i++ {
			n := []byte(strconv.FormatUint(i, 10))
			if !regpow.Check(g.hubAID, aid, seed, n, gateBits) {
				nonce = n
				break
			}
		}
	}
	return map[string]any{"pow": map[string]any{
		"seed":  base64.RawURLEncoding.EncodeToString(seed[:]),
		"nonce": base64.RawURLEncoding.EncodeToString(nonce),
	}}
}

// fillQuota takes every place of today's open-registration quota at the
// /32 of the gate client's address.
func (g *gateHub) fillQuota() {
	g.t.Helper()
	for i := 0; i < 20; i++ {
		if _, ok := g.store.gate().reserveSignup(net.ParseIP(gateClientIP), g.now); !ok {
			g.t.Fatalf("the quota filled after %d places, want 20", i)
		}
	}
	if _, ok := g.store.gate().reserveSignup(net.ParseIP(gateClientIP), g.now); ok {
		g.t.Fatal("a 21st place of the /32 was given")
	}
}

// dump is every row of every table of hub.db, for "nothing was written".
func (g *gateHub) dump() string {
	g.t.Helper()
	return dumpDB(g.t, g.store.db)
}

func dumpDB(t testing.TB, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	h := sha256.New()
	var b strings.Builder
	for _, tb := range tables {
		r, err := db.Query(`SELECT * FROM "` + tb + `"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := r.Columns()
		var lines []string
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprintf("%v", vals))
		}
		r.Close()
		sort.Strings(lines)
		fmt.Fprintf(&b, "%s: %d rows\n", tb, len(lines))
		for _, l := range lines {
			h.Write([]byte(tb + "\x00" + l + "\n"))
		}
	}
	return b.String() + hex.EncodeToString(h.Sum(nil))
}

// gateState puts a hub into one row of the matrix for c.
func (g *gateHub) gateState(state string, c *identity.Controller) {
	g.t.Helper()
	switch state {
	case "registered":
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := g.store.PutAgent(c.AID(), "registered", nil, kel); err != nil {
			g.t.Fatal(err)
		}
	case "listed":
		if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
			g.t.Fatal(err)
		}
	case "window_open":
		if _, err := g.store.OpenWindow(time.Hour, 5, "matrix"); err != nil {
			g.t.Fatal(err)
		}
	case "window_full":
		w, err := g.store.OpenWindow(time.Hour, 1, "matrix")
		if err != nil {
			g.t.Fatal(err)
		}
		if _, err := g.store.db.Exec(`UPDATE admission_window SET used = max WHERE id=?`, w.ID); err != nil {
			g.t.Fatal(err)
		}
	case "open":
		if err := g.store.SetAdmissionMode(AdmissionOpen); err != nil {
			g.t.Fatal(err)
		}
	case "closed":
	default:
		g.t.Fatalf("no state %q", state)
	}
}

// gateExpect is PAY-A1 for one cell: the status, the reason of a refusal,
// and the check_only answer.
func gateExpect(state, pow, quota string, checkOnly bool) (int, string, string) {
	switch state {
	case "registered", "listed":
		if checkOnly {
			return 200, "", CheckAdmitted
		}
		return 200, "", ""
	case "window_open":
		if checkOnly {
			return 200, "", CheckOpen
		}
		if pow != "good" {
			return 403, "pow_required", ""
		}
		return 200, "", ""
	case "open":
		if checkOnly {
			return 200, "", CheckOpen
		}
		if pow != "good" {
			return 403, "pow_required", ""
		}
		if quota == "full" {
			return 429, "registration_quota", ""
		}
		return 200, "", ""
	}
	return 403, "admission_required", ""
}

// TestAdmissionGateMatrix is P-PAY-11.
func TestAdmissionGateMatrix(t *testing.T) {
	for _, state := range []string{"registered", "listed", "window_open", "window_full", "open", "closed"} {
		for _, pow := range []string{"good", "bad", "missing"} {
			for _, quota := range []string{"free", "full"} {
				for _, checkOnly := range []bool{false, true} {
					name := fmt.Sprintf("%s/pow_%s/quota_%s/check_only_%v", state, pow, quota, checkOnly)
					t.Run(name, func(t *testing.T) {
						g := newGateHub(t)
						c, err := identitytest.Hub()
						if err != nil {
							t.Fatal(err)
						}
						g.gateState(state, c)
						if quota == "full" {
							g.fillQuota()
						}
						extra := g.pow(c.AID(), pow)
						if extra == nil {
							extra = map[string]any{}
						}
						if checkOnly {
							extra["check_only"] = true
						}
						before := g.dump()
						signupBefore, _, windowBefore := g.store.GateCountsForTest()
						replaysBefore := registerKELReplays.Load()

						code, out := g.register(c, c, extra)
						wantCode, wantReason, wantCheck := gateExpect(state, pow, quota, checkOnly)
						if code != wantCode || (wantReason != "" && out["reason"] != wantReason) {
							t.Fatalf("got %d %s, want %d %s", code, out["_raw"], wantCode, wantReason)
						}
						after := g.dump()
						signupAfter, _, windowAfter := g.store.GateCountsForTest()
						if windowAfter != 0 {
							t.Errorf("%d window places still held after the request", windowAfter)
						}
						switch {
						case code != 200:
							if after != before {
								t.Errorf("a refusal (%d %s) wrote:\nbefore %s\nafter  %s", code, out["reason"], before, after)
							}
							if signupAfter != signupBefore || windowAfter != windowBefore {
								t.Errorf("a refusal kept places: signup %d -> %d, window %d -> %d",
									signupBefore, signupAfter, windowBefore, windowAfter)
							}
							// The gate refuses before the KEL is decoded
							// (PAY-A2; M-PAY-22).
							if d := registerKELReplays.Load() - replaysBefore; d != 0 {
								t.Errorf("a refusal at the gate replayed %d KEL(s)", d)
							}
						case checkOnly:
							if out["status"] != wantCheck || len(out) != 2 {
								t.Errorf("check_only answered %s, want {status: %s}", out["_raw"], wantCheck)
							}
							if after != before {
								t.Errorf("check_only wrote:\nbefore %s\nafter  %s", before, after)
							}
							if signupAfter != signupBefore {
								t.Errorf("check_only took a quota place (%d -> %d)", signupBefore, signupAfter)
							}
						default:
							g.checkRegistered(t, state, c.AID(), out, signupBefore, signupAfter)
						}
					})
				}
			}
		}
	}
}

// checkRegistered checks what a registration that passed the gate wrote.
func (g *gateHub) checkRegistered(t *testing.T, state, aid string, out map[string]any, signupBefore, signupAfter int) {
	t.Helper()
	if out["status"] != "registered" {
		t.Fatalf("registration answered %s", out["_raw"])
	}
	var via, trial string
	var pu sql.NullInt64
	if err := g.store.db.QueryRow(`SELECT admitted_via, probation_until, trial FROM agent WHERE aid=?`, aid).
		Scan(&via, &pu, &trial); err != nil {
		t.Fatal(err)
	}
	if bal, _ := g.store.Balance(aid); bal != 0 {
		t.Errorf("registration paid %d credits", bal)
	}
	wantSignup := signupBefore
	switch state {
	case "registered", "listed":
		if via != viaList || pu.Valid || trial != trialNone {
			t.Errorf("%s: admitted_via %s, probation %v, trial %s; want list, none, none", state, via, pu, trial)
		}
		if _, has := out["probation_until"]; has {
			t.Errorf("%s: the answer carries probation: %s", state, out["_raw"])
		}
	case "window_open", "open":
		want := viaWindow
		if state == "open" {
			want = viaOpen
			wantSignup += 2 // the /32 and the /24 of an IPv4 client
		}
		until := g.now.Add(ProbationPeriod).UnixMilli()
		if via != want || !pu.Valid || pu.Int64 != until || trial != trialPending {
			t.Errorf("%s: admitted_via %s, probation %v, trial %s; want %s, %d, pending", state, via, pu, trial, want, until)
		}
		if out["trial"] != trialPending || out["probation_until"] != float64(until) {
			t.Errorf("%s: the answer does not carry the probation: %s", state, out["_raw"])
		}
		if state == "window_open" {
			var used int
			if err := g.store.db.QueryRow(`SELECT used FROM admission_window`).Scan(&used); err != nil || used != 1 {
				t.Errorf("the window's used = %d (%v), want 1", used, err)
			}
		}
	}
	if signupAfter != wantSignup {
		t.Errorf("%s: open-registration places %d -> %d, want %d", state, signupBefore, signupAfter, wantSignup)
	}
}

// What the gate reserved goes back when a later step (5 to 10) refuses
// (PAY-A1 step 11): a bad signature (step 5), a forked key history (step 6),
// a window that filled meanwhile (step 10).
func TestALaterRefusalGivesTheGatesPlaceBack(t *testing.T) {
	for _, mode := range []string{"open", "window_open"} {
		t.Run(mode+"/signature", func(t *testing.T) {
			g := newGateHub(t)
			g.gateState(mode, nil)
			c, _ := identitytest.Hub()
			other, _ := identitytest.Hub()
			before := g.dump()
			code, out := g.register(c, other, g.pow(c.AID(), "good"))
			if code != http.StatusUnauthorized || out["reason"] != "unauthorized" {
				t.Fatalf("a registration signed by another key: %d %s", code, out["_raw"])
			}
			if s, _, w := g.store.GateCountsForTest(); s != 0 || w != 0 {
				t.Errorf("the gate still holds %d quota and %d window places", s, w)
			}
			if g.dump() != before {
				t.Error("the refused registration wrote")
			}
		})
		t.Run(mode+"/fork", func(t *testing.T) {
			g := newGateHub(t)
			g.gateState(mode, nil)
			c, _ := identitytest.Hub()
			if err := identitytest.Rotate(c, kelTime()); err != nil {
				t.Fatal(err)
			}
			// It left this hub once, so its key history is a tombstone; a
			// fork of it comes back.
			snap, _ := c.Export()
			if err := identitytest.Rotate(c, kelTime()); err != nil {
				t.Fatal(err)
			}
			kel, _ := identity.MarshalKEL(c.KEL())
			if _, err := g.store.db.Exec(`INSERT INTO departed_kel(aid, kel, at) VALUES(?,?,'x')`, c.AID(), kel); err != nil {
				t.Fatal(err)
			}
			fork, _ := identity.Restore(snap)
			if err := identitytest.Rotate(fork, kelTime()); err != nil {
				t.Fatal(err)
			}
			code, out := g.register(fork, fork, g.pow(fork.AID(), "good"))
			if code != http.StatusConflict || out["reason"] != "kel_fork" {
				t.Fatalf("a fork of the tombstone: %d %s", code, out["_raw"])
			}
			if s, _, w := g.store.GateCountsForTest(); s != 0 || w != 0 {
				t.Errorf("the gate still holds %d quota and %d window places", s, w)
			}
		})
	}
	t.Run("window_filled_meanwhile", func(t *testing.T) {
		g := newGateHub(t)
		g.gateState("window_open", nil)
		c, _ := identitytest.Hub()
		// The window fills between the gate and the write: the place the
		// gate held was taken from the window's count; the write finds no
		// room and the registration is refused like any other at a full
		// window.
		calls := 0
		g.store.clock = func() time.Time {
			// The first read is the gate's (PAY-A1 step 4), the second the
			// write's (step 10): fill the window in between.
			if calls++; calls == 2 {
				if _, err := g.store.db.Exec(`UPDATE admission_window SET used = max`); err != nil {
					t.Error(err)
				}
			}
			return g.now
		}
		code, out := g.register(c, c, g.pow(c.AID(), "good"))
		g.store.clock = func() time.Time { return g.now }
		if code != http.StatusForbidden || out["reason"] != "admission_required" {
			t.Fatalf("a window that filled meanwhile: %d %s", code, out["_raw"])
		}
		if g.store.KnowsAgent(c.AID()) {
			t.Error("registered past a full window")
		}
		if _, _, w := g.store.GateCountsForTest(); w != 0 {
			t.Errorf("the gate still holds %d window places", w)
		}
	})
}

// A registration the gate let past is refused when, before it writes, the
// AID stopped being what let it past (PAY-A1 steps 4 and 10): a registered
// AID deregistered meanwhile (revoked, swept or gone), or a listed AID whose
// admission was revoked. Either is a newcomer the gate has not admitted, and
// writing its row would undo the revocation.
func TestARegistrationRacingARevocationIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		setup func(g *gateHub, c *identity.Controller)
		// meanwhile runs between the gate and the write, outside the
		// store's mutex (the write holds it), as another process would.
		meanwhile func(g *gateHub, c *identity.Controller) error
	}{
		{"registered_then_revoked",
			func(g *gateHub, c *identity.Controller) {
				if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
					t.Fatal(err)
				}
				if code, out := g.register(c, c, nil); code != http.StatusOK {
					t.Fatalf("register: %d %s", code, out["_raw"])
				}
			},
			func(g *gateHub, c *identity.Controller) error {
				_, err := dereg(g.store, c.AID(), DeregRevoked)
				return err
			}},
		{"listed_then_revoked",
			func(g *gateHub, c *identity.Controller) {
				if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
					t.Fatal(err)
				}
			},
			func(g *gateHub, c *identity.Controller) error {
				_, err := g.store.db.Exec(`DELETE FROM admitted WHERE aid=?`, c.AID())
				return err
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateHub(t)
			c, _ := identitytest.Hub()
			tc.setup(g, c)
			calls := 0
			g.store.clock = func() time.Time {
				// The first read is the gate's (step 4), the second the
				// write's (step 10).
				if calls++; calls == 2 {
					if err := tc.meanwhile(g, c); err != nil {
						t.Error(err)
					}
				}
				return g.now
			}
			code, out := g.register(c, c, nil)
			g.store.clock = func() time.Time { return g.now }
			if calls < 2 {
				t.Fatalf("the registration read the clock %d time(s); the race was not set up", calls)
			}
			if code != http.StatusForbidden || out["reason"] != "admission_required" || out["aid"] != c.AID() {
				t.Fatalf("a registration racing a revocation: %d %s, want 403 admission_required", code, out["_raw"])
			}
			if g.store.KnowsAgent(c.AID()) {
				t.Fatal("the revoked AID is registered again")
			}
			// It is a newcomer now: the gate refuses it.
			if code, out := g.register(c, c, nil); code != http.StatusForbidden || out["reason"] != "admission_required" {
				t.Errorf("registering again after the revocation: %d %s", code, out["_raw"])
			}
		})
	}
}

// The aid of a registration is a complete AID before anything uses it
// (PAY-A1 step 3): otherwise a closed hub logs "to let it in: anet-hub admit
// <aid>" with the sender's text in the line an operator copies into a shell,
// and echoes it in admission_required.
func TestARegistrationsAIDIsCheckedBeforeItIsUsed(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	g := newGateHub(t)
	c, _ := identitytest.Hub()
	kel, _ := identity.MarshalKEL(c.KEL())
	for _, aid := range []string{
		"x; echo admitted",
		c.AID() + "\nhub: forged line",
		strings.ToUpper(c.AID()),
		c.AID()[:58],
	} {
		raw, _ := json.Marshal(map[string]any{"aid": aid, "kel": base64.RawURLEncoding.EncodeToString(kel)})
		replays := registerKELReplays.Load()
		code, out := g.post(aid, c, raw)
		if code != http.StatusBadRequest || out["reason"] != "bad_request" {
			t.Errorf("aid %q: %d %s, want 400 bad_request", aid, code, out["_raw"])
		}
		if registerKELReplays.Load() != replays {
			t.Errorf("aid %q: the key history was replayed", aid)
		}
	}
	if strings.Contains(logged.String(), "echo admitted") || strings.Contains(logged.String(), "forged line") {
		t.Errorf("the sender's text reached the log: %q", logged.String())
	}
}

// The quota is per network and per UTC day: another /24 is not counted
// against this one, an IPv4-mapped IPv6 address counts as its IPv4 address,
// and a new day starts again (PAY-A3).
func TestTheQuotaIsPerNetworkAndDay(t *testing.T) {
	g := newGateHub(t)
	gate := g.store.gate()
	ip := net.ParseIP("198.51.100.20")
	for i := 0; i < 20; i++ {
		if _, ok := gate.reserveSignup(ip, g.now); !ok {
			t.Fatalf("place %d of the /32 refused", i+1)
		}
	}
	if _, ok := gate.reserveSignup(net.ParseIP("::ffff:198.51.100.20"), g.now); ok {
		t.Error("the IPv4-mapped form of a full /32 got a place")
	}
	if _, ok := gate.reserveSignup(net.ParseIP("198.51.100.21"), g.now); !ok {
		t.Error("another /32 of the same /24 was refused below the /24's 200")
	}
	// 21 places so far; 179 more /32s fill the /24 to its 200.
	for i := 0; i < 179; i++ {
		if _, ok := gate.reserveSignup(net.IPv4(198, 51, 100, byte(30+i)), g.now); !ok {
			t.Fatalf("place %d of the /24 refused", 22+i)
		}
	}
	if _, ok := gate.reserveSignup(net.ParseIP("198.51.100.250"), g.now); ok {
		t.Error("the /24 gave more than 200 places")
	}
	if _, ok := gate.reserveSignup(net.ParseIP("203.0.113.1"), g.now); !ok {
		t.Error("another /24 was refused")
	}
	// IPv6: /64 20, /48 200, /32 1000.
	for i := 0; i < 20; i++ {
		if _, ok := gate.reserveSignup(net.ParseIP(fmt.Sprintf("2001:db8:1:2::%x", i+1)), g.now); !ok {
			t.Fatalf("place %d of the /64 refused", i+1)
		}
	}
	if _, ok := gate.reserveSignup(net.ParseIP("2001:db8:1:2:ffff::1"), g.now); ok {
		t.Error("the /64 gave more than 20 places")
	}
	if _, ok := gate.reserveSignup(net.ParseIP("2001:db8:1:3::1"), g.now); !ok {
		t.Error("another /64 of the same /48 was refused")
	}
	// Tomorrow every count starts again, under a new key.
	key := append([]byte(nil), gate.dayKey...)
	tomorrow := time.UnixMilli((g.now.UnixMilli()/86_400_000 + 1) * 86_400_000)
	if _, ok := gate.reserveSignup(ip, tomorrow); !ok {
		t.Error("a full /32 was still full the next UTC day")
	}
	if bytes.Equal(key, gate.dayKey) {
		t.Error("the day key did not change with the day")
	}
	// registration_quota says to come back at the next UTC midnight.
	if d := untilTomorrow(g.now); d <= 0 || d > 24*time.Hour {
		t.Errorf("untilTomorrow = %v", d)
	}
}

// Every hub asks the same 22 bits, and the challenge says so (core L23,
// HPP §0.4); the gate tests lower it only for speed.
func TestThePowIsTheConstant(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.gate().bits != regpow.Bits || regpow.Bits != 22 {
		t.Fatalf("a new hub asks %d bits, want 22", store.gate().bits)
	}
	now := time.Now()
	ch := store.gate().challenge(now)
	if ch["bits"] != 22 {
		t.Errorf("the challenge says %v bits", ch["bits"])
	}
	h := regpow.Hour(uint64(now.UnixMilli()))
	if ch["not_after"] != regpow.NotAfter(h) {
		t.Errorf("not_after %v, want the end of the next hour %d", ch["not_after"], regpow.NotAfter(h))
	}
	seed, err := base64.RawURLEncoding.DecodeString(ch["seed"].(string))
	cur := store.gate().powSeed(h)
	if err != nil || !bytes.Equal(seed, cur[:]) {
		t.Errorf("the challenge's seed is not this hour's")
	}
	// The previous hour's seed is still taken, the one before it not.
	aid := "bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
	store.gate().bits = 4
	for back, want := range map[uint64]bool{0: true, 1: true, 2: false} {
		s := store.gate().powSeed(h - back)
		n, err := regpow.Solve(context.Background(), "hub", aid, s, 4)
		if err != nil {
			t.Fatal(err)
		}
		if got := store.gate().checkPow("hub", aid, s[:], n, now); got != want {
			t.Errorf("the seed of %d hour(s) ago: accepted %v, want %v", back, got, want)
		}
	}
}
