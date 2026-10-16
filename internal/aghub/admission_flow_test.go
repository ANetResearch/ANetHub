package aghub

// The admission list, the sign-up window, probation, the trial credit, the
// inactive sweep and revocation (hub-payment-privacy PAY-A3 to PAY-A7).

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// signedGet sends a signed GET as c to path (the action names the route).
func (g *gateHub) signedGet(c *identity.Controller, action, path, ip string) (int, map[string]any) {
	g.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://hub.test"+path, nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set(wireVersionHeader, strconv.Itoa(wireVersion))
	gateSigned++
	ts := uint64(time.Now().UnixMilli()) + uint64(gateSigned%1000)
	sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), g.hubAID, ts, req.Method, req.URL.RequestURI(), nil))
	req.Header.Set(relayauth.HeaderAID, c.AID())
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

// balance is GET /agents/{aid}/balance as c from ip: a signed request, so
// also the moment a pending trial credit is paid.
func (g *gateHub) balance(c *identity.Controller, ip string) map[string]any {
	g.t.Helper()
	code, out := g.signedGet(c, relayauth.ActionBalance, "/agents/"+c.AID()+"/balance", ip)
	if code != http.StatusOK {
		g.t.Fatalf("balance: %d %s", code, out["_raw"])
	}
	return out
}

// registerOpen registers a new identity through open registration.
func (g *gateHub) registerOpen() *identity.Controller {
	g.t.Helper()
	if err := g.store.SetAdmissionMode(AdmissionOpen); err != nil {
		g.t.Fatal(err)
	}
	c, _ := NewAgentForTest()
	if code, out := g.register(c, c, g.pow(c.AID(), "good")); code != http.StatusOK {
		g.t.Fatalf("open registration: %d %s", code, out["_raw"])
	}
	return c
}

// An admission grant is paid when the AID first registers, once: not again
// when it registers again, not again when it is admitted again.
func TestTheListGrantIsPaidOnceAtFirstRegistration(t *testing.T) {
	g := newGateHub(t)
	c, _ := NewAgentForTest()
	res, err := g.store.Admit(c.AID(), 30, "bench", true)
	if err != nil || res.Registered || res.Paid != 0 || res.Grant != 30 {
		t.Fatalf("admit with a grant before registering: %+v %v", res, err)
	}
	if bal, _ := g.store.Balance(c.AID()); bal != 0 {
		t.Fatalf("the grant was paid before the AID registered: %d", bal)
	}
	for i := 0; i < 2; i++ {
		if code, out := g.register(c, c, nil); code != http.StatusOK {
			t.Fatalf("register %d: %d %s", i, code, out["_raw"])
		}
		if bal, _ := g.store.Balance(c.AID()); bal != 30 {
			t.Fatalf("after registration %d the balance is %d, want 30", i, bal)
		}
	}
	var reason string
	if err := g.store.db.QueryRow(`SELECT reason FROM credit_entry WHERE aid=? AND delta=30`, c.AID()).Scan(&reason); err != nil || reason != reasonAdmissionGrant {
		t.Errorf("the grant's ledger reason is %q (%v), want %q", reason, err, reasonAdmissionGrant)
	}
	res, err = g.store.Admit(c.AID(), 30, "", false)
	if err != nil || !res.AlreadyGranted || !res.Registered || res.Paid != 0 {
		t.Fatalf("admitting again with a grant: %+v %v", res, err)
	}
	if bal, _ := g.store.Balance(c.AID()); bal != 30 {
		t.Fatalf("the grant was paid twice: %d", bal)
	}
	// The label of a second admission replaces the first; no label keeps it.
	if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	a, _ := g.store.ListAdmissions()
	if len(a.Admitted) != 1 || a.Admitted[0].Label != "bench" || !a.Admitted[0].Granted {
		t.Errorf("the list after re-admitting: %+v", a.Admitted)
	}
}

// Admitting an account already registered through a window or open
// registration ends its probation now and cancels a trial credit not yet
// paid; a grant is paid at once (PAY-A7).
func TestAdmittingARegisteredAccountEndsItsProbation(t *testing.T) {
	g := newGateHub(t)
	c := g.registerOpen()
	if until, on := g.store.ProbationUntil(c.AID()); !on || !until.Equal(time.UnixMilli(g.now.Add(ProbationPeriod).UnixMilli())) {
		t.Fatalf("after open registration: on probation %v until %v", on, until)
	}
	res, err := g.store.Admit(c.AID(), 7, "", false)
	if err != nil || !res.Registered || res.Paid != 7 {
		t.Fatalf("admit a registered account with a grant: %+v %v", res, err)
	}
	if _, on := g.store.ProbationUntil(c.AID()); on {
		t.Error("still on probation after being admitted")
	}
	out := g.balance(c, "198.51.100.1")
	if out["credits"] != float64(7) {
		t.Errorf("balance after admission: %s", out["_raw"])
	}
	if _, has := out["trial"]; has {
		t.Errorf("an admitted account still shows a trial credit: %s", out["_raw"])
	}
	// Its probation is over, but no trial credit comes: it was cancelled.
	g.now = g.now.Add(ProbationPeriod + time.Hour)
	if out := g.balance(c, "198.51.100.1"); out["credits"] != float64(7) {
		t.Errorf("an admitted account was paid a trial credit: %s", out["_raw"])
	}
}

// The trial credit: pending through probation, paid by the first signed
// request after it, once; /balance and /register say where it stands
// (PAY-A5, §2.2).
func TestTheTrialCreditAfterProbation(t *testing.T) {
	g := newGateHub(t)
	c := g.registerOpen()
	until := g.now.Add(ProbationPeriod).UnixMilli()

	out := g.balance(c, "198.51.100.1")
	if out["credits"] != float64(0) || out["trial"] != trialPending || out["probation_until"] != float64(until) {
		t.Fatalf("during probation: %s", out["_raw"])
	}
	g.now = g.now.Add(ProbationPeriod - time.Second)
	if out := g.balance(c, "198.51.100.1"); out["credits"] != float64(0) {
		t.Fatalf("paid a second before probation ended: %s", out["_raw"])
	}
	g.now = g.now.Add(time.Second)
	out = g.balance(c, "198.51.100.1")
	if out["credits"] != float64(TrialCredits) || out["trial"] != trialGranted {
		t.Fatalf("the first request after probation: %s", out["_raw"])
	}
	if out := g.balance(c, "198.51.100.1"); out["credits"] != float64(TrialCredits) {
		t.Fatalf("paid twice: %s", out["_raw"])
	}
	var reason string
	if err := g.store.db.QueryRow(`SELECT reason FROM credit_entry WHERE aid=? AND delta=?`, c.AID(), TrialCredits).Scan(&reason); err != nil || reason != reasonTrialCredit {
		t.Errorf("the trial credit's ledger reason is %q (%v)", reason, err)
	}
	// /register reports it too.
	code, reg := g.register(c, c, nil)
	if code != http.StatusOK || reg["trial"] != trialGranted || reg["probation_until"] != float64(until) {
		t.Errorf("re-registration after the trial credit: %d %s", code, reg["_raw"])
	}
	// An account the operator admitted shows neither field. Its key
	// history is made on the hub's clock, which has moved past the
	// probation: a new key event is taken within 5 minutes of it (KEL R-10).
	d, _ := NewAgentWitnessedBy(identitytest.Witness, g.now)
	if _, err := g.store.Admit(d.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	code, reg = g.register(d, d, nil)
	if _, has := reg["trial"]; code != http.StatusOK || has || strings.Contains(reg["_raw"].(string), "probation_until") {
		t.Errorf("a listed account's registration: %d %s", code, reg["_raw"])
	}
	if out := g.balance(d, "198.51.100.1"); out["trial"] != nil || out["probation_until"] != nil {
		t.Errorf("a listed account's balance: %s", out["_raw"])
	}
}

// pendingTrial writes an account whose probation ended and whose trial
// credit is pending, as the gate would have.
func (g *gateHub) pendingTrial() *identity.Controller {
	g.t.Helper()
	c, _ := NewAgentForTest()
	kel, _ := identity.MarshalKEL(c.KEL())
	if err := g.store.PutAgent(c.AID(), "t", nil, kel); err != nil {
		g.t.Fatal(err)
	}
	if _, err := g.store.db.Exec(`UPDATE agent SET admitted_via=?, probation_until=?, trial=? WHERE aid=?`,
		viaOpen, g.now.Add(-time.Minute).UnixMilli(), trialPending, c.AID()); err != nil {
		g.t.Fatal(err)
	}
	return c
}

// granted reports whether c's trial credit has been paid.
func (g *gateHub) granted(c *identity.Controller) bool {
	g.t.Helper()
	var trial string
	if err := g.store.db.QueryRow(`SELECT trial FROM agent WHERE aid=?`, c.AID()).Scan(&trial); err != nil {
		g.t.Fatal(err)
	}
	return trial == trialGranted
}

// The trial credits of a day are capped per network and for the hub
// (PAY-A5, §0.4): 3 per IPv4 /24 or IPv6 /48, 10 per IPv6 /32, 100 for the
// hub. Past a cap the credit stays pending and is paid on a later day.
// (trial_budget; M-PAY-26)
func TestTheTrialBudget(t *testing.T) {
	t.Run("ipv4_24", func(t *testing.T) {
		g := newGateHub(t)
		var cs []*identity.Controller
		for i := 0; i < 4; i++ {
			c := g.pendingTrial()
			cs = append(cs, c)
			g.balance(c, "198.51.100."+strconv.Itoa(10+i))
		}
		for i, c := range cs {
			if want := i < 3; g.granted(c) != want {
				t.Errorf("account %d of one /24: granted %v, want %v", i, !want, want)
			}
		}
		// Another network still has its budget.
		other := g.pendingTrial()
		g.balance(other, "203.0.113.10")
		if !g.granted(other) {
			t.Error("an account of another /24 was not paid")
		}
		// The next UTC day the pending one is paid.
		g.now = time.UnixMilli((g.now.UnixMilli()/86_400_000 + 1) * 86_400_000)
		g.balance(cs[3], "198.51.100.13")
		if !g.granted(cs[3]) {
			t.Error("the pending trial credit was not paid the next day")
		}
	})
	t.Run("ipv6", func(t *testing.T) {
		g := newGateHub(t)
		paid := 0
		// 12 accounts in 4 /48s of one /32: 3 per /48 would be 12, the
		// /32 stops it at 10.
		for i := 0; i < 16; i++ {
			c := g.pendingTrial()
			g.balance(c, net.ParseIP("2001:db8:"+strconv.Itoa(i/4)+"::1").String())
			if g.granted(c) {
				paid++
			}
		}
		if paid != 10 {
			t.Errorf("one IPv6 /32 was paid %d trial credits, want 10", paid)
		}
	})
	t.Run("hub", func(t *testing.T) {
		g := newGateHub(t)
		paid := 0
		for i := 0; i < trialBudgetHub+5; i++ {
			c := g.pendingTrial()
			g.balance(c, net.IPv4(198, 18+byte(i/250), byte(i%250), 1).String())
			if g.granted(c) {
				paid++
			}
		}
		if paid != trialBudgetHub {
			t.Errorf("the hub paid %d trial credits in a day, want %d", paid, trialBudgetHub)
		}
	})
}

// An account that never collected its mail in 7 days, holds nothing and was
// never reviewed is deregistered by the hourly sweep; its admission stays;
// its key history is its tombstone, so a truncated one cannot take the AID
// back (PAY-A6; M-PAY-25).
func TestTheInactiveSweep(t *testing.T) {
	g := newGateHub(t)
	c, _ := NewAgentForTest()
	for i := 0; i < 2; i++ {
		if err := identitytest.Rotate(c, kelTime()); err != nil {
			t.Fatal(err)
		}
	}
	snap, _ := c.Export()
	if err := identitytest.Rotate(c, kelTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if code, out := g.register(c, c, nil); code != http.StatusOK {
		t.Fatalf("register: %d %s", code, out["_raw"])
	}
	// Four that are kept: one that polled, one with credit, one reviewed
	// here and one reviewed on a peer hub.
	keep := map[string]func(aid string){
		"polled": func(aid string) { g.store.SeenPolling(aid) },
		"funded": func(aid string) { _ = g.store.Credit(aid, 1, "test") },
		"reviewed": func(aid string) {
			if _, err := g.store.db.Exec(`INSERT INTO review(ix_commit, subject_aid, tag, tag_key_id, rating, receipt_cid, completed_day, created_day, stored_day)
			    VALUES(?,?,?,?,?,?,?,?,?)`, []byte("ix-"+aid), aid, []byte("tag"), 1, 5, "cid", 0, 0, 0); err != nil {
				t.Fatal(err)
			}
		},
		"reviewed_on_a_peer": func(aid string) {
			if _, err := g.store.db.Exec(`INSERT INTO fed_review(ix_commit, subject_aid, tag, tag_key_id, peer_aid, rating, receipt_cid, created_day, stored_day)
			    VALUES(?,?,?,?,?,?,?,?,?)`, []byte("fix-"+aid), aid, []byte("tag"), 1, "peer", 5, "cid", 0, 0); err != nil {
				t.Fatal(err)
			}
		},
	}
	kept := map[string]*identity.Controller{}
	for name, f := range keep {
		k, _ := NewAgentForTest()
		kel, _ := identity.MarshalKEL(k.KEL())
		if err := g.store.PutAgent(k.AID(), name, nil, kel); err != nil {
			t.Fatal(err)
		}
		f(k.AID())
		kept[name] = k
	}
	if n, err := g.store.SweepInactive(); err != nil || n != 0 {
		t.Fatalf("a sweep before 7 days deregistered %d (%v)", n, err)
	}
	g.now = g.now.Add(InactiveAfter + time.Minute)
	if n, err := g.store.SweepInactive(); err != nil || n != 1 {
		t.Fatalf("the sweep after 7 days deregistered %d (%v), want 1", n, err)
	}
	if g.store.KnowsAgent(c.AID()) {
		t.Fatal("the inactive account is still registered")
	}
	for name, k := range kept {
		if !g.store.KnowsAgent(k.AID()) {
			t.Errorf("the %s account was swept", name)
		}
	}
	if ok, _ := g.store.isAdmitted(c.AID()); !ok {
		t.Error("the sweep revoked the admission")
	}
	// A truncated key history cannot take the AID back; its own can.
	old, _ := identity.Restore(snap)
	if code, out := g.register(old, old, nil); code != http.StatusConflict || out["reason"] != "kel_rollback" {
		t.Fatalf("a truncated key history after the sweep: %d %s, want 409 kel_rollback", code, out["_raw"])
	}
	if code, out := g.register(c, c, nil); code != http.StatusOK {
		t.Fatalf("its own key history after the sweep: %d %s", code, out["_raw"])
	}
}

// Revoking: an AID only on the list leaves the list; a registered one is
// deregistered as well (its balance stays, its key history becomes its
// tombstone, dereg_event tells the hub process); one in neither is
// ErrNotListed (PAY-A7).
func TestRevokingAnAdmission(t *testing.T) {
	g := newGateHub(t)
	listed, _ := NewAgentForTest()
	if _, err := g.store.Admit(listed.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	res, err := g.store.RevokeAdmission(listed.AID())
	if err != nil || res.Registered {
		t.Fatalf("revoking a listed AID: %+v %v", res, err)
	}
	if ok, _ := g.store.isAdmitted(listed.AID()); ok {
		t.Error("the AID is still listed")
	}
	if _, err := g.store.RevokeAdmission(listed.AID()); !errors.Is(err, ErrNotListed) {
		t.Errorf("revoking it again: %v, want ErrNotListed", err)
	}
	if _, err := g.store.RevokeAdmission("bafyrei-not-an-aid"); !errors.Is(err, ErrBadAID) {
		t.Errorf("revoking a malformed AID: %v, want ErrBadAID", err)
	}

	// An account that came in through open registration is deregistered
	// though it is not on the list.
	c := g.registerOpen()
	if err := g.store.Credit(c.AID(), 12, "test"); err != nil {
		t.Fatal(err)
	}
	res, err = g.store.RevokeAdmission(c.AID())
	if err != nil || !res.Registered || res.Balance != 12 {
		t.Fatalf("revoking a registered AID: %+v %v", res, err)
	}
	if g.store.KnowsAgent(c.AID()) {
		t.Error("still registered after the revocation")
	}
	if bal, _ := g.store.Balance(c.AID()); bal != 12 {
		t.Errorf("the balance moved: %d", bal)
	}
	var n int
	if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM dereg_event WHERE aid=?`, c.AID()).Scan(&n); err != nil || n != 1 {
		t.Errorf("no dereg_event for a deregistration outside the hub process (%d, %v)", n, err)
	}
	// It comes back only by being admitted (the hub is open, so with a
	// proof of work).
	if err := g.store.SetAdmissionMode(AdmissionClosed); err != nil {
		t.Fatal(err)
	}
	if code, out := g.register(c, c, nil); code != http.StatusForbidden || out["reason"] != "admission_required" {
		t.Errorf("a revoked AID at a closed hub: %d %s", code, out["_raw"])
	}
}

// admit --file imports the whole file or nothing (PAY-A7).
func TestAdmitFileIsAllOrNothing(t *testing.T) {
	g := newGateHub(t)
	var aids []string
	for i := 0; i < 3; i++ {
		c, _ := NewAgentForTest()
		aids = append(aids, c.AID())
	}
	reg, _ := NewAgentForTest()
	regKEL, _ := identity.MarshalKEL(reg.KEL())
	if err := g.store.PutAgent(reg.AID(), "r", nil, regKEL); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	body := "# the bench boards\n" + aids[0] + "\n\n  " + aids[1] + "  \n" + reg.AID() + "\n" + aids[0] + "\n"
	if err := os.WriteFile(good, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte(aids[2]+"\nnot-an-aid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := g.store.AdmitFile(bad, 0, "", false)
	var bl *BadLineError
	if !errors.As(err, &bl) || bl.Line != 2 {
		t.Fatalf("a file with a bad line 2: %v", err)
	}
	if ok, _ := g.store.isAdmitted(aids[2]); ok {
		t.Fatal("a file with a bad line was partly imported")
	}
	n, m, err := g.store.AdmitFile(good, 0, "", false)
	if err != nil || n != 3 || m != 1 {
		t.Fatalf("a good file: %d admitted, %d registered, %v; want 3, 1", n, m, err)
	}
	for _, aid := range []string{aids[0], aids[1], reg.AID()} {
		if ok, _ := g.store.isAdmitted(aid); !ok {
			t.Errorf("%s from the file is not listed", aid)
		}
	}
}

// A window lasts at most 7 days and takes at most 10000; one at a time;
// closing it reports how many came in through it (PAY-A7).
func TestTheSignUpWindow(t *testing.T) {
	g := newGateHub(t)
	for _, c := range []struct {
		d   time.Duration
		max int
	}{{0, 5}, {MaxWindowLength + time.Second, 5}, {time.Hour, 0}, {time.Hour, MaxWindowSize + 1}} {
		if _, err := g.store.OpenWindow(c.d, c.max, ""); !errors.Is(err, ErrWindowTooBig) {
			t.Errorf("a window of %v and %d: %v, want ErrWindowTooBig", c.d, c.max, err)
		}
	}
	w, err := g.store.OpenWindow(MaxWindowLength, MaxWindowSize, "campus")
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.store.OpenWindow(time.Hour, 1, "")
	var open *ErrWindowOpen
	if !errors.As(err, &open) || open.Window.ID != w.ID || !errors.Is(err, ErrWindowExists) {
		t.Fatalf("a second window: %v", err)
	}
	c, _ := NewAgentForTest()
	if code, out := g.register(c, c, g.pow(c.AID(), "good")); code != http.StatusOK || out["trial"] != trialPending {
		t.Fatalf("registration through the window: %d %s", code, out["_raw"])
	}
	closed, ok, err := g.store.CloseWindow()
	if err != nil || !ok || closed.Used != 1 {
		t.Fatalf("closing: %+v %v %v", closed, ok, err)
	}
	if _, ok, _ := g.store.CloseWindow(); ok {
		t.Error("a second close found a window open")
	}
	d, _ := NewAgentForTest()
	if code, out := g.register(d, d, g.pow(d.AID(), "good")); code != http.StatusForbidden || out["reason"] != "admission_required" {
		t.Errorf("after the window closed: %d %s", code, out["_raw"])
	}
	// A window that ran out is closed by the clock; a closed window's row
	// goes after 30 days.
	if _, err := g.store.OpenWindow(time.Hour, 3, ""); err != nil {
		t.Fatal(err)
	}
	g.now = g.now.Add(2 * time.Hour)
	if code, out := g.register(d, d, g.pow(d.AID(), "good")); code != http.StatusForbidden {
		t.Errorf("after the window's end: %d %s", code, out["_raw"])
	}
	g.now = g.now.Add(31 * 24 * time.Hour)
	if _, err := g.store.SweepInactive(); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM admission_window`).Scan(&rows); err != nil || rows != 0 {
		t.Errorf("%d window rows kept past 30 days", rows)
	}
}

// ValidAID takes complete AIDs only.
func TestValidAID(t *testing.T) {
	c, _ := NewAgentForTest()
	if !ValidAID(c.AID()) {
		t.Fatalf("%s is not valid", c.AID())
	}
	for _, s := range []string{"", c.AID()[:58], c.AID() + "a", strings.ToUpper(c.AID()), "did:anet:" + c.AID(),
		"b" + strings.Repeat("a", 58), c.AID()[:20] + "1" + c.AID()[21:]} {
		if ValidAID(s) {
			t.Errorf("%q is valid", s)
		}
	}
}
