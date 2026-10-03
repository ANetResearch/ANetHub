package aghub

// The one deregistration function (hub-payment-privacy PAY-O1, PAY-O2; core
// CORE-K27): nothing else deletes an agent row, the tombstone only grows,
// and a deregistration committed by another process reaches the hub
// process within two seconds.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

// deleteAgentRe matches SQL that deletes rows of the agent table (and not
// of agent_cap or another agent_… table).
var deleteAgentRe = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+"?agent"?(\s|;|$)`)

// writeTombstoneRe matches SQL that writes departed_kel.
var writeTombstoneRe = regexp.MustCompile(`(?i)\b(INSERT\s+(OR\s+\w+\s+)?INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+"?departed_kel"?\b`)

// writeAdmittedRe matches SQL that writes the admission list.
var writeAdmittedRe = regexp.MustCompile(`(?i)\b(INSERT\s+(OR\s+\w+\s+)?INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+"?admitted"?\b`)

// sqlLiterals is every string literal of the non-test Go files of dir, by
// file.
func sqlLiterals(t *testing.T, dir string) map[string][]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, err := strconv.Unquote(bl.Value); err == nil {
					out[filepath.Base(f)] = append(out[filepath.Base(f)], s)
				}
			}
			return true
		})
	}
	return out
}

// TestSingleDeregisterPath (PAY-O1; this package's half — PAY-16 extends
// it to internal/admin and cmd/anet-hub-admin): in internal/aghub only
// deregister.go deletes agent rows and writes tombstones, and only
// admission.go and deregister.go write the admission list.
func TestSingleDeregisterPath(t *testing.T) {
	lits := sqlLiterals(t, ".")
	if len(lits) == 0 {
		t.Fatal("no Go files scanned")
	}
	found := map[string]int{}
	for file, ss := range lits {
		for _, s := range ss {
			if deleteAgentRe.MatchString(s) {
				found["agent"]++
				if file != "deregister.go" {
					t.Errorf("%s deletes agent rows outside DeregisterTx: %q", file, s)
				}
			}
			if writeTombstoneRe.MatchString(s) {
				found["departed_kel"]++
				if file != "deregister.go" {
					t.Errorf("%s writes departed_kel outside DeregisterTx: %q", file, s)
				}
			}
			if writeAdmittedRe.MatchString(s) {
				found["admitted"]++
				if file != "deregister.go" && file != "admission.go" {
					t.Errorf("%s writes the admission list: %q", file, s)
				}
			}
		}
	}
	// The scan sees the deletions it allows, or it would pass by seeing
	// nothing.
	if found["agent"] != 1 || found["departed_kel"] == 0 || found["admitted"] == 0 {
		t.Errorf("the scan found %v; deregister.go deletes the agent row exactly once", found)
	}
}

// kelOf is c's key history, encoded.
func kelOf(t *testing.T, c *identity.Controller) []byte {
	t.Helper()
	b, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rotated is c rotated n more times.
func rotated(t *testing.T, c *identity.Controller, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.Rotate(kelTime()); err != nil {
			t.Fatal(err)
		}
	}
}

// lastKELTime is the last timestamp kelTime handed out.
var lastKELTime atomic.Uint64

// kelTime is a timestamp for a key event made now: after the inception just
// made and after every event an earlier call stamped, since each event of a
// key history must be later than the one before it (KEL v2).
func kelTime() uint64 {
	for {
		last := lastKELTime.Load()
		ts := uint64(time.Now().UnixMilli()) + 1
		if ts <= last {
			ts = last + 1
		}
		if lastKELTime.CompareAndSwap(last, ts) {
			return ts
		}
	}
}

// dereg runs DeregisterTx in its own transaction, committing on success.
func dereg(s *Store, aid, why string) (DeregResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return DeregResult{}, err
	}
	defer tx.Rollback()
	res, err := DeregisterTx(tx, aid, why)
	if err != nil {
		return res, err
	}
	return res, tx.Commit()
}

// The tombstone is always the longest key history this hub accepted for the
// AID: a registered one that is shorter than it, or forks from it, is not
// written over it; the deregistration fails and changes nothing
// (PAY-O1 step 2; M-PAY-44).
func TestDeregTombstoneNeverShrinks(t *testing.T) {
	g := newGateHub(t)
	c, _ := identity.Incept()
	rotated(t, c, 1)
	mid, _ := c.Export()
	rotated(t, c, 1)
	long := kelOf(t, c) // icp, rot, rot
	if _, err := g.store.db.Exec(`INSERT INTO departed_kel(aid, kel, at) VALUES(?,?,'then')`, c.AID(), long); err != nil {
		t.Fatal(err)
	}
	short, _ := identity.Restore(mid) // icp, rot
	fork, _ := identity.Restore(mid)
	if err := fork.Rotate(kelTime()); err != nil {
		t.Fatal(err)
	}
	for name, kel := range map[string][]byte{"shorter": kelOf(t, short), "forked": kelOf(t, fork)} {
		if err := g.store.PutAgent(c.AID(), name, nil, kel); err != nil {
			t.Fatal(err)
		}
		before := g.dump()
		if _, err := dereg(g.store, c.AID(), DeregRevoked); !errors.Is(err, ErrTombstoneShrinks) {
			t.Fatalf("%s: deregistering over a longer tombstone: %v, want ErrTombstoneShrinks", name, err)
		}
		if g.dump() != before {
			t.Errorf("%s: the refused deregistration changed the database", name)
		}
		var held []byte
		if err := g.store.db.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, c.AID()).Scan(&held); err != nil || string(held) != string(long) {
			t.Errorf("%s: the tombstone changed", name)
		}
	}
	// A key history that extends the tombstone replaces it.
	rotated(t, c, 1)
	longer := kelOf(t, c)
	if err := g.store.PutAgent(c.AID(), "longer", nil, longer); err != nil {
		t.Fatal(err)
	}
	if _, err := dereg(g.store, c.AID(), DeregSelf); err != nil {
		t.Fatalf("deregistering with a longer key history: %v", err)
	}
	var held []byte
	if err := g.store.db.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, c.AID()).Scan(&held); err != nil || string(held) != string(longer) {
		t.Error("the tombstone is not the longest key history")
	}
}

// An AID with no agent row: ErrNotRegistered, nothing written; an unknown
// reason is refused.
func TestDeregisterTxOfAnUnknownAID(t *testing.T) {
	g := newGateHub(t)
	c, _ := identity.Incept()
	before := g.dump()
	if _, err := dereg(g.store, c.AID(), DeregOperator); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("deregistering an unknown AID: %v", err)
	}
	if g.dump() != before {
		t.Error("deregistering an unknown AID wrote")
	}
	if err := g.store.PutAgent(c.AID(), "n", nil, kelOf(t, c)); err != nil {
		t.Fatal(err)
	}
	if _, err := dereg(g.store, c.AID(), "because"); err == nil {
		t.Error("an unknown reason was accepted")
	}
}

// Which reasons take the admission with them: revoked and operator do,
// the agent leaving, a deactivation and the inactive sweep do not.
func TestDeregisterTxKeepsTheAdmissionUnlessRevoked(t *testing.T) {
	for _, why := range []string{DeregSelf, DeregDip, DeregRevoked, DeregInactive, DeregOperator} {
		g := newGateHub(t)
		c, _ := identity.Incept()
		if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
			t.Fatal(err)
		}
		if err := g.store.PutAgent(c.AID(), "n", nil, kelOf(t, c)); err != nil {
			t.Fatal(err)
		}
		if _, err := dereg(g.store, c.AID(), why); err != nil {
			t.Fatalf("%s: %v", why, err)
		}
		listed, _ := g.store.isAdmitted(c.AID())
		if want := why != DeregRevoked && why != DeregOperator; listed != want {
			t.Errorf("%s: still admitted %v, want %v", why, listed, want)
		}
		var n int
		if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM dereg_event WHERE aid=?`, c.AID()).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: dereg_event rows %d (%v), want 1", why, n, err)
		}
	}
}

// In the hub process a deregistration runs the callbacks at once and clears
// its dereg_event row; the hub process starts with an empty dereg_event.
func TestInProcessDeregRunsTheCallbacks(t *testing.T) {
	g := newGateHub(t)
	stale, _ := identity.Incept()
	if _, err := g.store.db.Exec(`INSERT INTO dereg_event(aid, at) VALUES(?, 1)`, stale.AID()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	g.store.OnDeregistered(func(aid string) { mu.Lock(); got = append(got, aid); mu.Unlock() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM dereg_event`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("dereg_event after the hub process started: %d rows (%v)", n, err)
	}
	c, _ := identity.Incept()
	if err := g.store.PutAgent(c.AID(), "n", nil, kelOf(t, c)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.store.Deregister(c.AID(), DeregSelf); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(got) == 0 || got[0] != c.AID() {
		t.Errorf("the callbacks after an in-process deregistration: %v", got)
	}
	mu.Unlock()
	if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM dereg_event`).Scan(&n); err != nil || n != 0 {
		t.Errorf("dereg_event after an in-process deregistration: %d rows", n)
	}
}

// deregHelperEnv names the database the helper process revokes in, and the
// AID: with it set, this test binary is "anet-hub admissions revoke" in
// another process (TestMain).
const deregHelperEnv = "ANETHUB_DEREG_HELPER"

// TestMain runs the helper process when asked to, and the tests otherwise.
func TestMain(m *testing.M) {
	if v := os.Getenv(deregHelperEnv); v != "" {
		dir, aid, _ := strings.Cut(v, "|")
		s, err := Open(dir)
		if err == nil {
			_, err = s.RevokeAdmission(aid)
			s.Close()
		}
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestOutOfProcessDeregDropsSessions (PAY-O2; M-PAY-46): a deregistration
// committed by another process reaches the hub process's callbacks within
// two seconds. Until sealed-sender's sessions register their callback, a
// test callback stands for "drop this AID's sessions".
func TestOutOfProcessDeregDropsSessions(t *testing.T) {
	g := newGateHub(t)
	c, _ := identity.Incept()
	if _, err := g.store.Admit(c.AID(), 0, "", false); err != nil {
		t.Fatal(err)
	}
	if code, out := g.register(c, c, nil); code != 200 {
		t.Fatalf("register: %d %s", code, out["_raw"])
	}
	// The session table this stands for: a session of c's is live.
	var mu sync.Mutex
	sessions := map[string]bool{c.AID(): true}
	dropped := make(chan string, 4)
	g.store.OnDeregistered(func(aid string) {
		mu.Lock()
		delete(sessions, aid)
		mu.Unlock()
		dropped <- aid
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.store.StartDeregWatcher(ctx); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), deregHelperEnv+"="+g.dir+"|"+c.AID())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the other process: %v\n%s", err, out)
	}
	committed := time.Now()
	if g.store.KnowsAgent(c.AID()) {
		t.Fatal("the other process did not deregister")
	}
	select {
	case aid := <-dropped:
		if aid != c.AID() {
			t.Fatalf("the callback ran for %s", aid)
		}
		if d := time.Since(committed); d > 2*time.Second {
			t.Errorf("the hub process learned of it after %v, over 2 s", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the hub process did not learn of the deregistration within 2 s")
	}
	mu.Lock()
	live := sessions[c.AID()]
	mu.Unlock()
	if live {
		t.Error("the deregistered AID's session is still live")
	}
	// The watcher deletes the row right after the callbacks return, so it
	// may still be there the moment the callback is seen.
	var n int
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if err := g.store.db.QueryRow(`SELECT COUNT(*) FROM dereg_event`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 || time.Now().After(deadline) {
			break
		}
	}
	if n != 0 {
		t.Errorf("dereg_event after the hub process handled it: %d rows", n)
	}
	// Its signed requests are refused from now on.
	if code, out := g.signedGet(c, "balance", "/agents/"+c.AID()+"/balance", "198.51.100.1"); code != 401 {
		t.Errorf("a signed request of the deregistered AID: %d %s", code, out["_raw"])
	}
}
