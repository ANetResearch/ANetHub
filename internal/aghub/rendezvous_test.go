package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
)

func publishAddr(t *testing.T, srv *httptest.Server, c *identity.Controller, addr string) (int, []byte) {
	t.Helper()
	ts := uint64(time.Now().UnixMilli())
	sig, seq := c.Sign(relayauth.Preimage(relayauth.ActionProfile, c.AID(), ts))
	return post(t, srv.URL+"/agents/"+c.AID()+"/p2p", map[string]any{
		"addr": addr, "ts": ts, "key_state_seq": seq,
		"sig": base64.StdEncoding.EncodeToString(sig)})
}

// Two peers on different machines must be able to find each other.
//
// Discovery was a shared filesystem directory, so the p2p transport —
// which can carry traffic between machines — could only be used by nodes
// on one box, the case that does not need it. The hub already knows who
// exists, so it can answer "where do I dial this AID".
func TestTheHubCanActAsAPeerRendezvous(t *testing.T) {
	srv := newHub(t)
	a, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "Peer A", []string{"work.do"})

	// Nothing published: not listed, and said so as 404 rather than as an
	// empty address. A caller must be able to tell "not listed" from
	// "listed at nowhere" — the first falls back to the hub, the second
	// would be dialled.
	if code, _ := getJSON(t, srv.URL+"/agents/"+a.AID()+"/p2p"); code != 404 {
		t.Errorf("lookup of an unlisted agent = %d, want 404", code)
	}

	if code, body := publishAddr(t, srv, a, "tcp://10.0.0.7:39100"); code != 200 {
		t.Fatalf("publish = %d %s", code, body)
	}
	code, body := getJSON(t, srv.URL+"/agents/"+a.AID()+"/p2p")
	if code != 200 {
		t.Fatalf("lookup = %d %s", code, body)
	}
	var got struct{ Addr string }
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Addr != "tcp://10.0.0.7:39100" {
		t.Errorf("addr = %q", got.Addr)
	}

	// Withdrawing is separate from deregistering: an agent that wants
	// delivery but not direct connections must be able to say so without
	// leaving the hub.
	if code, body := publishAddr(t, srv, a, ""); code != 200 {
		t.Fatalf("withdraw = %d %s", code, body)
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+a.AID()+"/p2p"); code != 404 {
		t.Errorf("lookup after withdrawal = %d, want 404", code)
	}
}

// The hub must not be able to list an agent that did not ask to be
// listed. An address is a statement about oneself, and an unsigned one
// would let anybody publish where anybody else can be reached.
func TestAPeerAddressMustBeSignedByItsOwner(t *testing.T) {
	srv := newHub(t)
	a, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "Peer A", []string{"work.do"})

	code, _ := post(t, srv.URL+"/agents/"+a.AID()+"/p2p", map[string]any{
		"addr": "tcp://evil:1", "ts": uint64(time.Now().UnixMilli()),
		"key_state_seq": 0, "sig": base64.StdEncoding.EncodeToString([]byte("nope")),
	})
	if code == 200 {
		t.Error("an unsigned address was accepted")
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+a.AID()+"/p2p"); code == 200 {
		t.Error("the forged address was published")
	}
}

// The directory is published, because the cost of this feature is that
// the hub now holds a list of addresses. An operator, and an agent
// deciding whether to list itself, should both be able to see exactly
// what that list contains.
func TestThePeerDirectoryIsVisible(t *testing.T) {
	srv := newHub(t)
	a, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "Peer A", []string{"work.do"})
	publishAddr(t, srv, a, "tcp://10.0.0.7:39100")

	code, body := getJSON(t, srv.URL+"/p2p/peers")
	if code != 200 {
		t.Fatalf("directory = %d %s", code, body)
	}
	var got struct {
		Peers map[string]string `json:"peers"`
		Count int               `json:"count"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Count != 1 || got.Peers[a.AID()] != "tcp://10.0.0.7:39100" {
		t.Errorf("directory = %+v", got)
	}
}

// A correcting entry closes the gap once, is visible, and cannot move
// money.
//
// Accounts carrying settlements from before settlement wrote ledger
// entries have balances that moved and left nothing behind. `anet
// reconcile` then reports a discrepancy on every run — and a check that
// always says something is wrong is a check people stop reading.
func TestALedgerCorrectionIsDerivedAndVisible(t *testing.T) {
	srv, store := newHubWithStore(t)
	a, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	register(t, srv, a, "Old account", []string{"work.do"})

	// A balance move with no entry behind it: the shape the old
	// settlement path left.
	if err := store.MoveBalanceWithoutEntryForTest(a.AID(), -30); err != nil {
		t.Fatal(err)
	}
	bal, _ := store.Balance(a.AID())
	_, sum, err := store.LedgerTotals(a.AID())
	if err != nil {
		t.Fatal(err)
	}
	if bal == sum {
		t.Fatal("the fixture did not create a gap")
	}

	delta, err := store.RepairLedger(a.AID())
	if err != nil {
		t.Fatal(err)
	}
	if delta != bal-sum {
		t.Errorf("wrote %d, want the gap %d", delta, bal-sum)
	}
	// The balance is untouched: this writes history, it does not move
	// money, so an operator can run it and cannot aim it.
	if got, _ := store.Balance(a.AID()); got != bal {
		t.Errorf("the balance changed from %d to %d", bal, got)
	}
	_, sum2, _ := store.LedgerTotals(a.AID())
	if sum2 != bal {
		t.Errorf("entries sum to %d, balance is %d — the gap is still there", sum2, bal)
	}
	// And running it again does nothing, because there is no gap left.
	again, err := store.RepairLedger(a.AID())
	if err != nil || again != 0 {
		t.Errorf("a second run wrote %d (err %v); it must be a no-op", again, err)
	}

	// The correction is in the ledger, named for what it is.
	code, body := getJSON(t, srv.URL+"/agents/"+a.AID()+"/ledger?limit=500")
	if code != 200 {
		t.Fatalf("ledger = %d", code)
	}
	if !strings.Contains(string(body), "ledger correction") {
		t.Error("the correction is not visible in the ledger")
	}
}
