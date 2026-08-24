package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
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
