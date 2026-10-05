package aghub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"
	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// ANetHub's half of the wire registry checks (ANetCore wire/registry.json).

func hubRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = up
	}
}

// TestWireRegistry (CORE-S3, ANetHub): every keyasint struct, "anet…" string, relayauth action
// and identity-key signing call in this repository's code matches the registry, or is a v0.2
// leftover listed in ANetCore wire/transition.json with the work item that removes it.
func TestWireRegistry(t *testing.T) {
	ps, err := scan.Check(scan.Config{Dir: hubRoot(t), Repo: "ANetHub"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		t.Error(p.String())
	}
}

// wire3StrictDecode is the hub's strict JSON request decoder (CORE-E7: an unknown member is
// 400 bad_request).
var wire3StrictDecode = wire3.DecodeStrict

// TestWire3JSONFields (CORE-S5): the request and response structs of the wire-3 endpoints have
// exactly the registered JSON members (for a partial body: at least the members wire 3 adds),
// and every request that the registry marks strict is decoded strictly. A row whose struct does
// not exist yet, or still has its wire-2 shape, is skipped with the work item that brings it to
// the registered shape; once it matches, the skip has to go.
func TestWire3JSONFields(t *testing.T) {
	r, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		method, path string
		response     bool   // false: the request body
		alt          string // the response alternative, when the registry lists several
		typ          reflect.Type
		todo         string
	}
	req := func(m, p string, typ reflect.Type, todo string) row { return row{m, p, false, "", typ, todo} }
	resp := func(m, p string, typ reflect.Type, todo string) row { return row{m, p, true, "", typ, todo} }
	rows := []row{
		req("POST", "/relay/session", reflect.TypeFor[SessionRequest](), ""),
		resp("POST", "/relay/session", reflect.TypeFor[SessionResponse](), ""),
		resp("POST", "/relay/send", reflect.TypeFor[RelaySendResponse](), ""),
		req("POST", "/relay/poll", reflect.TypeFor[RelayPollRequest](), ""),
		resp("POST", "/relay/poll", reflect.TypeFor[RelayPollResponse](), "v030-todo(KEL-5)"),
		req("POST", "/relay/ack", reflect.TypeFor[RelayAckRequest](), "v030-todo(RC-3)"),
		resp("POST", "/relay/ack", reflect.TypeFor[RelayAckResponse](), "v030-todo(RC-3)"),
		req("POST", "/relay/status", nil, "v030-todo(RC-3)"),
		resp("POST", "/relay/status", nil, "v030-todo(RC-3)"),
		req("POST", "/mailbox/revoke", reflect.TypeFor[MailboxRevokeRequest](), ""),
		resp("POST", "/mailbox/revoke", reflect.TypeFor[MailboxRevokeResponse](), ""),
		req("POST", "/directory:bucket", reflect.TypeFor[DirBucketRequest](), ""),
		resp("POST", "/directory:bucket", reflect.TypeFor[DirBucketResponse](), ""),
		req("POST", "/register", reflect.TypeFor[RegisterRequest](), ""),
		{"POST", "/register", true, "registration", reflect.TypeFor[RegisterResponse](), "v030-todo(KEL-5)"},
		{"POST", "/register", true, "check_only", reflect.TypeFor[CheckOnlyResponse](), ""},
		req("POST", "/agents/{aid}/keys", reflect.TypeFor[KeysPublishRequest](), "v030-todo(FS-3)"),
		req("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("GET", "/hub/identity", reflect.TypeFor[hubid.IdentityResponse](), ""),
		resp("GET", "/hub/kels", nil, "v030-todo(KEL-7)"),
		resp("GET", "/agents/{aid}/kel", nil, "v030-todo(KEL-5)"),
		resp("GET", "/a2a/v1/agents", reflect.TypeFor[A2AAgentEntry](), ""), // per entry
		resp("GET", "/agents", reflect.TypeFor[AgentView](), ""),            // per entry
		resp("GET", "/agents/{aid}/balance", reflect.TypeFor[Balance](), ""),
		resp("GET", "/agents/{aid}/ledger", nil, "v030-todo(PAY-4)"),
		resp("GET", "/agents/{aid}/redemptions", nil, "v030-todo(PAY-4)"),
		resp("GET", "/agents/{aid}/liability-proof", reflect.TypeFor[LiabilityProof](), ""),
		req("POST", "/reviews", reflect.TypeFor[UploadReviewRequest](), "v030-todo(PAY-6)"),
		resp("POST", "/reviews", nil, "v030-todo(PAY-6)"),
		resp("POST", "/fed/v3/forward", reflect.TypeFor[FedForwardResponse](), ""),
		req("POST", "/fed/v3/directory:bucket", reflect.TypeFor[DirBucketRequest](), ""),
		resp("POST", "/fed/v3/directory:bucket", reflect.TypeFor[FedBucketResponse](), ""),
		req("POST", "/fed/v3/relay-status", nil, "v030-todo(RC-3)"),
		resp("POST", "/fed/v3/relay-status", nil, "v030-todo(RC-3)"),
		resp("GET", "/fed/v3/reviews", nil, "v030-todo(PAY-6)"),
		resp("GET", "/fed/v3/cards", reflect.TypeFor[federation.FedA2ACardEntry](), ""), // per entry
	}
	covered := map[string]bool{}
	for _, rw := range rows {
		dir := "request"
		if rw.response {
			dir = "response"
		}
		name := rw.method + " " + rw.path + " " + dir
		if rw.alt != "" {
			name += " (" + rw.alt + ")"
		}
		covered[rw.method+" "+rw.path+" "+dir] = true
		t.Run(name, func(t *testing.T) {
			ep := r.Endpoint(rw.method, rw.path)
			if ep == nil {
				t.Fatalf("%s %s is not a registered endpoint", rw.method, rw.path)
			}
			body := ep.Request
			if rw.response {
				body = ep.Response
			}
			if rw.alt != "" {
				body = scan.Alt(body, rw.alt)
			}
			if body == nil || body.Raw != "" || len(body.Fields) == 0 && !body.Partial {
				t.Fatalf("the registry has no JSON %s for %s %s", dir, rw.method, rw.path)
			}
			var diff []string
			if rw.typ != nil {
				diff = scan.JSONFields(rw.typ, body)
			}
			if rw.todo != "" {
				if rw.typ != nil && len(diff) == 0 {
					t.Fatalf("%s now has the registered shape: drop its %s skip", name, rw.todo)
				}
				t.Skip(rw.todo + "\n" + strings.Join(diff, "\n"))
			}
			if rw.typ == nil {
				t.Fatal("no Go type bound to this body")
			}
			for _, d := range diff {
				t.Error(d)
			}
			if !rw.response && body.Strict {
				v := reflect.New(rw.typ).Interface()
				if err := wire3StrictDecode([]byte(`{"zz_not_registered":1}`), v); err == nil {
					t.Error("an unknown member was accepted (CORE-E7)")
				}
			}
		})
	}
	// every JSON body the registry lists has a row
	for _, ep := range r.HubAPI.Endpoints {
		for dir, b := range map[string]*wire.Body{"request": ep.Request, "response": ep.Response} {
			if b == nil || b.Raw != "" || len(b.Fields) == 0 && len(b.Alt) == 0 {
				continue
			}
			if !covered[ep.Method+" "+ep.Path+" "+dir] {
				t.Errorf("registered %s of %s %s has no row here", dir, ep.Method, ep.Path)
			}
		}
	}
}

// The hub wire-3 contract fixtures (core §5.2 WIRE3-*), testdata/wire3/*.json; the format is
// documented in internal/wire3/wire3test. A package that adds an endpoint or a refusal adds its
// file there, and a setup here when the cases need more than the plain hub.

// wire3Dir holds the fixture files.
const wire3Dir = "testdata/wire3"

// wire3Setups are the environments fixture files can name.
var wire3Setups = map[string]wire3test.Setup{
	"hub":             wire3HubSetup,
	"register":        wire3RegisterSetup(AdmissionClosed, "register"),
	"register_open":   wire3RegisterSetup(AdmissionOpen, "open"),
	"register_quota":  wire3RegisterSetup(AdmissionOpen, "quota"),
	"register_window": wire3RegisterSetup(AdmissionClosed, "window"),
	"rc1":             wire3RC1Setup,
	"revoke":          wire3RevokeSetup,
	"relay":           wire3RelaySetup,
	"supply":          wire3SupplySetup,
}

// wire3SupplySetup is the hub of wire3HubSetup with two published supply
// epochs, on a clock that starts at 2026-01-01T12:00Z (UTC day 20454; the
// supply epochs of hub-payment-privacy §2.3). alice (40) and bob (25) are
// granted credit on day 20454, so the first epoch, published seven days on,
// covers 20454..20460 with 65 outstanding; alice is granted 2 more, and the
// second, published on day 20468, covers 20461..20467 with 67. late is
// registered after that, so it is on neither epoch's books. Each epoch's
// id, prev_id, root and record are ${e0_…} and ${e1_…}.
func wire3SupplySetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, store, signers := wire3Hub(t)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	store.clock = func() time.Time { return now }
	bob, late := wire3Incept(t), wire3Incept(t)
	signers["bob"], signers["late"] = bob, late
	put := func(c *identity.Controller, name string) {
		kel, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.PutAgent(c.AID(), name, nil, kel); err != nil {
			t.Fatal(err)
		}
	}
	put(bob, "bob")
	grant := func(c *identity.Controller, n int64) {
		if err := store.GrantCredit(c.AID(), n, "fixture"); err != nil {
			t.Fatal(err)
		}
	}
	grant(signers["alice"], 40)
	grant(bob, 25)
	var epochs []*SupplyEpochEntry
	publish := func(days int) {
		now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC).AddDate(0, 0, days)
		e, err := store.publishDueAt(now)
		if err != nil || e == nil {
			t.Fatalf("publish on day +%d: %+v %v", days, e, err)
		}
		epochs = append(epochs, e)
	}
	publish(7)
	grant(signers["alice"], 2)
	publish(14)
	put(late, "late")
	env.Vars["bob"], env.Vars["late"] = bob.AID(), late.AID()
	for i, e := range epochs {
		p := "e" + strconv.Itoa(i) + "_"
		env.Vars[p+"id"], env.Vars[p+"prev"], env.Vars[p+"root"], env.Vars[p+"record"] = e.ID, e.PrevID, e.Root, e.Record
	}
	env.Vars["supply_note"] = supplyNote
	return env
}

// wire3RelaySetup is the hub of wire3HubSetup for the /relay/session and
// /relay/send fixtures (sealed-sender §4.2.1, §4.2.3). alice is registered
// and has a first-contact session (${sid}); bob is registered with a mailbox
// key and issued alice a contact credential; nobody is not registered.
// Envelopes, base64url, with what their sends need:
//
//	${env_first}    a first contact from alice to bob, MAC ${mac_first}
//	${env_unknown}  a first contact to nobody, MAC ${mac_unknown}
//	${env_cap}      an envelope to bob under the credential, ${access_cap}
//	${env_forged}   the same credential with a proof by another key,
//	                ${access_forged}
//
// The MACs are over POST /relay/send, no X-ANet-Home, at ${ts}; ${access0}
// is the kind-0 access.
func wire3RelaySetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, store, signers := wire3Hub(t)
	hubAID := env.Vars["hub"]
	alice, bob, nobody := signers["alice"], wire3Incept(t), wire3Incept(t)
	signers["bob"], signers["nobody"] = bob, nobody
	kel, err := identity.MarshalKEL(bob.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(bob.AID(), "bob", nil, kel); err != nil {
		t.Fatal(err)
	}
	owner := &relayAgent{c: bob, aid: bob.AID()}
	(&relayHub{t: t, store: store, now: time.Now()}).publishTo(owner, 1, time.Now())
	ss, rec := openSessionVia(t, env.Handler, hubAID, alice)
	if rec.Code != http.StatusOK {
		t.Fatalf("open a session: %d %s", rec.Code, rec.Body)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	ts := uint64(time.Now().UnixMilli())
	first := func(name, to string) {
		e := envelope(t, to, []byte(name))
		mac, err := relayauth.SessionMAC(ss.key, ss.sid, ts, http.MethodPost, "/relay/send", "", e)
		if err != nil {
			t.Fatal(err)
		}
		env.Vars["env_"+name], env.Vars["mac_"+name] = b64(e), relayauth.EncodeMAC(mac)
	}
	first("first", bob.AID())
	first("unknown", nobody.AID())
	g := (&relayHub{t: t, now: time.Now()}).issue(owner, seal.CapClassContact, 24*time.Hour)
	withAccess := func(name string, g grant) {
		e := withCap(t, envelope(t, bob.AID(), []byte(name)), g)
		env.Vars["env_"+name], env.Vars["access_"+name] = b64(e), b64(accessRaw(t, e))
	}
	withAccess("cap", g)
	_, g.holder, _ = ed25519.GenerateKey(nil)
	withAccess("forged", g)
	env.Vars["bob"], env.Vars["nobody"] = bob.AID(), nobody.AID()
	env.Vars["sid"], env.Vars["ts"] = relayauth.EncodeSessionID(ss.sid), strconv.FormatUint(ts, 10)
	env.Vars["access0"] = b64([]byte{0xa1, 0x01, 0x00})
	env.Vars["epk"] = b64(func() []byte { _, epk, _ := relayauth.NewSessionKey(); return epk }())
	env.Vars["epk_short"] = b64(make([]byte, 31))
	return env
}

// wire3RC1Setup is wire3HubSetup for the RC1 fixtures (hub-payment-privacy
// §4.2.5). alice signs at now; alice_again signs at the time of alice's
// last request (a time accepted before); alice_before_start signs at a
// time before the hub started, which is at or below every signer's floor
// (${start_floor}); alice_bad_before_start is that with a signature over
// another body.
func wire3RC1Setup(t *testing.T) *wire3test.Env {
	t.Helper()
	before := uint64(time.Now().UnixMilli()) - 1000
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := NewServer(store)
	s.SetHubAID(id.AID)
	root := http.NewServeMux()
	root.Handle("/hub/identity", id.Handler())
	root.Handle("/", s.Handler())
	alice, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(alice.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(alice.AID(), "alice", nil, kel); err != nil {
		t.Fatal(err)
	}
	var last uint64
	return &wire3test.Env{
		Handler: wire3.Contract(root),
		Vars: map[string]string{"hub": id.AID, "alice": alice.AID(),
			"start_floor": strconv.FormatUint(s.replay.floorOf(alice.AID()), 10)},
		Sign: func(req *http.Request, body []byte, action, as string) error {
			signed := body
			var ts uint64
			switch as {
			case "alice":
				ts = uint64(wire3SigningNow().UnixMilli())
				last = ts
			case "alice_again":
				ts = last
			case "alice_before_start":
				ts = before
			case "alice_bad_before_start":
				ts, signed = before, append(append([]byte(nil), body...), ' ')
			default:
				return fmt.Errorf("no identity %q in this setup", as)
			}
			sig, seq := alice.Sign(relayauth.PreimageV2(action, alice.AID(), id.AID, ts, req.Method, req.URL.RequestURI(), signed))
			req.Header.Set(relayauth.HeaderAID, alice.AID())
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
			return nil
		},
	}
}

// wire3RegisterSetup is a hub for the /register fixtures (hub-payment-
// privacy PAY-A1), in the given admission mode, served as anet-hub serves
// it. Identities, each also a ${name} variable (its AID) with ${name_kel}
// (its key history, base64url):
//
//	alice     registered here
//	listed    on the admission list, not registered
//	stranger  neither; stranger2 too
//	rotor     registered with icp and one rot; rotor_old signs as rotor
//	          with the icp key (its KEL: ${rotor_old_kel}), rotor_fork with
//	          another rot from the icp (${rotor_fork_kel})
//
// ${alice_kel_std} is alice's key history in padded standard base64.
// variant "open", "quota" and "window" add what their cases need:
// ${pow_seed}, the challenge seed of this hour, and ${stranger_nonce} (and
// for window ${stranger2_nonce}), a 22-bit proof of work found for it;
// ${bogus_seed} is no hour's seed. "quota" has spent today's
// open-registration places of the fixtures' client address (192.0.2.1);
// "window" has a sign-up window with one place.
func wire3RegisterSetup(mode, variant string) wire3test.Setup {
	return func(t *testing.T) *wire3test.Env {
		t.Helper()
		store, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		id, err := hubid.LoadOrIncept(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		store.SetHubKey(id.Ctrl)
		s := NewServer(store)
		s.SetHubAID(id.AID)
		if err := store.SetAdmissionMode(mode); err != nil {
			t.Fatal(err)
		}
		root := http.NewServeMux()
		root.Handle("/hub/identity", id.Handler())
		root.Handle("/", s.Handler())

		incept := func() *identity.Controller {
			c, err := identitytest.Hub()
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		kelOf := func(c *identity.Controller) []byte {
			b, err := identity.MarshalKEL(c.KEL())
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		alice, listed, stranger, stranger2, rotor := incept(), incept(), incept(), incept(), incept()
		snap, err := rotor.Export()
		if err != nil {
			t.Fatal(err)
		}
		if err := identitytest.Rotate(rotor, uint64(time.Now().UnixMilli())); err != nil {
			t.Fatal(err)
		}
		rotorOld, _ := identity.Restore(snap)
		rotorFork, _ := identity.Restore(snap)
		if err := identitytest.Rotate(rotorFork, uint64(time.Now().UnixMilli())+17); err != nil {
			t.Fatal(err)
		}
		for _, c := range []*identity.Controller{alice, rotor} {
			if err := store.PutAgent(c.AID(), "fixture", nil, kelOf(c)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := store.Admit(listed.AID(), 0, "", false); err != nil {
			t.Fatal(err)
		}
		vars := map[string]string{"hub": id.AID}
		signers := map[string]*identity.Controller{}
		for name, c := range map[string]*identity.Controller{"alice": alice, "listed": listed, "stranger": stranger,
			"stranger2": stranger2, "rotor": rotor, "rotor_old": rotorOld, "rotor_fork": rotorFork} {
			vars[name] = c.AID()
			vars[name+"_kel"] = base64.RawURLEncoding.EncodeToString(kelOf(c))
			signers[name] = c
		}
		vars["alice_kel_std"] = base64.StdEncoding.EncodeToString(kelOf(alice))
		now := time.Now()
		seed := store.gate().powSeed(regpow.Hour(uint64(now.UnixMilli())))
		vars["pow_seed"] = base64.RawURLEncoding.EncodeToString(seed[:])
		bogus := sha256.Sum256([]byte("wire3 fixture: a seed of no hour"))
		vars["bogus_seed"] = base64.RawURLEncoding.EncodeToString(bogus[:])
		solve := func(c *identity.Controller) string {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			n, err := regpow.Solve(ctx, id.AID, c.AID(), seed, regpow.Bits)
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawURLEncoding.EncodeToString(n)
		}
		switch variant {
		case "open", "quota":
			vars["stranger_nonce"] = solve(stranger)
		case "window":
			vars["stranger_nonce"] = solve(stranger)
			vars["stranger2_nonce"] = solve(stranger2)
			if _, err := store.OpenWindow(time.Hour, 1, "fixture"); err != nil {
				t.Fatal(err)
			}
		}
		if variant == "quota" {
			for i := 0; i < 20; i++ {
				if _, ok := store.gate().reserveSignup(net.ParseIP("192.0.2.1"), now); !ok {
					t.Fatal("could not fill the quota")
				}
			}
		}
		return &wire3test.Env{
			Handler: wire3.Contract(root),
			Vars:    vars,
			Sign: func(req *http.Request, body []byte, action, as string) error {
				c, ok := signers[as]
				if !ok {
					return fmt.Errorf("no identity %q in this setup", as)
				}
				ts := uint64(wire3SigningNow().UnixMilli())
				sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), id.AID, ts, req.Method, req.URL.RequestURI(), body))
				req.Header.Set(relayauth.HeaderAID, c.AID())
				req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
				req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
				req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
				return nil
			},
		}
	}
}

// wire3HubSetup is a hub served the way anet-hub serves it (cmd/anet-hub newRoot and hubHandler):
// /hub/identity beside the kernel, the whole root under wire3.Contract. One agent, alice, is
// registered; ${hub} and ${alice} are their AIDs, and a case can sign as alice.
func wire3HubSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, _, _ := wire3Hub(t)
	return env
}

// wire3Hub is wire3HubSetup with its store and the identities its cases can sign as, for the
// setups that build on it: an identity added to signers can sign too.
func wire3Hub(t *testing.T) (*wire3test.Env, *Store, map[string]*identity.Controller) {
	t.Helper()
	store, err := Open(t.TempDir())
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
	t.Cleanup(func() { store.Close() })
	root := http.NewServeMux()
	id.DirMaxBits = s.DirMaxBits // as cmd/anet-hub newRoot does
	root.Handle("/hub/identity", id.Handler())
	root.Handle("/", s.Handler())

	alice, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(alice.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(alice.AID(), "alice", nil, kel); err != nil {
		t.Fatal(err)
	}
	signers := map[string]*identity.Controller{"alice": alice}
	return &wire3test.Env{
		Handler: wire3.Contract(root),
		Vars:    map[string]string{"hub": id.AID, "alice": alice.AID()},
		Sign: func(req *http.Request, body []byte, action, as string) error {
			c, ok := signers[as]
			if !ok {
				return fmt.Errorf("no identity %q in this setup", as)
			}
			ts := uint64(wire3SigningNow().UnixMilli())
			sig, seq := c.Sign(relayauth.PreimageV2(action, c.AID(), id.AID, ts, req.Method, req.URL.RequestURI(), body))
			req.Header.Set(relayauth.HeaderAID, c.AID())
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
			return nil
		},
	}, store, signers
}

// wire3RevokeSetup is the hub of wire3HubSetup for the /mailbox/revoke fixtures (sealed-sender
// SSR-H10, SSR-H11): alice is registered with no revocation; full is registered with
// MaxRevocationsPerOwner unexpired revocations (ids 0xf0, 0…, the index in the last 8 bytes);
// stranger is not registered. ${id1}, ${id2} and ${id3} are fresh 16-byte ids, ${id_padded} id1
// padded, ${id_std} a 16-byte id in the standard alphabet, ${id_short} a 15-byte one, and
// ${full_id0} the first id full revoked.
func wire3RevokeSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	env, store, signers := wire3Hub(t)
	full, stranger := wire3Incept(t), wire3Incept(t)
	signers["full"], signers["stranger"] = full, stranger
	kel, err := identity.MarshalKEL(full.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAgent(full.AID(), "full", nil, kel); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`WITH RECURSIVE k(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM k WHERE i+1 < ?)
	    INSERT INTO cap_revocation(owner, cap_id, revoked_at)
	    SELECT ?, unhex('F000000000000000' || printf('%016X', i)), ? FROM k`,
		MaxRevocationsPerOwner, full.AID(), time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	id := func(tag byte, n int) []byte {
		b := make([]byte, 16)
		b[0] = tag
		b[15] = byte(n)
		return b
	}
	b64 := base64.RawURLEncoding.EncodeToString
	env.Vars["full"], env.Vars["stranger"] = full.AID(), stranger.AID()
	env.Vars["id1"], env.Vars["id2"], env.Vars["id3"] = b64(id(1, 1)), b64(id(1, 2)), b64(id(1, 3))
	env.Vars["id_padded"] = base64.URLEncoding.EncodeToString(id(1, 1))
	env.Vars["id_std"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 16))
	env.Vars["id_short"] = b64(make([]byte, 15))
	env.Vars["full_id0"] = b64(id(0xf0, 0))
	return env
}

// wire3Incept is one more identity for a fixture to sign as, incepted like alice.
func wire3Incept(t *testing.T) *identity.Controller {
	t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// wire3LastSigned is the X-ANet-TS of the last request a fixture signed. RC1 takes each of a
// signer's times once, so two requests signed in the same millisecond would be refused as replayed.
var wire3LastSigned atomic.Int64

// wire3SigningNow is now, at least one millisecond after the previous signature.
func wire3SigningNow() time.Time {
	for {
		last := wire3LastSigned.Load()
		now := time.Now().UnixMilli()
		if now <= last {
			now = last + 1
		}
		if wire3LastSigned.CompareAndSwap(last, now) {
			return time.UnixMilli(now)
		}
	}
}

// wire3ErrorSamples are the extra members the error-body fixtures carry, for the codes that have
// some. Public, made-up values.
func wire3ErrorSamples() map[wire3.Reason]map[string]any {
	seed := sha256.Sum256([]byte("wire3 fixture: proof-of-work challenge seed"))
	return map[wire3.Reason]map[string]any{
		wire3.ReasonTSStale:           {"floor": 1767225600000},
		wire3.ReasonKeysRollback:      {"stored_seq": 7},
		wire3.ReasonBucketTooNarrow:   {"max_bits": 12},
		wire3.ReasonAdmissionRequired: {"aid": "bafyreigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"},
		wire3.ReasonPowRequired: {"challenge": map[string]any{
			"seed": base64.RawURLEncoding.EncodeToString(seed[:]), "bits": 22, "not_after": 1767229200000}},
	}
}

// TestWire3Fixtures runs every fixture file: the error body of each hub reason code (errors.json)
// and the request/response cases (core CORE-V1 negotiation, CORE-E7, CORE-E9, and each area's
// endpoints as they land).
//
// WIRE3_UPDATE=errors rewrites errors.json from wire3.Write, for a deliberate change of a
// sentence or a member (review the diff: these bytes are what daemons are tested against).
func TestWire3Fixtures(t *testing.T) {
	if os.Getenv("WIRE3_UPDATE") == "errors" {
		entries, err := wire3test.ErrorEntries(wire3ErrorSamples(), 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		f := &wire3test.File{
			Format: wire3test.Format,
			About: "The error body of every hub reason code (core §2.15.1, G1): the status, " +
				"Retry-After for a status that asks the caller to wait (here written with 30 seconds), " +
				"and {reason, error, ...} with the code's default sentence and its required members " +
				"(sample values). Generated by WIRE3_UPDATE=errors go test -run TestWire3Fixtures.",
			Errors: entries,
		}
		if err := wire3test.WriteFile(filepath.Join(wire3Dir, "errors.json"), f); err != nil {
			t.Fatal(err)
		}
	}
	wire3test.Run(t, wire3Dir, wire3Setups)
}
