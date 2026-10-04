package aghub

import (
	"context"
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
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"

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
	ps, err := scan.Check(scan.Config{Dir: hubRoot(t), Repo: "ANetHub", Tags: [][]string{{"taskboard"}}})
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
		req("POST", "/relay/session", nil, "v030-todo(SS-4)"),
		resp("POST", "/relay/session", nil, "v030-todo(SS-4)"),
		resp("POST", "/relay/send", reflect.TypeFor[RelaySendResponse](), "v030-todo(SS-4)"),
		req("POST", "/relay/poll", reflect.TypeFor[RelayPollRequest](), ""),
		resp("POST", "/relay/poll", reflect.TypeFor[RelayPollResponse](), "v030-todo(KEL-5)"),
		req("POST", "/relay/ack", reflect.TypeFor[RelayAckRequest](), "v030-todo(RC-3)"),
		resp("POST", "/relay/ack", reflect.TypeFor[RelayAckResponse](), "v030-todo(RC-3)"),
		req("POST", "/relay/status", nil, "v030-todo(RC-3)"),
		resp("POST", "/relay/status", nil, "v030-todo(RC-3)"),
		req("POST", "/mailbox/revoke", nil, "v030-todo(SS-3)"),
		resp("POST", "/mailbox/revoke", nil, "v030-todo(SS-3)"),
		req("POST", "/directory:bucket", nil, "v030-todo(SS-5)"),
		resp("POST", "/directory:bucket", nil, "v030-todo(SS-5)"),
		// pricing and card leave the request with PAY-8; FS-3 still owes
		// enc_keys in base64url and prev_seq's rules.
		req("POST", "/register", reflect.TypeFor[RegisterRequest](), "v030-todo(PAY-8)"),
		{"POST", "/register", true, "registration", reflect.TypeFor[RegisterResponse](), "v030-todo(KEL-5)"},
		{"POST", "/register", true, "check_only", reflect.TypeFor[CheckOnlyResponse](), ""},
		req("POST", "/agents/{aid}/keys", reflect.TypeFor[KeysPublishRequest](), "v030-todo(FS-3)"),
		req("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("GET", "/hub/identity", reflect.TypeFor[hubid.IdentityResponse](), "v030-todo(SS-5)"),
		resp("GET", "/hub/kels", nil, "v030-todo(KEL-7)"),
		resp("GET", "/agents/{aid}/kel", nil, "v030-todo(KEL-5)"),
		resp("GET", "/a2a/v1/agents", nil, "v030-todo(SS-5)"),
		resp("GET", "/agents", nil, "v030-todo(SS-5)"),
		resp("GET", "/agents/{aid}/balance", reflect.TypeFor[Balance](), ""),
		resp("GET", "/agents/{aid}/ledger", nil, "v030-todo(PAY-4)"),
		resp("GET", "/agents/{aid}/redemptions", nil, "v030-todo(PAY-4)"),
		resp("GET", "/agents/{aid}/liability-proof", nil, "v030-todo(PAY-3)"),
		req("POST", "/reviews", reflect.TypeFor[UploadReviewRequest](), "v030-todo(PAY-6)"),
		resp("POST", "/reviews", nil, "v030-todo(PAY-6)"),
		resp("POST", "/fed/v3/forward", nil, "v030-todo(SS-6)"),
		req("POST", "/fed/v3/directory:bucket", nil, "v030-todo(SS-6)"),
		resp("POST", "/fed/v3/directory:bucket", nil, "v030-todo(SS-6)"),
		req("POST", "/fed/v3/relay-status", nil, "v030-todo(RC-3)"),
		resp("POST", "/fed/v3/relay-status", nil, "v030-todo(RC-3)"),
		resp("GET", "/fed/v3/reviews", nil, "v030-todo(PAY-6)"),
		resp("GET", "/fed/v3/cards", nil, "v030-todo(SS-6)"),
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
	alice, err := identity.Incept()
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
			c, err := identity.Incept()
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
		if err := rotor.Rotate(uint64(time.Now().UnixMilli())); err != nil {
			t.Fatal(err)
		}
		rotorOld, _ := identity.Restore(snap)
		rotorFork, _ := identity.Restore(snap)
		if err := rotorFork.Rotate(uint64(time.Now().UnixMilli()) + 17); err != nil {
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
	root.Handle("/hub/identity", id.Handler())
	root.Handle("/", s.Handler())

	alice, err := identity.Incept()
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
	}
}

// wire3LastSigned is the X-ANet-TS of the last request a fixture signed. Two requests signed in
// the same millisecond would be the same signature, which the replay cache refuses.
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
