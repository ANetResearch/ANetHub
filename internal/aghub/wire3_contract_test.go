package aghub

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
	"github.com/ANetResearch/ANetCore/wire/scan"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
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
		req("POST", "/register", reflect.TypeFor[RegisterRequest](), "v030-todo(FS-3)"),
		{"POST", "/register", true, "registration", reflect.TypeFor[RegisterResponse](), "v030-todo(KEL-5)"},
		{"POST", "/register", true, "check_only", nil, "v030-todo(PAY-5)"},
		req("POST", "/agents/{aid}/keys", reflect.TypeFor[KeysPublishRequest](), "v030-todo(FS-3)"),
		req("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("POST", "/agents/kel:push", nil, "v030-todo(KEL-5)"),
		resp("GET", "/hub/identity", reflect.TypeFor[hubid.IdentityResponse](), "v030-todo(SS-5)"),
		resp("GET", "/hub/kels", nil, "v030-todo(KEL-7)"),
		resp("GET", "/agents/{aid}/kel", nil, "v030-todo(KEL-5)"),
		resp("GET", "/a2a/v1/agents", nil, "v030-todo(SS-5)"),
		resp("GET", "/agents", nil, "v030-todo(SS-5)"),
		resp("GET", "/agents/{aid}/balance", nil, "v030-todo(PAY-5)"),
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
