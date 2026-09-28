package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// FuzzAdminAPI drives the admin surface's JSON-decoding routes (login,
// moderation, official manifests) and its path and query parameters with
// fuzzed bodies, credentials and source addresses (ANet
// docs/notes/0033-验证-模糊测试-hub.md). Properties:
//
//   - no answer is a 5xx;
//   - no API route answers 200 without the operator's token, and login
//     answers 200 only for it;
//   - a moderation stored is one of ok, flagged, delisted;
//   - an official manifest answered 200 is one ParseManifest accepts, and
//     reading it back returns the manifest as parsed.
func FuzzAdminAPI(f *testing.F) {
	hubDir := f.TempDir()
	hs, err := aghub.Open(hubDir)
	if err != nil {
		f.Fatal(err)
	}
	var aids []string
	for i := 0; i < 3; i++ {
		c, _ := identity.Incept()
		kel, _ := identity.MarshalKEL(c.KEL())
		if err := hs.PutAgent(c.AID(), "agent", []string{"echo"}, kel); err != nil {
			f.Fatal(err)
		}
		aids = append(aids, c.AID())
	}
	hs.Close()
	store, err := OpenStore(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { store.Close() })
	hub, err := OpenHubDB(hubDir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { hub.Close() })
	adminDir := f.TempDir()
	srv := NewServer(store, hub, NewHarvester(filepath.Join(adminDir, "datasets")), NewVecClient(""), "test-token", "/admin")
	h := srv.Handler()

	f.Add(uint8(0), "", []byte(`{"token":"test-token"}`), "", "10.0.0.1")
	f.Add(uint8(0), "", []byte(`{"token":"wrong"}`), "", "10.0.0.2")
	f.Add(uint8(1), "Bearer test-token", []byte(`{"status":"flagged","note":"n"}`), aids[0], "")
	f.Add(uint8(1), "Bearer test-token", []byte(`{"status":"banished"}`), aids[1], "")
	f.Add(uint8(2), "Bearer test-token", []byte(`{"id":"a-1","name":"A","tier":"official","product_line":"anetos","aid":"x","caps":["c"]}`), "", "")
	f.Add(uint8(2), "Bearer test-token", []byte(`{"id":"a-1","name":"A","tier":"official","product_line":"anetos","runtime":{}}`), "", "")
	f.Add(uint8(3), "Bearer test-token", []byte(nil), "a-1", "")
	f.Add(uint8(4), "bearer  test-token", []byte(nil), "q=echo&tier=official", "")
	f.Add(uint8(5), "Bearer test-token", []byte(nil), aids[2], "")
	f.Add(uint8(6), "Bearer test-token", []byte(nil), aids[2], "")
	f.Add(uint8(7), "Bearer test-token", []byte(nil), "q=%zz", "")
	f.Add(uint8(1), "Bearer wrong", []byte(`{"status":"ok"}`), aids[0], "10.9.9.9")

	f.Fuzz(func(t *testing.T, route uint8, authz string, body []byte, param, ip string) {
		authz, param, ip = clip(authz, 256), clip(param, 512), clip(ip, 64)
		body = clipB(body, 16<<10)
		var method, path, query string
		switch route % 8 {
		case 0:
			method, path = http.MethodPost, "/admin/api/login"
		case 1:
			method, path = http.MethodPost, "/admin/api/agents/"+param+"/moderate"
		case 2:
			method, path = http.MethodPost, "/admin/api/official"
		case 3:
			method, path = http.MethodDelete, "/admin/api/official/"+param
		case 4:
			method, path, query = http.MethodGet, "/admin/api/agents", param
		case 5:
			method, path = http.MethodGet, "/admin/api/agents/"+param
		case 6:
			method, path = http.MethodPost, "/admin/api/deleted/"+param+"/restore"
		case 7:
			method, path, query = http.MethodGet, "/admin/api/discover", param
		}
		req := httptest.NewRequest(method, "/", bytes.NewReader(body))
		req.URL.Path = path
		req.URL.RawQuery = query
		req.RequestURI = req.URL.RequestURI()
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		if ip != "" {
			req.Header.Set("X-Real-Ip", ip)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.Bytes())
		}
		tok, hasTok := bearerToken(authz)
		authorized := hasTok && tok == "test-token"
		if rec.Code == http.StatusOK && !authorized {
			if route%8 != 0 {
				t.Fatalf("%s %s answered 200 to credentials %q", method, path, authz)
			}
			var lr struct {
				Token string `json:"token"`
			}
			if json.NewDecoder(bytes.NewReader(body)).Decode(&lr) != nil || lr.Token != "test-token" {
				t.Fatalf("login answered 200 for %q", body)
			}
		}
		if rec.Code != http.StatusOK {
			return
		}
		switch route % 8 {
		case 1:
			aid := path[len("/admin/api/agents/") : len(path)-len("/moderate")]
			mods, err := store.Moderations()
			if err != nil {
				t.Fatal(err)
			}
			m, ok := mods[aid]
			if !ok {
				// The mux matched another path shape; nothing to check.
				return
			}
			switch m.Status {
			case "ok", "flagged", "delisted":
			default:
				t.Fatalf("moderation stored with status %q", m.Status)
			}
		case 2:
			m, err := ParseManifest(bytes.TrimSpace(body))
			if err != nil {
				t.Fatalf("an official manifest ParseManifest refuses was accepted: %v", err)
			}
			got, err := store.Official(m.ID)
			if err != nil {
				t.Fatalf("accepted official %q cannot be read back: %v", m.ID, err)
			}
			if !reflect.DeepEqual(normManifest(got), normManifest(m)) {
				t.Fatalf("official %q read back as %+v, accepted as %+v", m.ID, got, m)
			}
		}
	})
}

// normManifest treats a nil and an empty capability list alike.
func normManifest(m *Manifest) Manifest {
	c := *m
	if len(c.Caps) == 0 {
		c.Caps = nil
	}
	return c
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func clipB(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
