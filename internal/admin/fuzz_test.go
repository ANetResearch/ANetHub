package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// FuzzAdminAPI drives the admin surface's JSON-decoding routes (login,
// moderation, official manifests), the operator's delete and the deleted
// list, and their path and query parameters, with fuzzed bodies,
// credentials and source addresses (ANet
// an internal note). Properties:
//
//   - no answer is a 5xx;
//   - no API route answers 200 without the operator's token, and login
//     answers 200 only for it;
//   - a moderation stored is one of ok, flagged, delisted;
//   - an official manifest answered 200 is one ParseManifest accepts, and
//     reading it back returns the manifest as parsed;
//   - a delete answered 200 was of a registered agent, which is then
//     deregistered with its key history kept as its tombstone (PAY-O3);
//   - the removed restore route never answers 200 (PAY-O4);
//   - the deleted list as an admit file is valid AIDs, each once; any other
//     format is refused.
func FuzzAdminAPI(f *testing.F) {
	hubDir := f.TempDir()
	hs, err := aghub.Open(hubDir)
	if err != nil {
		f.Fatal(err)
	}
	var aids []string
	for i := 0; i < 3; i++ {
		c, _ := identitytest.Hub()
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
	rawHub, err := sql.Open("sqlite", filepath.Join(hubDir, "hub.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { rawHub.Close() })
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
	f.Add(uint8(6), "Bearer test-token", []byte(nil), "bafynotregistered", "")
	f.Add(uint8(7), "Bearer test-token", []byte(nil), "q=%zz", "")
	f.Add(uint8(8), "Bearer test-token", []byte(nil), "format=admit", "")
	f.Add(uint8(8), "Bearer test-token", []byte(nil), "format=admit&limit=-3", "")
	f.Add(uint8(8), "Bearer test-token", []byte(nil), "format=csv", "")
	f.Add(uint8(9), "Bearer test-token", []byte(nil), aids[1], "")
	f.Add(uint8(1), "Bearer wrong", []byte(`{"status":"ok"}`), aids[0], "10.9.9.9")

	f.Fuzz(func(t *testing.T, route uint8, authz string, body []byte, param, ip string) {
		authz, param, ip = clip(authz, 256), clip(param, 512), clip(ip, 64)
		body = clipB(body, 16<<10)
		var method, path, query string
		switch route % 10 {
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
			method, path = http.MethodDelete, "/admin/api/agents/"+param
		case 7:
			method, path, query = http.MethodGet, "/admin/api/discover", param
		case 8:
			method, path, query = http.MethodGet, "/admin/api/deleted", param
		case 9:
			method, path = http.MethodPost, "/admin/api/deleted/"+param+"/restore"
		}
		var registered bool
		if route%10 == 6 {
			var n int
			_ = rawHub.QueryRow(`SELECT COUNT(*) FROM agent WHERE aid = ?`, param).Scan(&n)
			registered = n == 1
		}
		req := httptest.NewRequest(method, "/", bytes.NewReader(body))
		req.URL.Path = path
		req.URL.RawQuery = query
		req.RequestURI = req.URL.RequestURI()
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		if ip != "" {
			req.RemoteAddr = "127.0.0.1:40000"
			req.Header.Set("X-Real-Ip", ip)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.Bytes())
		}
		tok, hasTok := bearerToken(authz)
		authorized := hasTok && tok == "test-token"
		if route%10 == 9 && rec.Code == http.StatusOK {
			t.Fatalf("the removed restore route answered 200: %s", rec.Body.Bytes())
		}
		if rec.Code == http.StatusOK && !authorized {
			if route%10 != 0 {
				t.Fatalf("%s %s answered 200 to credentials %q", method, path, authz)
			}
			var lr struct {
				Token string `json:"token"`
			}
			if json.NewDecoder(bytes.NewReader(body)).Decode(&lr) != nil || lr.Token != "test-token" {
				t.Fatalf("login answered 200 for %q", body)
			}
		}
		if route%10 == 8 && authorized && rec.Code != http.StatusTooManyRequests {
			switch format := req.URL.Query().Get("format"); {
			case format == "admit" && rec.Code != http.StatusOK, format != "admit" && format != "" && rec.Code != http.StatusBadRequest:
				t.Fatalf("GET %s?%s: %d", path, query, rec.Code)
			}
		}
		if rec.Code != http.StatusOK {
			return
		}
		switch route % 10 {
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
		case 6:
			// Answered 200, the path was taken as it is: its last segment
			// is the AID.
			aid := path[len("/admin/api/agents/"):]
			var agents, tombs int
			_ = rawHub.QueryRow(`SELECT COUNT(*) FROM agent WHERE aid = ?`, aid).Scan(&agents)
			_ = rawHub.QueryRow(`SELECT COUNT(*) FROM departed_kel WHERE aid = ?`, aid).Scan(&tombs)
			if !registered || agents != 0 || tombs != 1 {
				t.Fatalf("DELETE %q answered 200: registered before %v, agent rows %d, tombstones %d",
					aid, registered, agents, tombs)
			}
		case 8:
			if req.URL.Query().Get("format") != "admit" {
				return
			}
			seen := map[string]bool{}
			for _, l := range strings.Split(strings.TrimSuffix(rec.Body.String(), "\n"), "\n") {
				if l == "" && rec.Body.Len() == 0 {
					continue
				}
				if !aghub.ValidAID(l) || seen[l] {
					t.Fatalf("the admit file has the line %q (valid %v, repeated %v)", l, aghub.ValidAID(l), seen[l])
				}
				seen[l] = true
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
