package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// T-1 findings: anonymous floods, log injection, forged client addresses.

func TestAnonymousRequestsDoNotFloodTheAuditLog(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)
	before := auditCount(t, store, "auth.missing")
	for i := 0; i < 2000; i++ {
		r := httptest.NewRequest("GET", "/admin/api/overview", nil)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if n := auditCount(t, store, "auth.missing") - before; n > 1 {
		t.Fatalf("2000 anonymous requests from one source wrote %d audit rows, want at most 1", n)
	}
	// Many sources together stay under the global cap.
	for i := 0; i < 500; i++ {
		r := httptest.NewRequest("GET", "/admin/api/overview", nil)
		r.RemoteAddr = "10.1." + string(rune('0'+i%10)) + "." + strings1(i) + ":1"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if n := auditCount(t, store, "auth.missing") - before; n > denialGlobalPerMin {
		t.Fatalf("anonymous requests from many sources wrote %d rows, cap is %d", n, denialGlobalPerMin)
	}
}

func strings1(i int) string {
	return strings.Repeat("1", 1) + string(rune('0'+i/10%10)) + string(rune('0'+i%10))
}

func TestAPathCannotForgeALogLine(t *testing.T) {
	srv, store, _, _, _ := newTestServer(t)
	h := srv.Handler()
	buf := captureLog(t)
	r := httptest.NewRequest("GET", "/admin/api/overview%0Aadmin:%20auth.ok%20ip=1.2.3.4%20FORGED", nil)
	h.ServeHTTP(httptest.NewRecorder(), r)
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "admin: auth.ok") {
			t.Fatalf("forged log line: %q", line)
		}
	}
	rows, _ := store.AuditTail(10)
	for _, e := range rows {
		if strings.ContainsAny(e.Detail+e.Target, "\n\r") {
			t.Fatalf("control character in audit row: %+v", e)
		}
	}
}

func TestAForgedRealIPFromANonLoopbackPeerDoesNotRotateTheBudget(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)
	got429 := false
	for i := 0; i < 60; i++ {
		r := httptest.NewRequest("GET", "/admin/api/overview", nil)
		r.RemoteAddr = "198.51.100.7:5555"
		r.Header.Set("Authorization", "Bearer bad"+string(rune('a'+i%26)))
		r.Header.Set("X-Real-Ip", "2001:db8::"+string(rune('a'+i%26)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("60 bad tokens from one peer with rotating X-Real-Ip never reached the limiter")
	}
}

func TestOneIPv6PrefixSharesOneBudget(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	h := srv.Handler()
	captureLog(t)
	got429 := false
	for i := 0; i < 60; i++ {
		r := httptest.NewRequest("GET", "/admin/api/overview", nil)
		r.RemoteAddr = "127.0.0.1:5555"
		r.Header.Set("Authorization", "Bearer bad")
		r.Header.Set("X-Real-Ip", "2001:db8:0:1::"+string(rune('a'+i%26)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("addresses of one /64 each got a fresh guess budget")
	}
}

func TestTheAdminDatabaseIsOwnerOnlyUnderUmask022(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Audit("t", "x", "", "") // makes the -wal file exist
	for _, f := range []string{"admin.db", "admin.db-wal", "admin.db-shm"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %v", f, fi.Mode().Perm())
		}
	}
}
