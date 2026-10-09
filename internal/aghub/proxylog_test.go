package aghub_test

// [redteam:F3] Regression for the si2 red-team PoC
// TestRedteamSI2_ProxyAccessLogKeepsWhoTalksToWhom (A2A-DESIGN X1, §21
// item 1). The shipped reverse-proxy configuration kept nginx's default
// combined access log, and a daemon looked up its recipient's key set with
// an unauthenticated GET /agents/{recipient}/keys from its own address, so
// after the relay row was acked and securely deleted the hub host's access
// log alone still gave the edge sender -> recipient, with times and sizes.
//
// Two changes, each checked here: the shipped vhosts keep no access log
// (and an error log at crit only), and a daemon finds its recipient in a
// directory bucket (POST /directory:bucket, sealed-sender §2.9), which names
// neither the recipient nor its directory hash, only a prefix of a few bits
// that many agents share, so even a proxy that an operator runs with the
// default log records no such edge from the lookup.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// nginxBlocks returns the body of every `<name> {` block of an nginx
// configuration, comments removed. Nested blocks are part of the body.
func nginxBlocks(t *testing.T, conf, name string) []string {
	t.Helper()
	var out []string
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*\{`)
	for _, loc := range re.FindAllStringIndex(conf, -1) {
		depth, i := 0, loc[1]-1
		for ; i < len(conf); i++ {
			if conf[i] == '{' {
				depth++
			} else if conf[i] == '}' {
				if depth--; depth == 0 {
					break
				}
			}
		}
		if i == len(conf) {
			t.Fatalf("unbalanced %s block", name)
		}
		out = append(out, conf[loc[1]:i])
	}
	return out
}

// topLevel removes the nested blocks of a block body, leaving the
// directives that apply to the block itself.
func topLevel(body string) string {
	var b strings.Builder
	depth := 0
	for _, r := range body {
		switch {
		case r == '{':
			depth++
		case r == '}':
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// The shipped vhosts keep no access log anywhere, and in every server
// block an error log at crit or above, which holds no request lines.
func TestTheShippedProxyKeepsNoLogOfWhoTalksToWhom(t *testing.T) {
	stripComments := regexp.MustCompile(`(?m)#.*$`)
	accessLog := regexp.MustCompile(`(?m)^\s*access_log\s+([^;]*);`)
	errorLog := regexp.MustCompile(`(?m)^\s*error_log\s+(\S+)\s+(\w+)\s*;`)
	for _, f := range []string{"nginx-hub.conf", "nginx-hub.conf.example"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", f))
		if err != nil {
			t.Fatal(err)
		}
		conf := stripComments.ReplaceAllString(string(b), "")
		for _, m := range accessLog.FindAllStringSubmatch(conf, -1) {
			if strings.TrimSpace(m[1]) != "off" {
				t.Errorf("%s: access_log %s; request lines name agents and come with the client address", f, m[1])
			}
		}
		if strings.Contains(conf, "log_format") {
			t.Errorf("%s: defines a log_format; this vhost keeps no access log", f)
		}
		servers := nginxBlocks(t, conf, "server")
		if len(servers) == 0 {
			t.Fatalf("%s: no server block", f)
		}
		for i, srv := range servers {
			top := topLevel(srv)
			if !regexp.MustCompile(`(?m)^\s*access_log\s+off\s*;`).MatchString(top) {
				t.Errorf("%s: server block %d does not turn the access log off; it would inherit nginx.conf's", f, i)
			}
			m := errorLog.FindStringSubmatch(top)
			if m == nil {
				t.Errorf("%s: server block %d sets no error_log; the default level (error) logs client addresses with request lines", f, i)
				continue
			}
			if lvl := m[2]; lvl != "crit" && lvl != "alert" && lvl != "emerg" {
				t.Errorf("%s: server block %d logs errors at %s; below crit a line carries the request line", f, i, lvl)
			}
		}
		if !regexp.MustCompile(`(?s)location\s+/\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1`).MatchString(conf) {
			t.Errorf("%s does not proxy / to the hub", f)
		}
	}
}

// combinedLog is what nginx writes with its default combined format:
//
//	'$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'
//
// $remote_addr is the client address, which the proxy forwards to the hub
// as X-Real-IP. It stands for an operator's own proxy that logs.
type combinedLog struct {
	mu    sync.Mutex
	lines []string
}

type countingWriter struct {
	http.ResponseWriter
	status int
	n      int
}

func (w *countingWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *countingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.n += n
	return n, err
}

func (l *combinedLog) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &countingWriter{ResponseWriter: w}
		next.ServeHTTP(cw, r)
		line := fmt.Sprintf(`%s - - [%s] "%s %s %s" %d %d "-" "%s"`,
			r.Header.Get("X-Real-IP"), time.Now().Format("02/Jan/2006:15:04:05 -0700"),
			r.Method, r.URL.RequestURI(), r.Proto, cw.status, cw.n, r.UserAgent())
		l.mu.Lock()
		l.lines = append(l.lines, line)
		l.mu.Unlock()
	})
}

// A sender that looks its recipient up the way a daemon now does leaves no
// request line, and no request body, naming the recipient or its directory
// hash, even behind a proxy that logs every line: it asks for the bucket of
// a short prefix of the hash and opens the recipient's entry itself.
func TestABucketLookupDoesNotNameTheRecipient(t *testing.T) {
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := aghub.HubIdentityForTest(t)
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	var acc combinedLog
	var bodies [][]byte
	var mu sync.Mutex
	srv := httptest.NewServer(acc.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(b))
		s.Handler().ServeHTTP(w, r)
	})))
	t.Cleanup(func() { srv.Close(); store.Close() })
	testHubAID.Store(srv.URL, id.AID)
	testHubStores.Store(srv.URL, store)

	alice, bob := twoAgents(t)
	const ipAlice, ipBob = "203.0.113.10", "198.51.100.20"
	for _, p := range []struct {
		c  *identity.Controller
		ip string
	}{{alice, ipAlice}, {bob, ipBob}} {
		if _, err := store.Admit(p.c.AID(), 0, "", false); err != nil {
			t.Fatal(err)
		}
		req := signedRequest(t, srv, p.c, relayauth.ActionRegister, http.MethodPost, "/register", registerBody(t, p.c, "n", nil))
		req.Header.Set("X-Real-IP", p.ip)
		if code, b, _ := send(t, req); code != 200 {
			t.Fatalf("register: %d %s", code, b)
		}
		raw, _ := mintKeySet(t, p.c, uint64(time.Now().UnixMilli()))
		req = signedRequest(t, srv, p.c, relayauth.ActionKeys, http.MethodPost,
			"/agents/"+p.c.AID()+"/keys", map[string]any{"keys": base64.RawURLEncoding.EncodeToString(raw), "prev_seq": 0})
		req.Header.Set("X-Real-IP", p.ip)
		if code, b, _ := send(t, req); code != 200 {
			t.Fatalf("publish keys: %d %s", code, b)
		}
	}
	mu.Lock()
	bodies = nil
	mu.Unlock()

	// Alice looks Bob up as a daemon does now.
	entry := lookUpInBucket(t, srv, bob.AID(), ipAlice)
	if entry == nil {
		t.Fatal("Bob's entry is not in the bucket of his directory hash")
	}
	keys, _, _, _ := store.LocalKeys(bob.AID())
	if !bytes.Equal(entry.Keys, keys) {
		t.Fatal("the entry does not carry the key set Bob published")
	}

	h, _ := dirbox.Hash(bob.AID())
	acc.mu.Lock()
	lines := append([]string(nil), acc.lines...)
	acc.mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("nothing was logged")
	}
	for _, l := range lines {
		if strings.HasPrefix(l, ipAlice+" ") && (strings.Contains(l, bob.AID()) ||
			strings.Contains(l, base64.RawURLEncoding.EncodeToString(h))) {
			t.Errorf("a request line from the sender's address names the recipient: %s", l)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, b := range bodies {
		if bytes.Contains(b, []byte(bob.AID())) || bytes.Contains(b, []byte(base64.RawURLEncoding.EncodeToString(h))) ||
			bytes.Contains(b, []byte(base64.RawURLEncoding.EncodeToString(h[:8]))) {
			t.Errorf("a request body names the recipient or more than a short prefix of its hash: %s", b)
		}
	}
}
