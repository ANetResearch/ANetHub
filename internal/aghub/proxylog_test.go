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
// (and an error log at crit only), and the key lookup a daemon makes names
// the recipient in its body (POST /agents/keys:lookup), not in its request
// line, so even a proxy that an operator runs with the default log records
// no such edge from the lookup.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
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
// request line naming the recipient, even behind a proxy that logs every
// line: the lookup that used to give the edge sender -> recipient is
// POST /agents/keys:lookup with the AID in the body.
func TestAKeysLookupDoesNotNameTheRecipientInTheRequestLine(t *testing.T) {
	store, err := aghub.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.SetHubKey(id.Ctrl)
	s := aghub.NewServer(store)
	s.SetHubAID(id.AID)
	var acc combinedLog
	srv := httptest.NewServer(acc.wrap(s.Handler()))
	t.Cleanup(func() { srv.Close(); store.Close() })
	testHubAID.Store(srv.URL, id.AID)

	alice, bob := twoAgents(t)
	const ipAlice, ipBob = "203.0.113.10", "198.51.100.20"
	as := func(ip string, req *http.Request) (int, []byte) {
		req.Header.Set("X-Real-IP", ip)
		code, b, _ := send(t, req)
		return code, b
	}
	for _, p := range []struct {
		c  *identity.Controller
		ip string
	}{{alice, ipAlice}, {bob, ipBob}} {
		if code, b := as(p.ip, signedRequest(t, srv, p.c, relayauth.ActionRegister, http.MethodPost,
			"/register", registerBody(t, p.c, "n", nil))); code != 200 {
			t.Fatalf("register: %d %s", code, b)
		}
		raw, _ := mintKeySet(t, p.c, uint64(time.Now().UnixMilli()))
		if code, b := as(p.ip, signedRequest(t, srv, p.c, relayauth.ActionKeys, http.MethodPost,
			"/agents/"+p.c.AID()+"/keys", map[string]any{"keyset": base64.StdEncoding.EncodeToString(raw)})); code != 200 {
			t.Fatalf("publish keys: %d %s", code, b)
		}
	}

	// Alice looks Bob up as a daemon does now, then sends.
	lookup, _ := json.Marshal(aghub.KeysLookupRequest{AID: bob.AID()})
	req := newRequest(t, srv, http.MethodPost, aghub.KeysLookupPath, lookup)
	code, viaPost := as(ipAlice, req)
	if code != 200 {
		t.Fatalf("keys lookup: %d %s", code, viaPost)
	}
	env := testEnvelope(t, bob.AID(), bytes.Repeat([]byte{0xA5}, 3000))
	if code, b := as(ipAlice, signedRequest(t, srv, alice, relayauth.ActionSend, http.MethodPost, "/relay/send",
		map[string]any{"to_aid": bob.AID(), "envelope": base64.StdEncoding.EncodeToString(env)})); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	code, pb := as(ipBob, signedRequest(t, srv, bob, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}))
	if code != 200 || !bytes.Contains(pb, []byte(`"id":`)) {
		t.Fatalf("poll: %d %s", code, pb)
	}

	acc.mu.Lock()
	lines := append([]string(nil), acc.lines...)
	acc.mu.Unlock()
	for _, l := range lines {
		if strings.HasPrefix(l, ipAlice+" ") && strings.Contains(l, bob.AID()) {
			t.Errorf("a request line from the sender's address names the recipient: %s", l)
		}
	}

	// The lookup answers what GET /agents/{aid}/keys answers, which stays
	// for older daemons.
	code, viaGet := getJSON(t, srv.URL+"/agents/"+bob.AID()+"/keys")
	if code != 200 || !bytes.Equal(viaGet, viaPost) {
		t.Fatalf("GET keys: %d %s; the POST lookup answered %s", code, viaGet, viaPost)
	}
}

// The lookup route's refusals: an AID nobody holds is the handler's JSON
// 404 (what a daemon reads as "recipient unknown"), a body without an AID
// is 400, and a body larger than an AID needs is 413.
func TestTheKeysLookupRefusals(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	for _, tc := range []struct {
		name string
		body []byte
		code int
	}{
		{"unknown AID", []byte(`{"aid":"` + c.AID() + `"}`), http.StatusNotFound},
		{"no AID", []byte(`{}`), http.StatusBadRequest},
		{"not JSON", []byte(`aid=` + c.AID()), http.StatusBadRequest},
		{"oversized", []byte(`{"aid":"` + strings.Repeat("a", 8<<10) + `"}`), http.StatusRequestEntityTooLarge},
	} {
		code, b, _ := send(t, newRequest(t, srv, http.MethodPost, aghub.KeysLookupPath, tc.body))
		var out map[string]string
		if code != tc.code || json.Unmarshal(b, &out) != nil || out["error"] == "" {
			t.Errorf("%s: %d %s, want %d with a JSON error", tc.name, code, b, tc.code)
		}
	}
}
