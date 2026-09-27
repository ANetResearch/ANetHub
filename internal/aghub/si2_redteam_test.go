package aghub_test

// Red-team PoCs for SI-2 / X1 (A2A-DESIGN §1, §2 X1, §3.7, §9; lens si2).
//
// Each test asserts that an attack SUCCEEDS: a passing test means the
// defect is present. They use the real hub handlers and store.

import (
	"bytes"
	"encoding/base64"
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

// combinedLog is what nginx writes for every request that passes through
// the shipped deploy/nginx-hub.conf: that file sets no access_log and no
// log_format, so nginx's built-in default applies,
//
//	access_log logs/access.log combined;
//	log_format combined '$remote_addr - $remote_user [$time_local] '
//	                    '"$request" $status $body_bytes_sent '
//	                    '"$http_referer" "$http_user_agent"';
//
// $remote_addr is the client address, which the proxy forwards to the hub
// as X-Real-IP (nginx-hub.conf: proxy_set_header X-Real-IP $remote_addr).
// The middleware below writes exactly those fields, and nothing the hub
// itself could not have been handed by the proxy.
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

// TestRedteamSI2_ProxyAccessLogKeepsWhoTalksToWhom: the shipped reverse
// proxy configuration logs every request line with the client address,
// and the daemon's send path makes an unauthenticated
// GET /agents/{recipient}/keys (internal/daemon/seal_send.go
// recipientKeys/fetchRecipientKeys, on first contact and every 10 minutes
// of an ongoing conversation). After the relay row is acked and securely
// deleted, the hub host's access log alone still yields the edge
// sender -> recipient, contrary to X1 ("日志只记收件方与字节数"; "删除的是
// 存储中的社交图") and docs/DATA-ASSETS.md ("通信元数据 … 不写入存储").
func TestRedteamSI2_ProxyAccessLogKeepsWhoTalksToWhom(t *testing.T) {
	// 1. The deployment files ship the default combined access log for
	//    the location that proxies every hub route.
	for _, f := range []string{"nginx-hub.conf", "nginx-hub.conf.example"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "deploy", f))
		if err != nil {
			t.Fatal(err)
		}
		conf := string(b)
		if regexp.MustCompile(`(?m)^\s*access_log\s+off\s*;`).MatchString(conf) {
			t.Fatalf("%s turns the access log off; the proxy does not record request lines", f)
		}
		if strings.Contains(conf, "log_format") {
			t.Fatalf("%s defines its own log_format; re-check what it records", f)
		}
		if !regexp.MustCompile(`(?s)location\s+/\s*\{[^}]*proxy_pass\s+http://127\.0\.0\.1`).MatchString(conf) {
			t.Fatalf("%s does not proxy / to the hub", f)
		}
	}

	// 2. A hub behind that proxy.
	dir := t.TempDir()
	store, err := aghub.Open(dir)
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
		req.Header.Set("X-Real-IP", ip) // what nginx sets from $remote_addr
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
		// Every daemon publishes its key set under its own AID
		// (hub_client.go publishKeys: at registration fallback and on
		// each weekly rotation, enckeys.go).
		raw, _ := mintKeySet(t, p.c, uint64(time.Now().UnixMilli()))
		if code, b := as(p.ip, signedRequest(t, srv, p.c, relayauth.ActionKeys, http.MethodPost,
			"/agents/"+p.c.AID()+"/keys", map[string]any{"keyset": base64.StdEncoding.EncodeToString(raw)})); code != 200 {
			t.Fatalf("publish keys: %d %s", code, b)
		}
	}

	// 3. Alice sends to Bob the way a daemon does: fetch Bob's key set
	//    (no authentication, Bob's AID in the path), then /relay/send.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/agents/"+bob.AID()+"/keys", nil)
	req.Header.Set("X-ANet-Wire", "2")
	if code, b := as(ipAlice, req); code != 200 {
		t.Fatalf("keys lookup: %d %s", code, b)
	}
	env := testEnvelope(t, bob.AID(), bytes.Repeat([]byte{0xA5}, 3000))
	if code, b := as(ipAlice, signedRequest(t, srv, alice, relayauth.ActionSend, http.MethodPost, "/relay/send",
		map[string]any{"to_aid": bob.AID(), "envelope": base64.StdEncoding.EncodeToString(env)})); code != 200 {
		t.Fatalf("send: %d %s", code, b)
	}
	// Bob collects and acks: the hub deletes the row (SI-2 holds for hub.db).
	code, pb := as(ipBob, signedRequest(t, srv, bob, relayauth.ActionPoll, http.MethodPost, "/relay/poll", map[string]any{}))
	if code != 200 || !bytes.Contains(pb, []byte(`"id":`)) {
		t.Fatalf("poll: %d %s", code, pb)
	}
	var ids []int64
	for _, m := range regexp.MustCompile(`"id":(\d+)`).FindAllSubmatch(pb, -1) {
		var n int64
		fmt.Sscan(string(m[1]), &n)
		ids = append(ids, n)
	}
	if code, b := as(ipBob, signedRequest(t, srv, bob, relayauth.ActionAck, http.MethodPost, "/relay/ack",
		map[string]any{"ids": ids})); code != 200 {
		t.Fatalf("ack: %d %s", code, b)
	}
	if n, _ := store.RelayPending(bob.AID()); n != 0 {
		t.Fatalf("relay row not deleted on ack")
	}

	// 4. Reconstruct the social graph from the access log only.
	acc.mu.Lock()
	lines := append([]string(nil), acc.lines...)
	acc.mu.Unlock()
	lineRE := regexp.MustCompile(`^(\S+) - - \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d+) (\d+)`)
	ipToAID := map[string]string{} // from POST /agents/{aid}/keys (a node publishes only its own)
	lookups := map[string][]string{}
	pollBytes := map[string]int{}
	sends := map[string]int{}
	for _, l := range lines {
		m := lineRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ip, method, uri := m[1], m[2], m[3]
		if k := regexp.MustCompile(`^/agents/([^/]+)/keys$`).FindStringSubmatch(uri); k != nil {
			switch method {
			case http.MethodPost:
				ipToAID[ip] = k[1]
			case http.MethodGet:
				lookups[ip] = append(lookups[ip], k[1])
			}
		}
		if method == http.MethodPost && uri == "/relay/send" {
			sends[ip]++
		}
		if method == http.MethodPost && uri == "/relay/poll" {
			var n int
			fmt.Sscan(m[5], &n)
			pollBytes[ip] += n
		}
	}
	edge := ""
	for ip, targets := range lookups {
		if sends[ip] == 0 {
			continue
		}
		for _, to := range targets {
			edge = ipToAID[ip] + " -> " + to
		}
	}
	want := alice.AID() + " -> " + bob.AID()
	if edge != want {
		t.Fatalf("could not rebuild the edge from the log (got %q); lines:\n%s", edge, strings.Join(lines, "\n"))
	}
	// The recipient's poll line also records the delivered size.
	if pollBytes[ipBob] < base64.StdEncoding.EncodedLen(len(env)) {
		t.Fatalf("poll response size %d does not reveal the %d-byte envelope", pollBytes[ipBob], len(env))
	}
	t.Logf("ATTACK OK: after ack, the proxy access log alone yields %s (sender IP %s, %d bytes delivered to %s)",
		edge, ipAlice, pollBytes[ipBob], ipBob)
}
