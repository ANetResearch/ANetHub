package aghub

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The reverse proxy caps request bodies before the hub sees them, so its
// client_max_body_size is the limit that actually applies to a daemon
// sending a large envelope. It stood at 96m, the size of the largest
// envelope, while the hub accepts that envelope's base64 plus its JSON
// (about 128 MiB): envelopes above about 72 MiB were refused by nginx with
// an HTML 413 the daemon cannot read, near 64 MiB attachments after Padmé
// padding (05-hub H8). Nothing compared the two numbers, and the comment in
// the vhost named a constant that no longer existed.
//
// The production vhost must be at least the hub's own limit and, so that
// "in step" means something, less than a MiB above it. The reference vhost
// only has to be large enough.
func TestTheProxyBodyLimitMatchesTheHubs(t *testing.T) {
	want := DefaultLimits().sendBodyLimit()
	for _, c := range []struct {
		file  string
		exact bool
	}{
		{"nginx-hub.conf", true},
		{"nginx-hub.conf.example", false},
	} {
		got := proxyBodyLimit(t, filepath.Join("..", "..", "deploy", c.file))
		if got < want {
			t.Errorf("%s: client_max_body_size for location / is %d bytes, below the hub's "+
				"/relay/send limit of %d (Limits.sendBodyLimit)", c.file, got, want)
		}
		if c.exact && got-want >= 1<<20 {
			t.Errorf("%s: client_max_body_size is %d bytes, more than a MiB above the hub's %d; "+
				"keep it at the next whole MiB", c.file, got, want)
		}
	}
}

// proxyBodyLimit reads client_max_body_size inside the `location /` block
// that proxies to the hub, in bytes.
func proxyBodyLimit(t *testing.T, path string) int64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// The TLS server block's `location / {` that proxies; the port-80
	// block has a one-line `location /` that only redirects.
	i := strings.Index(s, "proxy_pass http://127.0.0.1:8088")
	if i < 0 {
		t.Fatalf("%s: no proxy_pass to the hub", path)
	}
	start := strings.LastIndex(s[:i], "location / {")
	end := strings.Index(s[i:], "\n    }")
	if start < 0 || end < 0 {
		t.Fatalf("%s: cannot find the proxying location / block", path)
	}
	block := s[start : i+end]
	m := regexp.MustCompile(`(?m)^\s*client_max_body_size\s+(\d+)([kKmMgG]?)\s*;`).FindStringSubmatch(block)
	if m == nil {
		t.Fatalf("%s: no client_max_body_size in the proxying location / block "+
			"(nginx's default of 1m would apply)", path)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	switch strings.ToLower(m[2]) {
	case "k":
		n <<= 10
	case "m":
		n <<= 20
	case "g":
		n <<= 30
	}
	return n
}
