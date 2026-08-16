package admin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// MonitorProxy relays a small whitelisted set of read-only endpoints from an official agent's monitor
// (the classic token-gated console every official agent ships) into the admin UI, so operators see the
// agent's own telemetry without a second login. The console token is injected server-side; it never
// reaches the browser.
//
// Auth model of the classic monitor (see anet-ai-srv monitor.go): POST /login with form token= sets a
// session cookie. The proxy logs in lazily and caches the cookie per agent, re-logging-in once on 401/
// 403/redirect-to-login.
type MonitorProxy struct {
	token string
	hc    *http.Client

	mu      sync.Mutex
	cookies map[string]string // manifest id → session cookie ("name=value")
}

// monitorPathWhitelist is the closed set of proxyable monitor paths (v2 adds stats/models/acl).
var monitorPathWhitelist = map[string]string{
	"state":   "/api/state",
	"catalog": "/api/catalog",
	"stats":   "/api/stats",
	"models":  "/api/models",
	"acl":     "/api/acl",
}

// FetchRaw proxies a whitelisted GET and returns the body (see Fetch).
func (p *MonitorProxy) FetchRaw(ctx context.Context, m *Manifest, what string) ([]byte, error) {
	return p.Fetch(ctx, m, what)
}

// PostACL forwards an ACL mutation (grant/revoke/mode) to the agent's monitor POST /api/acl.
func (p *MonitorProxy) PostACL(ctx context.Context, m *Manifest, body []byte) ([]byte, error) {
	if m.Monitor.URL == "" {
		return nil, fmt.Errorf("admin: manifest %s declares no monitor", m.ID)
	}
	p.mu.Lock()
	cookie := p.cookies[m.ID]
	p.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if cookie == "" {
			var err error
			cookie, err = p.login(ctx, m)
			if err != nil {
				return nil, err
			}
			p.mu.Lock()
			p.cookies[m.ID] = cookie
			p.mu.Unlock()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimRight(m.Monitor.URL, "/")+"/api/acl", bytesReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", cookie)
		resp, err := p.hc.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			cookie = ""
			p.mu.Lock()
			delete(p.cookies, m.ID)
			p.mu.Unlock()
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("monitor acl: http %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	}
	return nil, fmt.Errorf("monitor acl: authentication failed")
}

// NewMonitorProxy returns a proxy using token for monitor logins.
func NewMonitorProxy(token string) *MonitorProxy {
	return &MonitorProxy{
		token: token,
		hc: &http.Client{
			Timeout: 15 * time.Second,
			// The monitor redirects unauthenticated requests to /login — catching the redirect (rather
			// than following it) is how the proxy detects an expired session.
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
		cookies: map[string]string{},
	}
}

func (p *MonitorProxy) login(ctx context.Context, m *Manifest) (string, error) {
	form := url.Values{"token": {p.token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(m.Monitor.URL, "/")+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Value != "" {
			return c.Name + "=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("monitor login rejected (http %d)", resp.StatusCode)
}

func (p *MonitorProxy) get(ctx context.Context, m *Manifest, path, cookie string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(m.Monitor.URL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	return p.hc.Do(req)
}

// Fetch returns the JSON body of one whitelisted monitor endpoint ("state" | "catalog") for m.
func (p *MonitorProxy) Fetch(ctx context.Context, m *Manifest, what string) ([]byte, error) {
	path, ok := monitorPathWhitelist[what]
	if !ok {
		return nil, fmt.Errorf("admin: monitor endpoint %q not proxyable", what)
	}
	if m.Monitor.URL == "" {
		return nil, fmt.Errorf("admin: manifest %s declares no monitor", m.ID)
	}
	p.mu.Lock()
	cookie := p.cookies[m.ID]
	p.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if cookie == "" {
			var err error
			cookie, err = p.login(ctx, m)
			if err != nil {
				return nil, err
			}
			p.mu.Lock()
			p.cookies[m.ID] = cookie
			p.mu.Unlock()
		}
		resp, err := p.get(ctx, m, path, cookie)
		if err != nil {
			return nil, err
		}
		// A dead session comes back as a redirect to /login (or an auth status) — drop the cookie and
		// retry once with a fresh login.
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther ||
			resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			cookie = ""
			p.mu.Lock()
			delete(p.cookies, m.ID)
			p.mu.Unlock()
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("monitor %s: http %d", path, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}
	return nil, fmt.Errorf("monitor %s: authentication failed", path)
}
