package aghub

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// This hub's public base URL.
//
// A hub behind a reverse proxy cannot reliably tell from a request where
// the world reaches it: the Host header and X-Forwarded-Proto are what the
// proxy chose to pass on. Where the hub states its own address — homeHub in
// the A2A registry (§10.5), the URL in llms.txt, where its KEL is served —
// the operator can therefore configure it (anet-hub -public-url). Without
// the setting the request's origin is used, as before.

// SetPublicURL sets this hub's public base URL: an absolute http(s) URL
// without query or fragment; a trailing slash is dropped. Empty clears it.
// Call it before serving.
func (s *Server) SetPublicURL(raw string) error {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		s.publicURL = ""
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("public URL %q is not an absolute http(s) URL without credentials, query or fragment", raw)
	}
	s.publicURL = raw
	return nil
}

// PublicURL is the configured public base URL, or empty.
func (s *Server) PublicURL() string { return s.publicURL }

// origin is this hub's base URL as stated to a client of r: the configured
// public URL, else the origin r arrived at.
func (s *Server) origin(r *http.Request) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	return requestOrigin(r)
}
