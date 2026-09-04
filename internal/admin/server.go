package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetHub/internal/version"
)

// Server is the /admin HTTP surface. Everything is mounted under basePath (default "/admin"):
//
//	GET  /admin/               the operator SPA (token gate lives in the page)
//	GET  /admin/healthz        liveness (no auth)
//	POST /admin/api/login      token check (rate-limited) — the SPA then sends Bearer <token> on every call
//	...  /admin/api/*          the operator API (Bearer-guarded)
//
// The service binds loopback and sits behind nginx `location ^~ /admin`; the public hub binary and its
// routes are untouched.
type Server struct {
	store   *Store
	hub     *HubDB
	ops     *Ops
	mon     *MonitorProxy
	harvest *Harvester
	vec     *VecClient // v2: semantic capability discovery (nil/disabled → lexical fallback)
	token   string
	base    string

	authFails *authLimiter // failed credential checks per source IP (login AND Bearer)

	harvestMu sync.Mutex // one harvest at a time (ticker + manual button may race)

	delLimiter *destructiveLimiter // caps registry deletes so a scripted loop can't wipe it
}

// NewServer wires the admin surface.
func NewServer(store *Store, hub *HubDB, ops *Ops, mon *MonitorProxy, hv *Harvester, vec *VecClient, token, basePath string) *Server {
	if basePath == "" {
		basePath = "/admin"
	}
	return &Server{
		store: store, hub: hub, ops: ops, mon: mon, harvest: hv, vec: vec,
		token: token, base: strings.TrimRight(basePath, "/"),
		authFails: newAuthLimiter(authMaxFailures, authWindow),
		// At most 5 registry deletes per minute — a legitimate operator never bulk-deletes; a scripted
		// loop against the (weak-token, public) admin API is stopped before it can wipe the registry.
		delLimiter: newDestructiveLimiter(5, time.Minute),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// Handler returns the full /admin mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	b := s.base

	// healthz reports which build is answering, not only that one is.
	//
	// It returned {"status":"ok"} and nothing else, and this is a
	// SEPARATE binary from the hub — so a deploy that shipped anet-hub
	// and forgot anet-hub-admin left the operator surface running an old
	// build with nothing anywhere saying so. That is what happened: the
	// recovery endpoints were absent from production for a full release
	// while every check reported the surface healthy.
	//
	// The same shape as the webui that sat five deployments behind: a
	// component with no version on the wire cannot be seen to be stale.
	mux.HandleFunc("GET "+b+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":   "ok",
			"version":  version.V,
			"commit":   version.Commit,
			"built_at": version.BuiltAt,
		})
	})
	serveSPA := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(AdminHTML())
	}
	mux.HandleFunc("GET "+b, serveSPA)
	mux.HandleFunc("GET "+b+"/", serveSPA)
	mux.HandleFunc("POST "+b+"/api/login", s.hLogin)

	api := func(pattern string, h http.HandlerFunc) {
		mux.HandleFunc(pattern, s.auth(h))
	}
	api("GET "+b+"/api/overview", s.hOverview)
	api("GET "+b+"/api/agents", s.hAgents)
	api("GET "+b+"/api/agents/{aid}", s.hAgent)
	api("POST "+b+"/api/agents/{aid}/quota", s.hQuota)
	api("POST "+b+"/api/agents/{aid}/moderate", s.hModerate)
	api("DELETE "+b+"/api/agents/{aid}", s.hDeleteAgent)
	api("GET "+b+"/api/official", s.hOfficials)
	api("POST "+b+"/api/official", s.hPutOfficial)
	api("DELETE "+b+"/api/official/{id}", s.hDeleteOfficial)
	api("POST "+b+"/api/official/{id}/ops", s.hRunOp)
	api("GET "+b+"/api/official/{id}/monitor/{what}", s.hMonitor)
	api("GET "+b+"/api/official/{id}/insights", s.hInsights)
	api("POST "+b+"/api/official/{id}/acl", s.hOfficialACL)
	api("GET "+b+"/api/capabilities", s.hCapabilities)
	api("GET "+b+"/api/discover", s.hDiscover)
	api("GET "+b+"/api/vision", s.hVision)
	api("GET "+b+"/api/store", s.hStore)
	api("GET "+b+"/api/sessions", s.hSessions)
	api("GET "+b+"/api/sessions/{source}/{id}", s.hSession)
	api("POST "+b+"/api/harvest", s.hHarvest)
	api("GET "+b+"/api/reviews", s.hReviews)
	api("GET "+b+"/api/tasks", s.hTasks)
	api("GET "+b+"/api/audit", s.hAudit)
	// The other half of a reversible delete. Archiving without a way to
	// read the archive back made "any delete is reversible" true of the
	// bytes and false of the operator.
	api("GET "+b+"/api/deleted", s.hDeleted)
	api("POST "+b+"/api/deleted/{aid}/restore", s.hRestore)
	return mux
}

// --- auth ---

func remoteIP(r *http.Request) string {
	// Behind our own nginx only — trust X-Real-IP when present, else the socket peer.
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const (
	authWindow      = time.Minute
	authMaxFailures = 20
	throttleMsg     = "尝试过于频繁，请稍后再试"
)

// authLimiter counts FAILED credential checks per source IP in a rolling window.
//
// One budget covers both credential paths. /api/login was rate-limited and the
// Bearer check was not, so an attacker who simply never called /api/login could
// guess the token against any protected endpoint at full speed: the limit
// applied to the one path nobody is obliged to use. The token is the only thing
// guarding this surface, and the surface deletes agents, changes quotas and
// runs commands on other hosts over ssh.
//
// The cost is a map keyed by source IP. It grows only with IPs that fail, and
// entries are dropped as their window expires, so an operator who logs in
// successfully leaves nothing in it. A distributed guesser with many source
// addresses still gets one budget per address — this bounds a single client,
// not a botnet — and maxTrackedIPs bounds what that costs in memory.
type authLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	fails  map[string][]time.Time
	// noted marks IPs whose current over-budget episode has already been
	// recorded, so a sustained flood produces one log line and one audit row
	// instead of one per request. Cleared when the window empties.
	noted map[string]bool
}

func newAuthLimiter(max int, window time.Duration) *authLimiter {
	return &authLimiter{
		window: window, max: max,
		fails: map[string][]time.Time{}, noted: map[string]bool{},
	}
}

// prune drops attempts that fell out of the window and returns what remains.
// Caller holds mu.
func (l *authLimiter) prune(ip string, now time.Time) []time.Time {
	recent := l.fails[ip][:0]
	for _, t := range l.fails[ip] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(l.fails, ip)
		delete(l.noted, ip) // window elapsed: the next episode is reported again
		return nil
	}
	l.fails[ip] = recent
	return recent
}

// blocked reports whether ip has spent its failure budget. first is true only
// for the first blocked request of an episode.
func (l *authLimiter) blocked(ip string) (blocked, first bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.prune(ip, time.Now())) < l.max {
		return false, false
	}
	if l.noted[ip] {
		return true, false
	}
	l.noted[ip] = true
	return true, true
}

// maxTrackedIPs bounds how much memory a guesser with many source addresses can
// make this map take. Entries are otherwise only pruned when the same address
// is seen again, so addresses that fail once and never return are never
// collected.
const maxTrackedIPs = 10000

// sweep prunes every tracked address, and drops the table outright if that was
// not enough. Losing the counters resets the budget for everyone currently
// being tracked, which is worse than nothing and better than a map that grows
// without limit; an attacker able to reach this point holds ten thousand source
// addresses and is not being stopped by a per-address budget anyway. Caller
// holds mu.
func (l *authLimiter) sweep(now time.Time) {
	for ip := range l.fails {
		l.prune(ip, now)
	}
	if len(l.fails) >= maxTrackedIPs {
		l.fails = map[string][]time.Time{}
		l.noted = map[string]bool{}
	}
}

// record adds one failed credential check for ip. Successful requests are never
// recorded, so a working operator is never throttled.
func (l *authLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.fails) >= maxTrackedIPs {
		l.sweep(now)
	}
	l.fails[ip] = append(l.prune(ip, now), now)
}

// bearerToken extracts the credential from an Authorization header value.
//
// The header used to be parsed with strings.TrimPrefix(h, "Bearer "), which
// returns its input unchanged when the prefix is absent: a bare token with no
// scheme authenticated, while "bearer <tok>" was rejected. RFC 7235 §2.1 makes
// the scheme name case-insensitive and leaves the credential case-sensitive, so
// this accepts any capitalisation of "Bearer" and nothing without a scheme.
// ok is false for every other shape, an empty credential included.
func bearerToken(h string) (string, bool) {
	scheme, cred, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	cred = strings.TrimLeft(cred, " ") // RFC 7235 allows 1*SP before the credential
	if cred == "" {
		return "", false
	}
	return cred, true
}

// noteAuthDenial records one rejected credential check.
//
// The admin plane audited what operators did and nothing about who tried to get
// in: a failed login and a Bearer probe left no process log line and no
// audit_log row, so a credential-guessing run against this surface was
// invisible after the fact. Volume is bounded by authLimiter — past the failure
// budget only the first request of an episode is recorded, or the record of a
// flood becomes a second flood. The actor is "anonymous" because the request
// carried no valid credential; the source IP is the target so an operator can
// group by it.
func (s *Server) noteAuthDenial(r *http.Request, ip, action string) {
	log.Printf("admin: %s ip=%s method=%s path=%s", action, ip, r.Method, r.URL.Path)
	s.store.Audit("anonymous", action, ip, r.Method+" "+r.URL.Path)
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if blocked, first := s.authFails.blocked(ip); blocked {
		if first {
			s.noteAuthDenial(r, ip, "auth.throttled")
		}
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": throttleMsg})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.token)) != 1 {
		s.authFails.record(ip)
		s.noteAuthDenial(r, ip, "auth.failed")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token 不正确"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := remoteIP(r)
		tok, ok := bearerToken(r.Header.Get("Authorization"))
		// The throttle is checked only for requests that present a
		// credential — the same rule as counting them. Checked before this,
		// a blocked address got 429 for a request that never tried, which
		// is the same wrong answer arriving one step earlier: it slows no
		// attacker (guessing requires sending a token) and it makes an
		// address that once tripped the limiter unable to get an honest 401
		// for anything.
		//
		// Found by scripts/prodtest.sh: the run does a rate-limit check and
		// then asserts an unauthenticated call is refused with 401 — it saw
		// 429. The first fix stopped credential-less requests from
		// INCREMENTING the counter but left them subject to it, and the
		// unit test happened to run its credential-less loop before the
		// counter was tripped, so it could not tell the difference.
		if ok {
			if blocked, first := s.authFails.blocked(ip); blocked {
				if first {
					s.noteAuthDenial(r, ip, "auth.throttled")
				}
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": throttleMsg})
				return
			}
		}
		if !ok {
			// No credential at all. Refused and logged, but neither counted
			// as a guess nor blocked by the guess limiter: guessing the
			// token requires sending one, so neither counting nor throttling
			// these slows an attacker down. What it does do is put an IP
			// over the limit on traffic that never tried — a browser
			// opening the page, a health probe, a link somebody followed —
			// after which every honest request from that IP gets 429 and
			// the operator cannot tell "wrong token" from "throttled".
			//
			// Found by scripts/prodtest.sh, which asserts an
			// unauthenticated call is refused with 401: it saw 429,
			// because an earlier rate-limit check from the same address
			// had tripped the counter.
			s.noteAuthDenial(r, ip, "auth.missing")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			s.authFails.record(ip)
			s.noteAuthDenial(r, ip, "auth.failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

// --- handlers ---

func (s *Server) hOverview(w http.ResponseWriter, r *http.Request) {
	totals, err := s.hub.Totals()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	snaps, _ := s.store.Snapshots(288)
	states, _ := s.store.HarvestStates()
	counts, _ := s.store.SessionCounts()
	officials, _ := s.store.Officials()
	probes := make([]Probe, 0, len(officials))
	for _, m := range officials {
		probes = append(probes, s.ops.Probe(r.Context(), m, false))
	}
	audit, _ := s.store.AuditTail(10)
	writeJSON(w, http.StatusOK, map[string]any{
		"totals":       totals,
		"hub_db_bytes": s.hub.SizeBytes(),
		"snapshots":    snaps,
		"harvest":      states,
		"datasets":     counts,
		"officials":    len(officials),
		"probes":       probes,
		"audit":        audit,
	})
}

func (s *Server) hAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.hub.AllAgents(r.URL.Query().Get("q"))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	mods, _ := s.store.Moderations()
	officials, _ := s.store.Officials()
	officialByAID := map[string]*Manifest{}
	for _, m := range officials {
		if m.AID != "" {
			officialByAID[m.AID] = m
		}
	}
	type row struct {
		AdminAgentView
		Tier       string `json:"tier"`
		OfficialID string `json:"official_id,omitempty"`
		Moderation string `json:"moderation,omitempty"`
		ModNote    string `json:"moderation_note,omitempty"`
	}
	out := make([]row, 0, len(agents))
	for _, a := range agents {
		rw := row{AdminAgentView: a, Tier: "community"}
		if m, ok := officialByAID[a.AID]; ok {
			rw.Tier = "official"
			rw.OfficialID = m.ID
		}
		if md, ok := mods[a.AID]; ok && md.Status != "ok" {
			rw.Moderation = md.Status
			rw.ModNote = md.Note
		}
		out = append(out, rw)
	}
	if t := r.URL.Query().Get("tier"); t == "official" || t == "community" {
		filtered := out[:0]
		for _, rw := range out {
			if rw.Tier == t {
				filtered = append(filtered, rw)
			}
		}
		out = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": out})
}

func (s *Server) hAgent(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	agent, err := s.hub.Agent(aid)
	if err != nil {
		errJSON(w, http.StatusNotFound, err)
		return
	}
	reviews, _ := s.hub.RecentReviews(200)
	own := []HubReview{}
	for _, rv := range reviews {
		if rv.SubjectAID == aid || rv.ReviewerAID == aid {
			own = append(own, rv)
		}
	}
	sessions, _ := s.store.Sessions("", aid, 50)
	mods, _ := s.store.Moderations()
	var mod *Moderation
	if m, ok := mods[aid]; ok {
		mod = &m
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent": agent, "reviews": own, "sessions": sessions, "moderation": mod,
	})
}

func (s *Server) hQuota(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	var req struct {
		GuestQuota int `json:"guest_quota"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := s.hub.SetGuestQuota(aid, req.GuestQuota); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	s.store.Audit("admin", "agent.quota", aid, fmt.Sprintf("guest_quota=%d", req.GuestQuota))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) hModerate(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetModeration(aid, req.Status, req.Note); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	s.store.Audit("admin", "agent.moderate", aid, req.Status+" "+req.Note)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) hDeleteAgent(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	// Rate-limit destructive registry ops. A real operator never deletes in bursts; this stops a
	// scripted loop (like the 2026-07-20 incident) from wiping the registry.
	if !s.delLimiter.allow() {
		s.store.Audit("admin", "agent.delete.throttled", aid, "destructive-op rate limit hit")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "删除过于频繁，已限流（防批量误删/攻击）。稍后重试。"})
		return
	}
	// Archive the full row (incl. kel) BEFORE deleting, so any delete is reversible.
	if rowJSON, err := s.hub.FullAgentRow(aid); err == nil {
		_ = s.store.ArchiveDeletedAgent(aid, rowJSON, "admin")
	}
	if err := s.hub.DeleteAgent(aid); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	// Record the intent — deletion alone is not enforcement (the agent may re-register).
	_ = s.store.SetModeration(aid, "delisted", "removed from registry by operator")
	s.store.Audit("admin", "agent.delete", aid, "archived for restore")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) hOfficials(w http.ResponseWriter, r *http.Request) {
	officials, err := s.store.Officials()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	force := r.URL.Query().Get("probe") == "force"
	type row struct {
		Manifest *Manifest `json:"manifest"`
		Probe    Probe     `json:"probe"`
	}
	out := make([]row, 0, len(officials))
	for _, m := range officials {
		out = append(out, row{Manifest: m, Probe: s.ops.Probe(r.Context(), m, force)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"officials": out})
}

func (s *Server) hPutOfficial(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	m, err := ParseManifest(raw)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.PutOfficial(m); err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	s.store.Audit("admin", "official.put", m.ID, m.Name)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": m.ID})
}

func (s *Server) hDeleteOfficial(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// A DELETE of an id that was never registered answered 200 and wrote an
	// audit row indistinguishable from a real delete. An audit trail that
	// records events which did not happen cannot be used to establish what did,
	// so the row is written only when a manifest was actually removed. The
	// store reports that rather than a separate existence query, which would
	// leave a window between the check and the delete.
	found, err := s.store.DeleteOfficial(id)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	if !found {
		errJSON(w, http.StatusNotFound, fmt.Errorf("admin: official agent %q not found", id))
		return
	}
	s.store.Audit("admin", "official.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) hRunOp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := s.store.Official(id)
	if err != nil {
		errJSON(w, http.StatusNotFound, err)
		return
	}
	var req struct {
		Op  string `json:"op"`
		Arg string `json:"arg"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	res := s.ops.Run(r.Context(), m, req.Op, req.Arg)
	detail := res.Command
	if res.Err != "" {
		detail += " → " + res.Err
	}
	s.store.Audit("admin", "official.ops."+req.Op, id, detail)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) hMonitor(w http.ResponseWriter, r *http.Request) {
	id, what := r.PathValue("id"), r.PathValue("what")
	m, err := s.store.Official(id)
	if err != nil {
		errJSON(w, http.StatusNotFound, err)
		return
	}
	body, err := s.mon.Fetch(r.Context(), m, what)
	if err != nil {
		errJSON(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

// hStore is the Agent Store composition: agents grouped by product line, with tier + capability
// rollups. Payments are out of scope for v1 (pricing text is display-only, as in the public hub).
func (s *Server) hInsights(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.Official(r.PathValue("id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.buildInsights(ctx, m))
}

func (s *Server) hOfficialACL(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.Official(r.PathValue("id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		errJSON(w, http.StatusBadRequest, err)
		return
	}
	body, err := s.mon.PostACL(r.Context(), m, raw)
	if err != nil {
		errJSON(w, http.StatusBadGateway, err)
		return
	}
	s.store.Audit("admin", "official.acl", m.ID, string(raw))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) hCapabilities(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	caps := s.buildCapsules(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"capsules": caps, "count": len(caps)})
}

func (s *Server) hDiscover(w http.ResponseWriter, r *http.Request) {
	task := r.URL.Query().Get("task")
	if task == "" {
		errJSON(w, http.StatusBadRequest, fmt.Errorf("task required"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	caps := s.buildCapsules(ctx)
	matches, method := s.discoverSemantic(ctx, caps, task, 20)
	writeJSON(w, http.StatusOK, map[string]any{"task": task, "matches": matches, "method": method})
}

func (s *Server) hVision(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.buildVisionMap(ctx))
}

func (s *Server) hStore(w http.ResponseWriter, r *http.Request) {
	agents, err := s.hub.AllAgents("")
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	officials, _ := s.store.Officials()
	byAID := map[string]*Manifest{}
	lines := map[string][]any{}
	for _, m := range officials {
		byAID[m.AID] = m
	}
	capCount := map[string]int{}
	for _, a := range agents {
		if !a.Listed {
			continue
		}
		line := "community"
		tier := "community"
		var officialID string
		if m, ok := byAID[a.AID]; ok {
			line, tier, officialID = m.ProductLine, m.Tier, m.ID
		}
		lines[line] = append(lines[line], map[string]any{
			"aid": a.AID, "name": a.Name, "caps": a.Caps, "summary": a.Summary,
			"pricing": a.Pricing, "avg_rating": a.AvgRating, "review_count": a.ReviewCount,
			"tasks": a.TasksAsProvider, "tier": tier, "official_id": officialID,
		})
		for _, c := range a.Caps {
			capCount[c]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"product_lines": lines, "capabilities": capCount})
}

func (s *Server) hSessions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.store.Sessions(r.URL.Query().Get("source"), r.URL.Query().Get("q"), limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	counts, _ := s.store.SessionCounts()
	writeJSON(w, http.StatusOK, map[string]any{"sessions": rows, "counts": counts})
}

func (s *Server) hSession(w http.ResponseWriter, r *http.Request) {
	source, id := r.PathValue("source"), r.PathValue("id")
	row, err := s.store.GetSession(source, id)
	if err != nil {
		errJSON(w, http.StatusNotFound, fmt.Errorf("session not found"))
		return
	}
	card, _ := s.harvest.ReadSessionCard(source, id)
	events, _ := s.harvest.ReadSessionData(source, id, 500)
	writeJSON(w, http.StatusOK, map[string]any{"session": row, "card": card, "events": events})
}

func (s *Server) hHarvest(w http.ResponseWriter, r *http.Request) {
	s.harvestMu.Lock()
	defer s.harvestMu.Unlock()
	results := s.harvest.RunAll(r.Context())
	detail, _ := json.Marshal(results)
	s.store.Audit("admin", "harvest.run", "", string(detail))
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) hReviews(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.hub.RecentReviews(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": rows})
}

func (s *Server) hTasks(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.hub.RecentTasks(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": rows})
}

func (s *Server) hAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.store.AuditTail(limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": rows})
}

// --- background tickers ---

// StartTickers launches the snapshot + harvest loops (stopped via ctx).
func (s *Server) StartTickers(ctx context.Context, snapshotEvery, harvestEvery time.Duration) {
	if snapshotEvery > 0 {
		go func() {
			t := time.NewTicker(snapshotEvery)
			defer t.Stop()
			for {
				s.takeSnapshot()
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	if harvestEvery > 0 {
		go func() {
			t := time.NewTicker(harvestEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					s.harvestMu.Lock()
					results := s.harvest.RunAll(ctx)
					s.harvestMu.Unlock()
					for _, r := range results {
						if r.Err != "" {
							log.Printf("admin: harvest %s: %s", r.Source, r.Err)
						} else if r.Events > 0 {
							log.Printf("admin: harvest %s: +%d events (%d sessions)", r.Source, r.Events, r.Sessions)
						}
					}
				}
			}
		}()
	}
}

func (s *Server) takeSnapshot() {
	totals, err := s.hub.Totals()
	if err != nil {
		log.Printf("admin: snapshot: %v", err)
		return
	}
	_ = s.store.PutSnapshot(Snapshot{
		TS: nowRFC3339(), Agents: totals.Agents, Listed: totals.Listed,
		TasksCompleted: totals.TasksCompleted, Reviews: totals.Reviews, AvgRating: totals.AvgRating,
		RelayBacklog: totals.RelayBacklog, HubDBBytes: s.hub.SizeBytes(),
	})
}

// shippedDefaults are credentials this software once shipped with.
//
// The built-in default was removed and ADMIN_TOKEN made mandatory, which
// stops a NEW deployment being wide open. It does nothing for one already
// running: the value was copied into a systemd unit at install time and
// stays there, so the deployments most likely to be using it are the
// oldest ones. Found on the production hub, where the admin surface is
// reachable from the public internet and this list's first entry was
// still the live credential.
//
// Named rather than checked for entropy. A length rule would flag a
// strong short token and miss a long published one; what makes these
// unusable is that they are in a public repository, not that they are
// weak.
var shippedDefaults = []string{"anetpw2077", "admin", "changeme"}

// WeakToken reports whether a credential is one this software published,
// and is exported so a deployment check can ask without holding the
// operator's real token.
func WeakToken(tok string) bool {
	for _, d := range shippedDefaults {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(d)) == 1 {
			return true
		}
	}
	return false
}

// hDeleted lists agents an operator removed, newest first.
func (s *Server) hDeleted(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.DeletedAgents(100)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []DeletedAgent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": rows})
}

// hRestore puts one archived agent back.
//
// The most recent archive for that AID: an agent deleted twice has two
// rows, and the newer one is the state it was last in.
func (s *Server) hRestore(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	rows, err := s.store.DeletedAgents(500)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	for _, d := range rows {
		if d.AID != aid {
			continue
		}
		if err := s.hub.RestoreDeletedAgent(d.RowJSON); err != nil {
			errJSON(w, http.StatusBadRequest, err)
			return
		}
		s.store.Audit("admin", "agent.restore", aid, "from archive "+d.DeletedAt)
		// The delete recorded a moderation intent ("delisted"); restoring has to
		// clear it, or the agent comes back into the registry still shown as
		// removed by an operator.
		//
		// The reset was here from the start and never took effect: it passed an
		// empty status, SetModeration rejects any status outside
		// ok|flagged|delisted, and the returned error was discarded. A dropped
		// error is why a step that exists could be absent for three releases,
		// so this one is checked. The registry row is already back at this
		// point, which is why the failure is reported as a partial outcome
		// rather than as "restore failed" — the operator has to know both that
		// the agent returned and that its governance state did not.
		if err := s.store.SetModeration(aid, "ok", "restored by operator"); err != nil {
			s.store.Audit("admin", "agent.restore.moderation_failed", aid, err.Error())
			log.Printf("admin: restore %s: moderation not reset: %v", aid, err)
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":              "已恢复注册表记录，但监管状态未复位：" + err.Error(),
				"restored":           true,
				"moderation_cleared": false,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "archived_at": d.DeletedAt, "moderation": "ok"})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error": "no archived copy of " + aid})
}
