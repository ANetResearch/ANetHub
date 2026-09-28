package aghub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/seamerr"
	"github.com/ANetResearch/ANetHub/internal/version"
)

// Server is the Hub HTTP API over a Store.
type Server struct {
	store *Store
	// modules names the optional modules the application wired in; /stats
	// reports it. Set before serving (SetModules).
	modules []string
	// forwardUnknown, when set (by the application wiring, K207: kernel
	// never imports modules), offers an envelope for a locally-unknown
	// recipient to federation peers. Returns (accepted, peerHubAID, error).
	// Only the recipient and the envelope cross: the sender is not
	// forwarded (§3.9).
	forwardUnknown func(toAID string, envelope []byte) (bool, string, error)
	// fedKeys, when set, asks peer hubs for the key set of an AID not
	// registered here (/fed/v2/keys). Nil in a build without federation.
	fedKeys FederatedKeyLookup
	// limits are the §3.7 bounds; sendLimiter, registerLimiter and
	// keysLimiter are the token buckets they configure; replay is the
	// relayauth v2 replay cache.
	limits          Limits
	sendLimiter     *rateLimiter
	registerLimiter *rateLimiter
	keysLimiter     *rateLimiter
	replay          *replayCache
	// jwks caches the JWKS derived from each stored KEL (registry.go).
	jwks *jwksCache
	// federated, when set, answers discovery with agents learned from
	// peer hubs. Nil in a build without federation, which is how that
	// build says it has none.
	federated func(capFilter string) ([]AgentView, error)
	// hubAID names this hub's own ledger network (hub:<aid>). Two hubs
	// are two networks: a credit on one is not a credit on the other, and
	// settling somebody else's would mint money.
	hubAID string
	// peerKELs, when set, resolves a federation peer's verified key
	// history. Nil in a build without federation — which is also a build
	// with no peers, so nothing that needs it can happen.
	peerKELs func(aid string) ([]identity.SignedEvent, error)
	// peerEndpoints, when set, answers where a peer hub can be reached.
	peerEndpoints func(aid string) string
	// publicURL is this hub's configured public base URL (publicurl.go);
	// empty means the origin of each request.
	publicURL string
}

// SetPeerEndpointResolver installs the federation hook for "where does
// this peer live". Used to tell a reader where to go and check a witness
// attestation for themselves.
func (s *Server) SetPeerEndpointResolver(f func(aid string) string) {
	s.peerEndpoints = f
}

// peerEndpoint is where a peer hub can be reached, or empty.
func (s *Server) peerEndpoint(aid string) string {
	if s.peerEndpoints == nil {
		return ""
	}
	return s.peerEndpoints(aid)
}

// SetPeerKELResolver installs the federation hook for checking what a
// peer hub signed. Kept a seam rather than an import: the kernel does not
// know federation exists (K207).
func (s *Server) SetPeerKELResolver(f func(aid string) ([]identity.SignedEvent, error)) {
	s.peerKELs = f
}

// ownKEL marshals this hub's own key history.
func (s *Server) ownKEL() ([]byte, error) {
	c := s.store.hubKey
	if c == nil {
		return nil, fmt.Errorf("this hub holds no signing key")
	}
	return identity.MarshalKEL(c.KEL())
}

// peerKEL resolves a peer's key history, or explains why it cannot.
func (s *Server) peerKEL(aid string) ([]identity.SignedEvent, error) {
	if aid == "" {
		return nil, fmt.Errorf("name the peer hub")
	}
	if s.peerKELs == nil {
		return nil, fmt.Errorf("this hub federates with nobody, so it owes nobody and is owed by nobody")
	}
	return s.peerKELs(aid)
}

// SetHubAID names the ledger this facilitator settles on.
func (s *Server) SetHubAID(aid string) { s.hubAID = aid }

// SetForwarder installs the federation egress hook.
func (s *Server) SetForwarder(f func(toAID string, envelope []byte) (bool, string, error)) {
	s.forwardUnknown = f
}

// SetFederatedDirectory lets discovery answer with agents learned from
// peer hubs as well as those registered here.
//
// Injected rather than read directly, so this package keeps knowing
// nothing about federation: a hub built with -tags no_federation has no
// federated agents, and that is expressed by nobody calling this.
func (s *Server) SetFederatedDirectory(f func(capFilter string) ([]AgentView, error)) {
	s.federated = f
}

// SetModules records which optional modules the application wired in, for
// /stats. The kernel attaches no meaning to the names; a client uses them
// to decide what to show (the web UI hides the task board unless
// "taskboard" is listed). Call it before serving.
func (s *Server) SetModules(names []string) {
	s.modules = append([]string(nil), names...)
}

// NewServer wraps a store, with DefaultLimits.
func NewServer(store *Store) *Server {
	s := &Server{store: store, replay: newReplayCache(defaultReplayCacheMax, defaultReplayPerSigner),
		jwks: newJWKSCache(jwksCacheBytes, a2acard.JWKS)}
	if err := s.SetLimits(DefaultLimits()); err != nil {
		panic(err) // the defaults are constants and valid
	}
	return s
}

// SetLimits replaces the §3.7 limits. Call it before serving: it rebuilds
// the rate limiters, so buckets in use are reset.
func (s *Server) SetLimits(l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	s.limits = l
	s.sendLimiter = newRateLimiter(l.SendRate, l.SendBurst)
	s.registerLimiter = newRateLimiter(l.RegisterPerMinute/60, l.RegisterBurst)
	s.keysLimiter = newRateLimiter(l.KeysLookupPerMinute/60, l.KeysLookupBurst)
	s.replay.setPerSigner(replayPerSignerFor(l))
	s.store.SetRelayQuota(l.MailboxMessages, l.MailboxBytes)
	return nil
}

// Limits returns the limits in force.
func (s *Server) Limits() Limits { return s.limits }

// RunRelayJanitor deletes envelopes older than the undelivered TTL, once
// at start and then every interval, until ctx ends.
func (s *Server) RunRelayJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.store.PurgeExpiredRelay(s.limits.UndeliveredTTL, time.Now()); err != nil {
			log.Printf("hub: relay TTL purge: %v", err)
		} else if n > 0 {
			log.Printf("hub: relay TTL purge deleted %d undelivered envelope(s) older than %s",
				n, s.limits.UndeliveredTTL)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// limitBody caps every request body at the largest body any route
// accepts, which is a /relay/send carrying the largest envelope. Routes
// with smaller bodies apply their own, lower caps. Keep the reverse
// proxy's client_max_body_size (deploy/nginx-hub*.conf) at or above this
// value, or the proxy refuses envelopes the hub would accept.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.limits.sendBodyLimit())
		next.ServeHTTP(w, r)
	})
}

// C2 — the Hub wire contract's own version.
//
// The daemon, this hub and ANetLink each depend only on ANetCore, which is
// what keeps them from knowing about each other. That discipline is worth
// nothing if they silently disagree about which contract they are speaking:
// the three repos had drifted onto three different kernel versions at once
// and nothing on the wire could have told anybody. So both sides state the
// contract version they speak, on every request and every response.
//
// The daemon declares the same number in its own package. That duplication
// is the point — two programs that never import each other still have to
// agree, and a header is how they say so.
//
// Wire 2 (A2A-DESIGN §3.7, §18) is a breaking change: the relay carries
// only sealed envelopes and every signed endpoint uses relayauth v2
// headers. There is no fallback for wire-1 daemons.
const (
	wireVersion       = 2
	wireVersionHeader = "X-ANet-Wire"
)

// WireVersion is the Hub wire contract version this build speaks.
const WireVersion = wireVersion

// wireContract stamps this hub's contract version on every response,
// turns away a caller speaking a newer one, and turns away a /relay/*
// caller speaking an older one.
//
// A newer daemon is refused everywhere: it may send fields this hub will
// silently drop, and a delegation that half-arrives is worse than one that
// is plainly rejected.
//
// An older or absent version is refused on /relay/* with 426. A wire-1
// daemon would post plaintext payloads the relay no longer stores and poll
// for a response shape it cannot read; 426 with the required anet version
// states the reason at the first request. Other routes stay open to such
// callers: reads are unchanged, and the signed writes refuse a wire-1
// body at their own authentication step.
func wireContract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(wireVersionHeader, strconv.Itoa(wireVersion))
		v := r.Header.Get(wireVersionHeader)
		n, perr := strconv.Atoi(v)
		if v != "" && perr == nil && n > wireVersion {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf(
					"this hub speaks wire contract %d, the caller speaks %d — upgrade the hub",
					wireVersion, n),
			})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/relay/") && (v == "" || perr != nil || n < wireVersion) {
			sent := v
			if sent == "" {
				sent = "none"
			}
			writeJSON(w, http.StatusUpgradeRequired, map[string]any{
				"error": fmt.Sprintf(
					"this hub's relay speaks wire contract %d and requires anet >= 0.2.0 "+
						"(the request declared %s: %s); upgrade the node", wireVersion, wireVersionHeader, sent),
				"required_wire": wireVersion,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler builds the routed, CORS-enabled HTTP handler (the anetspace web is a browser origin).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// healthz reports which build is answering, not only that something
	// is. "Is the thing I deployed the thing that is running" is the
	// question that comes up, and a bare status cannot answer it.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]string{"status": "ok"}
		for k, v := range version.Full() {
			out[k] = v
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("POST /register", s.hRegister)
	mux.HandleFunc("POST /profile", s.hProfile)
	mux.HandleFunc("POST /reviews", s.hUploadReview)
	mux.HandleFunc("GET /agents", s.hAgents)
	mux.HandleFunc("GET /agents/{aid}", s.hAgent)
	mux.HandleFunc("GET /agents/{aid}/kel", s.hAgentKEL)
	mux.HandleFunc("POST "+KELLookupPath, s.hAgentKELLookup)
	mux.HandleFunc("GET /agents/{aid}/card", s.hAgentCard)
	// The JWKS named by the jku of an agent's A2A card, derived from its
	// KEL (A2A-DESIGN §10.3, §10.5). See registry.go.
	mux.HandleFunc("GET /agents/{aid}/jwks.json", s.hJWKS)
	mux.HandleFunc("GET /agents/{aid}/balance", s.hBalance)
	mux.HandleFunc("GET /agents/{aid}/ledger", s.hLedger)
	// Encryption key sets (§3.7). See keys.go.
	mux.HandleFunc("GET /agents/{aid}/keys", s.hKeysGet)
	mux.HandleFunc("POST "+KeysLookupPath, s.hKeysLookup)
	mux.HandleFunc("POST /agents/{aid}/keys", s.hKeysPost)
	mux.HandleFunc("POST /agents/{aid}/visibility", s.hVisibility)
	// The other half of registration: leaving. See deregister.go.
	mux.HandleFunc("POST /agents/{aid}/deregister", s.hDeregister)
	// The three endpoints x402 defines for a facilitator. This hub hosts
	// its own, which the spec permits outright — and for a ledger rail
	// there is nothing to separate from, because the balances are here.
	mux.HandleFunc("GET /x402/supported", s.hX402Supported)
	mux.HandleFunc("POST /agents/{aid}/p2p", s.hP2PPublish)
	mux.HandleFunc("GET /agents/{aid}/p2p", s.hP2PLookup)
	mux.HandleFunc("GET /p2p/peers", s.hP2PDirectory)
	// Credit going back out, and the arithmetic of what is outstanding.
	mux.HandleFunc("POST /x402/redeem", s.hRedeem)
	mux.HandleFunc("GET /x402/supply", s.hSupply)
	// The signed record of every supply change, and the witnesses who
	// have pinned it. See issuance.go and witness.go.
	mux.HandleFunc("GET /x402/issuance", s.hIssuance)
	mux.HandleFunc("GET /x402/issuance/head", s.hIssuanceHead)
	mux.HandleFunc("POST /x402/witness", s.hWitnessSubmit)
	mux.HandleFunc("GET /x402/witnesses", s.hWitnesses)
	mux.HandleFunc("GET /agents/{aid}/redemptions", s.hRedemptions)
	mux.HandleFunc("POST /federation/clear", s.hClear)
	// Reputation across hub boundaries — the signed evidence, never an
	// aggregate somebody else computed.
	//
	// The peer-facing review STREAM is deliberately absent here. It
	// belongs to the federation plane and is served at GET
	// /fed/v1/reviews by internal/federation, behind the discovery switch
	// and the no_federation tag. The kernel served the same stream at GET
	// /federation/reviews behind neither, so a hub built -tags
	// no_federation — an organisation's internal hub, which has opted out
	// of federation entirely — still published every signed review it
	// held to anyone who asked. Nothing called the kernel copy: peers
	// sync from /fed/v1/reviews, and no daemon, CLI, script or page in
	// these repositories names /federation/reviews.
	mux.HandleFunc("GET /agents/{aid}/reputation", s.hReputation)
	mux.HandleFunc("POST /x402/verify", s.hX402Verify)
	mux.HandleFunc("POST /x402/settle", s.hX402Settle)
	// The resource server: pay here, work there. See gateway.go for why
	// this hands back a voucher instead of proxying the call.
	mux.HandleFunc("GET /x402/resource/{aid}/{capability}", s.hX402Resource)
	// The A2A registry: verified A2A cards of agents registered here
	// (A2A-DESIGN §10.5). See registry.go.
	mux.HandleFunc("GET /a2a/v1/agents", s.hA2AAgents)
	mux.HandleFunc("GET /a2a/v1/agents/{aid}/card", s.hA2ACard)
	mux.HandleFunc("POST "+CardLookupPath, s.hA2ACardLookup)
	mux.HandleFunc("GET /graph", s.hGraph)
	mux.HandleFunc("GET /stats", s.hStats)
	// Relay (wire 2): sealed envelopes only. send is authenticated so the
	// hub can rate-limit per sender without storing who sent what; poll
	// and ack are authenticated so only the mailbox owner can read and
	// clear it. See relay.go.
	mux.HandleFunc("POST /relay/send", s.hRelaySend)
	mux.HandleFunc("POST /relay/poll", s.hRelayPoll)
	mux.HandleFunc("POST /relay/ack", s.hRelayAck)
	// There is no guest mode (A2A-DESIGN §9 row 访客模式). The hub used to
	// relay a browser visitor's messages under a hub-held identity, which
	// made it a plaintext endpoint of the conversation; /guest/* is not
	// routed and answers 404.
	//
	// Agent-facing onboarding manual (AgentHansa-style): one URL an LLM agent reads to learn how to drive
	// the local `anet` CLI. Injects THIS hub's origin so the copy-paste commands point at the right Hub.
	mux.HandleFunc("GET /llms.txt", s.hLLMs)
	// Researcher directory: a filtered lens over the SAME registry (agents carrying the reserved
	// `research` cap). This is what Research Galaxy publishes into — one ecosystem, one registry, a
	// research sub-view. See web/research.html (client-side fetch of /agents?cap=research).
	mux.HandleFunc("GET /research", s.hResearch)
	// The self-contained web UI (starfield of the real registry). It has no chat: there is no guest
	// mode, and delegating needs a local anet daemon. Other static assets fall through.
	fileSrv := http.FileServer(http.FS(webRoot()))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.hIndex(w, r)
			return
		}
		fileSrv.ServeHTTP(w, r)
	})
	return cors(wireContract(s.limitBody(mux)))
}

// hIndex serves the Hub SPA (a self-contained page built from webui/: the directory, agent profiles
// with their verified reviews, and the join guide).
func (s *Server) hIndex(w http.ResponseWriter, r *http.Request) {
	b, err := IndexHTML()
	if err != nil {
		http.Error(w, "index unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

// hResearch serves the researcher directory (web/research.html): a category view of the registry showing
// only agents that advertise the reserved `research` capability. It is a lens over the same /agents data,
// not a separate registry.
func (s *Server) hResearch(w http.ResponseWriter, r *http.Request) {
	b, err := researchHTML()
	if err != nil {
		http.Error(w, "research directory unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

// hLLMs serves the agent-onboarding manual, injecting this Hub's own origin into {{HUB_URL}} so the
// copy-paste `anet hub-register <url>` / fetch commands target the exact Hub that answered the request
// (works unchanged for the official Hub and any self-hosted deployment behind a TLS reverse proxy).
func (s *Server) hLLMs(w http.ResponseWriter, r *http.Request) {
	b, err := llmsTxt()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := strings.ReplaceAll(string(b), "{{HUB_URL}}", s.origin(r))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(out))
}

// requestOrigin reconstructs the scheme://host the client used to reach this Hub, honoring a reverse
// proxy's X-Forwarded-Proto (TLS terminates at the proxy for a self-hosted deployment).
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

// hGraph returns the whole registry as a starfield: nodes (agents + aggregate rating) and edges (one
// per verified review, reviewer → subject). It is a single round-trip for the web UI.
// hStats returns the headline landing metrics (agents / published receipts / reviews / avg rating)
// and the optional modules this build wired in.
func (s *Server) hStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.store.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(s.modules) > 0 {
		st.Modules = append([]string(nil), s.modules...)
	}
	// The peer-learned count goes through the same hook and the same dedupe
	// hAgents uses, so the two endpoints cannot disagree about the directory
	// without the merge itself being wrong. Counting it from the store
	// instead would report agents the directory does not show whenever the
	// federation module has not installed that hook.
	local, lerr := s.store.ListAgents("")
	if lerr == nil {
		seen := make(map[string]bool, len(local))
		for _, a := range local {
			seen[a.AID] = true
		}
		for _, a := range s.federatedAgents("") {
			if !seen[a.AID] && a.Listed && a.Browsable() {
				st.FederatedAgents++
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hGraph(w http.ResponseWriter, _ *http.Request) {
	agents, err := s.store.ListAgents("")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	edges, err := s.store.ReviewEdges()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if agents == nil {
		agents = []AgentView{}
	}
	if edges == nil {
		edges = []Edge{}
	}
	// Every AID an edge names must have a node.
	//
	// nodes came from the browsable listing and edges from every stored
	// review, and the two disagree by construction: an agent that left,
	// or went quiet for a month, drops out of the listing while its
	// reviews stay — because leaving removes routing and keeps evidence.
	// Production had one node and fifteen edges.
	//
	// The missing ones are added rather than the edges dropped. Dropping
	// them would make the graph consistent by hiding interactions that
	// really happened, which is the opposite of what this endpoint is
	// for: the directory answers "who can I reach now", the graph answers
	// "what has happened here".
	known := make(map[string]bool, len(agents))
	for _, a := range agents {
		known[a.AID] = true
	}
	for _, e := range edges {
		for _, aid := range []string{e.Source, e.Target} {
			if aid == "" || known[aid] {
				continue
			}
			known[aid] = true
			agents = append(agents, s.store.GraphNodeFor(aid))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": agents, "edges": edges,
		"note": "nodes with registered=false are agents this hub no longer routes for — " +
			"they left, or have not collected mail in a long time. Their reviews stay " +
			"because those record things that happened."})
}

// RegisterRequest is an agent's self-registration: its profile, its KEL
// (base64 CoreDet-CBOR), optionally its signed cards and its encryption
// key set.
//
// The request is authenticated with relayauth v2 headers, action
// "register", verified against the KEL in this body (the agent may not be
// stored yet). The X-ANet-AID header must equal aid. Proof of key
// possession is what stops a stranger who knows the public KEL from
// overwriting the registration.
type RegisterRequest struct {
	AID     string   `json:"aid"`
	Name    string   `json:"name"`
	Caps    []string `json:"caps"`
	Summary string   `json:"summary"`
	Readme  string   `json:"readme"`
	Pricing string   `json:"pricing"`
	KEL     string   `json:"kel"` // base64(identity.MarshalKEL)
	// Invite is an admission token, needed only when this hub requires
	// one AND does not already know this AID. Empty from a node that was
	// never given one, which is every node on a hub that admits openly.
	Invite string `json:"invite"`
	// Card is the agent's own signed statement of what it offers (an ADP
	// AgentCard). The authentication proves who is calling; only the card
	// makes Name and Caps attributable to the agent rather than to this
	// hub. Optional.
	Card json.RawMessage `json:"card"`
	// EncKeys is the agent's encryption key set: base64 (std) of the
	// seal.SignedEncKeySet encoding (§3.1). Optional. A set that does not
	// verify, or does not advance the stored one, is reported in
	// keys_status and does not fail the registration.
	EncKeys string `json:"enc_keys,omitempty"`
	// A2ACard is the agent's signed A2A AgentCard as a JSON object.
	// Optional. It is verified against KEL and the stored card's
	// params.seq, stored as the exact bytes received when admitted, and
	// reported in card_status; it does not fail the registration (see
	// a2acard.go).
	A2ACard json.RawMessage `json:"a2a_card,omitempty"`
}

// RegisterResponse is the /register answer. keys_status and card_status
// report the optional fields individually; keys_error and card_error
// explain a status other than ok, unchanged or absent.
type RegisterResponse struct {
	AID        string `json:"aid"`
	Status     string `json:"status"`
	KeysStatus string `json:"keys_status"`
	KeysError  string `json:"keys_error,omitempty"`
	CardStatus string `json:"card_status"`
	CardError  string `json:"card_error,omitempty"`
}

// maxRegisterBody caps a registration, separately from limitBody.
//
// The general ceiling is sized for relay envelopes, and registration
// inherited it: one unauthenticated POST could hand this hub a
// multi-megabyte body before anything examined its contents, which is the
// root of the capability-index amplification the constants in aghub.go
// bound. A registration carries a KEL, a signed card, profile text, a
// capability list, a key set and an A2A card (at most maxA2ACardBytes).
// The largest plausible one is maxCapsPerAgent ids of maxCapIDLen bytes
// listed twice — once in caps, once inside the signed card — at roughly
// 130 KiB, so 1 MiB admits it with room for a long readme. An agent whose
// registration does not fit is refused with 413 rather than truncated.
const maxRegisterBody = 1 << 20

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	// Per client IP, before anything else: an AID is one locally
	// generated key pair, so without this the per-sender send limit is
	// bypassed by registering a new sender (§2 X1, [C15f]).
	if ok, wait := s.registerLimiter.allow(clientIP(r)); !ok {
		w.Header().Set("Retry-After", retryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "too many registrations from this address; retry later"})
		return
	}
	auth, err := parseV2Headers(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	body, f := readRawBody(w, r, maxRegisterBody)
	if f != nil {
		if f.code == http.StatusRequestEntityTooLarge {
			writeJSON(w, f.code, map[string]string{
				"error": fmt.Sprintf("registration body exceeds %d bytes", maxRegisterBody)})
			return
		}
		writeJSON(w, f.code, map[string]string{"error": f.Error()})
		return
	}
	var req RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aid + kel required"})
		return
	}
	if req.AID == "" || req.KEL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aid + kel required"})
		return
	}
	if auth.AID != req.AID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": relayauth.HeaderAID + " does not match the aid being registered"})
		return
	}
	// The declared capability set is checked before the signature work:
	// it is the cheapest check, it needs nothing but the request itself,
	// and an oversized registration is the case worth rejecting cheaply.
	if err := validateCaps(req.Caps); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	kelBytes, err := base64.StdEncoding.DecodeString(req.KEL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kel not base64"})
		return
	}
	// The same caps every sender applies to a KEL it is handed
	// (seal.MaxKELEvents, seal.MaxKELBytes). A KEL is replayed, one
	// Ed25519 verification per event, wherever it is checked: here, on
	// each signed request of this agent, and for readers of its JWKS. The
	// hub had no bound but the 1 MiB body, so one registration of a long
	// KEL made every unauthenticated read of it cost hundreds of
	// milliseconds of this hub's CPU [redteam:F36]. No sender would accept
	// a longer KEL anyway, so the agent could not be written to.
	kel, err := seal.ParseKEL(kelBytes)
	if err != nil {
		if seal.ReasonOf(err) == seal.ReasonKELTooLarge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
				"kel too long (%v): this hub, like every sender, accepts at most %d events and %d bytes",
				err, seal.MaxKELEvents, seal.MaxKELBytes)})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kel undecodable"})
		return
	}
	derived, err := aidFromKEL(kel)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kel invalid: " + err.Error()})
		return
	}
	// The KEL must derive the claimed AID — a registration cannot claim an AID it does not control.
	if derived != req.AID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kel does not derive claimed aid"})
		return
	}
	// Proof of key possession, against the SUBMITTED KEL (the agent may
	// not be stored yet).
	if f := s.verifyV2(r, relayauth.ActionRegister, body, auth, kel); f != nil {
		writeAuthFailure(w, f, "register authentication invalid: ")
		return
	}
	// The KEL may only grow (§3.8). The registrant is the owner, so a
	// shorter KEL than the one stored is not a stale cache: it is either
	// an old copy being replayed or a rollback to before a rotation, and
	// a KEL that disagrees with the stored one on some event is a fork.
	// Accepting either would let whoever holds a superseded key take the
	// registration back to the state that key controls.
	if stored, err := s.store.KnownKEL(req.AID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if stored != nil {
		if err := identity.ExtendsKEL(stored, kel); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error": "the submitted KEL does not extend the one this hub holds: " + err.Error()})
			return
		}
	}
	// Admission, after the signature and before anything is written.
	//
	// The order matters in both directions. After the challenge, because
	// an invite spent by somebody who cannot prove they hold the key
	// would be an invite burned by an attacker. Before the writes,
	// because an agent that got a row and then failed admission is an
	// agent this hub admitted.
	//
	// Only an AID this hub does not already know is gated — see
	// invite.go for why re-registration is not.
	firstTime := !s.store.KnowsAgent(req.AID)
	if firstTime && s.store.InviteRequired() {
		if err := s.store.RedeemInvite(req.Invite, req.AID); err != nil {
			// A refusal is logged so an operator running a closed hub can
			// see that someone was turned away. /register is rate-limited
			// per client IP (Limits.RegisterPerMinute), which bounds how
			// fast one address can append to this log.
			log.Printf("hub: registration refused for %s: %v", req.AID, err)
			// The use is consumed before the agent row is written, so a
			// failure between here and PutAgent burns a use rather than
			// admitting an agent nobody can account for. An operator can
			// mint another invite; they cannot un-admit quietly.
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": err.Error(),
				"hint":  "ask this hub's operator for an invite, then register with --token",
			})
			return
		}
	}
	// The card, if one came, before the row it speaks for — so a
	// registration whose card is a forgery does not first take effect and
	// then get rejected.
	if len(req.Card) > 0 {
		if err := s.store.AdmitCard(req.AID, req.Card, kel); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	// RegisterAgent repeats the KEL extension check inside the write
	// transaction, for a concurrent registration of the same AID that
	// wrote between the check above and this write.
	if err := s.store.RegisterAgent(req.AID, req.Name, req.Caps, kelBytes, kel); err != nil {
		if errors.Is(err, ErrKELNotExtended) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Optional profile carried on the registration (usually set later via /profile).
	if req.Summary != "" || req.Readme != "" || req.Pricing != "" {
		if err := s.store.PutProfile(req.AID, req.Summary, req.Readme, req.Pricing); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	out := RegisterResponse{AID: req.AID, Status: "registered",
		KeysStatus: KeysStatusAbsent, CardStatus: CardStatusAbsent}
	// The key set and the A2A card are reported per field, after the
	// registration is written: a node whose key set is stale or malformed
	// is still registered and can publish a corrected set with POST
	// /agents/{aid}/keys, instead of being unable to register at all.
	if req.EncKeys != "" {
		raw, derr := base64.StdEncoding.DecodeString(req.EncKeys)
		if derr != nil {
			out.KeysStatus, out.KeysError = KeysStatusInvalid, "enc_keys not base64"
		} else {
			out.KeysStatus, out.KeysError = keysStatusOf(s.store.PublishKeys(req.AID, raw, kel, time.Now()))
		}
	}
	// Also when the field is absent: the stored card is re-verified
	// against the KEL just registered, which may have rotated away from
	// the key that signed it.
	out.CardStatus, out.CardError = s.store.RegisterA2ACard(req.AID, req.A2ACard, kel, time.Now())
	if out.CardStatus == CardStatusOK {
		logCardHome(req.AID, req.A2ACard, s.origin(r))
	}
	if firstTime {
		// A grant on arrival, so a new node can try a paid capability
		// before anyone has funded it. A network where nothing works
		// until an operator notices you is a network nobody evaluates.
		if err := s.store.GrantOnRegistration(req.AID); err != nil {
			log.Printf("hub: registration grant for %s: %v", req.AID, err)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ProfileRequest updates an agent's self-authored profile. The request is
// authenticated with relayauth v2 headers, action "profile", verified
// against the agent's REGISTERED KEL. aid is optional; when present it must
// equal the X-ANet-AID header.
type ProfileRequest struct {
	AID     string `json:"aid,omitempty"`
	Summary string `json:"summary"`
	Readme  string `json:"readme"`
	Pricing string `json:"pricing"`
}

func (s *Server) hProfile(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionProfile, signedBodyLimit)
	if !ok {
		return
	}
	var req ProfileRequest
	if err := json.Unmarshal(a.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if req.AID != "" && req.AID != a.AID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "aid does not match " + relayauth.HeaderAID})
		return
	}
	if err := s.store.PutProfile(a.AID, req.Summary, req.Readme, req.Pricing); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": a.AID, "status": "profile_updated"})
}

// UploadReviewRequest carries the provider-signed receipt and the requester-signed review, both base64
// CoreDet-CBOR, and nothing else.
//
// Earlier versions also required request_doc and deliverable, the raw interaction content, so the hub
// could re-hash it against the receipt and publish the goal and the deliverable with the review. The
// hub no longer receives content (A2A-DESIGN §0 decision 2, §9 row 评价): it verifies the interlock
// without it and reports the content binding as UNVERIFIED.
type UploadReviewRequest struct {
	Receipt string `json:"receipt"` // base64(evidence.Receipt.Marshal)
	Review  string `json:"review"`  // base64(evidence.Review.Marshal)
}

// maxReviewUploadBody bounds a review upload: two signed objects, each well under 16 KiB.
const maxReviewUploadBody = 64 << 10

func (s *Server) hUploadReview(w http.ResponseWriter, r *http.Request) {
	// The body is decoded with the two retired content fields in view so
	// that a client still sending them is told so, rather than having the
	// fields dropped silently and its review stored as if it had not tried
	// to hand the hub content.
	var req struct {
		UploadReviewRequest
		RequestDoc  string `json:"request_doc"`
		Deliverable string `json:"deliverable"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReviewUploadBody)).Decode(&req); err != nil ||
		req.Receipt == "" || req.Review == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt + review required"})
		return
	}
	if req.RequestDoc != "" || req.Deliverable != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this hub does not accept " +
			"interaction content with a review: send receipt and review only (request_doc and " +
			"deliverable were removed; upgrade anet to >= 0.2.0)"})
		return
	}
	rcBytes, err1 := base64.StdEncoding.DecodeString(req.Receipt)
	rvBytes, err2 := base64.StdEncoding.DecodeString(req.Review)
	if err1 != nil || err2 != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt/review not base64"})
		return
	}
	rc, err := evidence.UnmarshalReceipt(rcBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt undecodable"})
		return
	}
	rv, err := evidence.UnmarshalReview(rvBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "review undecodable"})
		return
	}
	if err := checkReviewComment(rv.Comment); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	detail, err := s.verify(rc, rv)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.PutReview(rv, detail); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "store: " + err.Error()})
		return
	}
	// Keep the signed objects that were verified, not only what they
	// meant. A peer asking for this review later needs the objects to
	// check for itself; handing it our conclusion would make federated
	// reputation a chain of hubs trusting hubs.
	if err := s.store.PutReviewBlob(rv.InteractionID, rcBytes, rvBytes); err != nil {
		log.Printf("hub: review evidence not kept for %s: %v", rv.InteractionID, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interaction_id": rv.InteractionID, "status": "accepted",
		"content_binding": ContentBindingUnverified})
}

// verify is the heart of the trust model. Two halves, deliberately split:
// what only this Hub can know (has this interaction been rated, are these
// agents registered here) stays here; the interlock itself — same
// interaction, right parties, review anchored to this receipt, both
// signatures live — is evidence.VerifyInterlock, so a third party holding
// the same files reaches the same verdict without trusting this Hub.
//
// Content binding (does request_cid / result_cid hash to particular bytes)
// is not checked: the hub does not receive content, and VerifyInterlock is
// called with nil for both content arguments. Reviews are served with
// content_binding "UNVERIFIED" to say so.
//
// Any failure ⇒ the review is rejected and never displayed. On success it
// returns the receipt anchors to store beside the review.
func (s *Server) verify(rc *evidence.Receipt, rv *evidence.Review) (ReviewDetail, error) {
	var zero ReviewDetail

	// Uniqueness first: it is the cheapest check and the only one that is
	// this Hub's business rather than a fact about the objects.
	if s.store.HasInteraction(rv.InteractionID) {
		return zero, fmt.Errorf("interaction already reviewed")
	}

	// Registration is likewise policy, not arithmetic — this Hub rates
	// agents it knows. The KELs it holds are what the interlock is checked
	// against, so a stranger re-checking later uses the published KELs and
	// reaches the same verdict.
	// The reviewer must have an account here — this hub rates on behalf
	// of its own users and not on behalf of strangers.
	reqKELBytes, err := s.store.AgentKEL(rv.ReviewerAID)
	if err != nil {
		return zero, fmt.Errorf("reviewer not registered")
	}
	// The provider need only be SOMEBODY this hub can identify, here or
	// at a peer. Requiring it to be local meant a cross-hub interaction
	// could not be reviewed by either side: the reviewer banks here, the
	// provider banks there, and neither hub knew both. Federation was
	// producing work that nothing could rate.
	provKELBytes, err := s.store.AnyKEL(rc.ProviderAID)
	if err != nil {
		return zero, fmt.Errorf("provider unknown to this hub: %w", err)
	}
	provKEL, err := identity.UnmarshalKEL(provKELBytes)
	if err != nil {
		return zero, fmt.Errorf("provider kel corrupt")
	}
	reqKEL, err := identity.UnmarshalKEL(reqKELBytes)
	if err != nil {
		return zero, fmt.Errorf("reviewer kel corrupt")
	}

	// /reviews needs no authentication, so a bad signature on either
	// object is refused on the key its signer's KEL names, before the
	// interlock replays the two KELs (kelreplay.go) [redteam:F36].
	if verr := plausibleEnvelope(rc.Envelope, rc.ProviderAID, provKEL, rc.CanonicalPreimage); verr != nil {
		return zero, fmt.Errorf("evidence: receipt signature invalid: %w", verr)
	}
	if verr := plausibleEnvelope(rv.Envelope, rv.ReviewerAID, reqKEL, rv.CanonicalPreimage); verr != nil {
		return zero, fmt.Errorf("evidence: review signature invalid: %w", verr)
	}

	// Everything else is arithmetic over the objects, and it lives in
	// ANetCore so that anyone holding these files reaches this same
	// verdict without trusting this Hub — which is the whole content of
	// "the Hub cannot fake a rating".
	if err := evidence.VerifyInterlock(rc, rv, nil, nil, provKEL, reqKEL); err != nil {
		return zero, err
	}
	return ReviewDetail{
		RequestCID:  rc.RequestCID,
		ResultCID:   rc.ResultCID,
		CompletedAt: rc.CompletedAt,
	}, nil
}

func (s *Server) hAgents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	// ?cap= is answered from the capability index rather than by
	// post-filtering a prose search. Same parameter, same comma-OR
	// meaning, two things it can now do that it could not: match a
	// structured id exactly, and match a family by prefix.
	//
	// It does not fall back to the prose search when nothing matches.
	// "who serves cas.put" and "who mentions cas.put" are different
	// questions, and answering the second when asked the first sends work
	// to a provider that will refuse it.
	//
	// Presence of the parameter, not emptiness of its value, decides which
	// question was asked. Testing the trimmed value merged two of them: a
	// caller that built ?cap= from an empty variable, or sent whitespace,
	// was read as having asked for no filter at all and was handed the
	// whole directory — a plausible-looking answer to a question it did
	// not ask, with nothing in the response to distinguish it.
	if query.Has("cap") {
		capID := strings.TrimSpace(query.Get("cap"))
		if capID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "cap must name a capability id; omit the parameter to list every agent"})
			return
		}
		agents, err := s.store.FindByCapability(capID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Agents learned from peer hubs answer the same question, and
		// carry the home hub that says where to reach them. Local first:
		// an agent this hub can deliver to directly is a better answer
		// than one behind another hop.
		agents = mergeFederated(agents, s.federatedAgents(capID))
		if agents == nil {
			agents = []AgentView{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
		return
	}
	q := query.Get("q")
	agents, err := s.store.ListAgents(q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// The prose search and the unfiltered listing answer from peer hubs
	// too. Only ?cap= did, so an agent learned from a peer could be found
	// by an exact capability id and by nothing else: `anet find <text>`
	// missed it, and the starfield — which asks with no parameter at all —
	// never drew it. A hub that federates a directory and then shows it in
	// one of three views is reporting less than it knows.
	agents = mergeFederated(agents, federatedMatching(s.federatedAgents(""), q))
	if agents == nil {
		agents = []AgentView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// mergeFederated appends the peer-learned agents the local answer does
// not already name.
//
// Local first, and local wins a collision: an agent registered here is
// one hop away and its row carries liveness and ratings that a synced
// card does not. home_hub survives on the federated entries, because that
// field is what tells a caller where the work actually has to be sent.
func mergeFederated(local, fed []AgentView) []AgentView {
	if len(fed) == 0 {
		return local
	}
	seen := make(map[string]bool, len(local)+len(fed))
	for _, a := range local {
		seen[a.AID] = true
	}
	for _, a := range fed {
		if a.AID == "" || seen[a.AID] {
			continue
		}
		seen[a.AID] = true
		local = append(local, a)
	}
	return local
}

// federatedMatching applies to peer-learned agents the filter ListAgents
// applies locally.
//
// The federated directory seam filters by capability id only, so a text
// query has to be matched here, over what a synced card carries: AID,
// name and capability ids. Case-insensitively, matching the SQL LIKE the
// local half uses — a name search is prose, unlike a capability id (see
// FindByCapability, where the opposite rule applies and why). Unlisted
// entries are dropped for the reason ListAgents drops them: this is a
// listing somebody reads, not a routing table.
func federatedMatching(fed []AgentView, query string) []AgentView {
	q := strings.ToLower(query)
	var out []AgentView
	for _, a := range fed {
		if !a.Listed || !a.Browsable() {
			continue
		}
		if q != "" && !agentMentions(a, q) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// agentMentions reports whether an already-lowercased query occurs in the
// fields ListAgents searches: aid, name, caps, summary, readme.
func agentMentions(a AgentView, lowerQuery string) bool {
	for _, f := range append([]string{a.AID, a.Name, a.Summary, a.Readme}, a.Caps...) {
		if strings.Contains(strings.ToLower(f), lowerQuery) {
			return true
		}
	}
	return false
}

// --- relay handlers (wire 2) ---

// RelaySendRequest posts one sealed envelope into a recipient's mailbox.
// The sender is the X-ANet-AID of the request (relayauth v2, action
// "send") and is not part of the body: the hub uses it for rate limiting
// and does not store it (§2 X1).
type RelaySendRequest struct {
	ToAID    string `json:"to_aid"`
	Envelope string `json:"envelope"` // base64 (std) of the seal.SealedEnvelope encoding
}

// RelaySendResponse is the /relay/send answer for an envelope queued
// here. An envelope handed to a peer hub is answered with status
// "forwarded" and via_hub instead of an id.
type RelaySendResponse struct {
	ID             int64  `json:"id,omitempty"`
	Status         string `json:"status"`
	ViaHub         string `json:"via_hub,omitempty"`
	RecipientQuiet bool   `json:"recipient_quiet,omitempty"`
	Warning        string `json:"warning,omitempty"`
}

// RelayPollRequest is the /relay/poll body (relayauth v2, action "poll").
//
// AfterID is optional: only envelopes with an id above it are returned,
// still oldest first and under the same limit and byte budget. Absent or 0
// is the whole mailbox, as before the field existed.
type RelayPollRequest struct {
	Limit   int   `json:"limit,omitempty"`
	AfterID int64 `json:"after_id,omitempty"`
}

// RelayEnvelopeView is one mailbox entry on the wire.
type RelayEnvelopeView struct {
	ID       int64  `json:"id"`
	Envelope string `json:"envelope"` // base64 (std)
}

// RelayPollResponse is the /relay/poll answer.
type RelayPollResponse struct {
	Messages []RelayEnvelopeView `json:"messages"`
}

// RelayAckRequest is the /relay/ack body (relayauth v2, action "ack").
type RelayAckRequest struct {
	IDs []int64 `json:"ids"`
}

// RelayAckResponse is the /relay/ack answer: how many rows were deleted.
type RelayAckResponse struct {
	Acked int `json:"acked"`
}

// hRelaySend accepts a sealed envelope from an authenticated sender.
//
// Order: a non-consuming check of the sender's bucket, authentication
// (the signer must be registered here), the per-sender bucket, decoding,
// the envelope size, the structural check, then routing and the
// recipient's quota. The size cap on the raw body is
// applied while it is read, before the signature is checked, because the
// signature covers the body. Nothing about the sender is written: the
// row holds the recipient, the size, the time and the envelope.
func (s *Server) hRelaySend(w http.ResponseWriter, r *http.Request) {
	// A sender whose bucket is already empty is refused before its body
	// (up to the envelope limit) is read. The check takes no token, so
	// naming another agent in the header cannot drain that agent's bucket.
	if hdr, ok := singleHeader(r, relayauth.HeaderAID); ok {
		if empty, wait := s.sendLimiter.empty(hdr); empty {
			w.Header().Set("Retry-After", retryAfter(wait))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "send rate exceeded for this sender; retry later"})
			return
		}
	}
	a, ok := s.authRegistered(w, r, relayauth.ActionSend, s.limits.sendBodyLimit())
	if !ok {
		return
	}
	if ok, wait := s.sendLimiter.allow(a.AID); !ok {
		w.Header().Set("Retry-After", retryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "send rate exceeded for this sender; retry later"})
		return
	}
	var req RelaySendRequest
	if err := json.Unmarshal(a.Body, &req); err != nil || req.ToAID == "" || req.Envelope == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to_aid + envelope required"})
		return
	}
	// The raw body was capped at sendBodyLimit while it was read, which
	// bounds the decoded size to MaxEnvelope plus less than 48 KiB; the
	// exact limit is checked on the decoded bytes.
	envelope, err := base64.StdEncoding.DecodeString(req.Envelope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "envelope not base64"})
		return
	}
	if int64(len(envelope)) > s.limits.MaxEnvelope {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
			"error": fmt.Sprintf("envelope exceeds %d bytes", s.limits.MaxEnvelope)})
		return
	}
	if err := CheckEnvelope(req.ToAID, envelope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// The recipient must be a registered agent, so the relay only holds
	// mail for real mailboxes. A recipient unknown HERE may still live on
	// a federated peer (K208 delivery federation).
	if _, err := s.store.AgentKEL(req.ToAID); err != nil {
		if s.forwardUnknown != nil {
			ok, peer, ferr := s.forwardUnknown(req.ToAID, envelope)
			switch {
			case ok:
				writeJSON(w, http.StatusOK, RelaySendResponse{Status: "forwarded", ViaHub: peer})
				return
			case errors.Is(ferr, seamerr.ErrMailboxFull):
				writeJSON(w, http.StatusInsufficientStorage, map[string]string{
					"error": "recipient mailbox full at its hub: " + ferr.Error()})
				return
			case ferr != nil:
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "federation forward failed: " + ferr.Error()})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "recipient not registered"})
		return
	}
	// Queued either way — but if the recipient has not collected its mail
	// in a long time, the sender is told before it starts waiting. This
	// hub cannot know whether the agent is coming back, and refusing the
	// send would be asserting that it is not.
	live, _ := s.store.LivenessOf(req.ToAID)
	id, err := s.store.RelayEnqueue(req.ToAID, envelope)
	switch {
	case errors.Is(err, ErrMailboxFull):
		writeJSON(w, http.StatusInsufficientStorage, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, ErrBadEnvelope):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := RelaySendResponse{ID: id, Status: "queued"}
	if live.Quiet {
		out.RecipientQuiet = true
		out.Warning = fmt.Sprintf(
			"queued, but %s has not collected its mail for %s — it may not be running",
			req.ToAID, live.QuietFor)
	}
	writeJSON(w, http.StatusOK, out)
}

// hRelayPoll returns the caller's own mailbox, from after_id on when the
// request names one.
func (s *Server) hRelayPoll(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionPoll, signedBodyLimit)
	if !ok {
		return
	}
	var req RelayPollRequest
	if len(a.Body) > 0 {
		if err := json.Unmarshal(a.Body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
			return
		}
	}
	if req.AfterID < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "after_id must not be negative"})
		return
	}
	// Collecting mail is the liveness signal. Recorded here rather than
	// at a heartbeat endpoint because this is the thing that actually
	// matters: a node that asks for its mail is a node that will do the
	// work, and a node that has stopped asking will not, whatever else it
	// might still be answering.
	s.store.SeenPolling(a.AID)
	msgs, err := s.store.RelayPoll(a.AID, req.AfterID, req.Limit, s.limits.PollBudget)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := RelayPollResponse{Messages: make([]RelayEnvelopeView, 0, len(msgs))}
	for _, m := range msgs {
		out.Messages = append(out.Messages, RelayEnvelopeView{
			ID: m.ID, Envelope: base64.StdEncoding.EncodeToString(m.Payload)})
	}
	writeJSON(w, http.StatusOK, out)
}

// hRelayAck deletes envelopes the caller has processed.
func (s *Server) hRelayAck(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionAck, signedBodyLimit)
	if !ok {
		return
	}
	var req RelayAckRequest
	if err := json.Unmarshal(a.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	n, err := s.store.RelayAck(a.AID, req.IDs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, RelayAckResponse{Acked: n})
}

// VerifyAgentChallenge authenticates a wire-1 signed action challenge
// (relayauth.Preimage in a JSON body) from a REGISTERED agent.
//
// The hub's own endpoints use relayauth v2 headers since wire 2 (see
// auth2.go). This remains for the taskboard module, which authenticates
// its own requests through this seam and is outside the wire-2 change.
func (st *Store) VerifyAgentChallenge(action, aid string, ts, keyStateSeq uint64, sigB64 string) error {
	kelBytes, err := st.AgentKEL(aid)
	if err != nil {
		return fmt.Errorf("agent not registered")
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		return fmt.Errorf("kel corrupt")
	}
	return verifyChallenge(kel, action, aid, ts, keyStateSeq, sigB64)
}

// verifyChallenge checks a signed action challenge against a specific KEL, within the replay window. The
// caller signs relayauth.Preimage(action, aid, ts) with its current key; this rebuilds the identical
// bytes and verifies them, binding the signature to (action, aid) so it cannot be reused elsewhere.
func verifyChallenge(kel []identity.SignedEvent, action, aid string, ts, keyStateSeq uint64, sigB64 string) error {
	if aid == "" || sigB64 == "" {
		return fmt.Errorf("aid + sig required")
	}
	now := uint64(time.Now().UnixMilli())
	skew := int64(now) - int64(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > relayauth.MaxSkewMillis {
		return fmt.Errorf("stale or future-dated challenge")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("sig not base64")
	}
	pre := relayauth.Preimage(action, aid, ts)
	// A bad signature costs one verification, not a replay of the KEL
	// (kelreplay.go) [redteam:F36].
	if verr := plausibleSignature(kel, keyStateSeq, pre, sig); verr != nil {
		return verr
	}
	return identity.VerifyObject(kel, aid, keyStateSeq, ts, pre, sig)
}

func (s *Server) hAgent(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	av, reviews, err := s.store.GetAgent(aid)
	if err != nil {
		// Not registered here. This hub may still know the agent from a
		// peer, and it already says so on /agents?cap= — the two
		// endpoints gave opposite answers to "do you know this AID",
		// and the one that 404s is the one a caller holding an AID uses.
		if node := s.store.GraphNodeFor(aid); node.Name != "" || s.store.HomeHubOf(aid) != "" {
			node.HomeHub = s.store.HomeHubOf(aid)
			writeJSON(w, http.StatusOK, map[string]any{
				"agent": node, "reviews": []ReviewView{},
				"note": "known from a peer, not registered here"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if reviews == nil {
		reviews = []ReviewView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": av, "reviews": reviews})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// cors allows the browser-based anetspace web (served by ANY origin — the official page, a local daemon
// console, or a self-hosted deployment) to call the Hub. Open CORS is safe here because the Hub keeps no
// browser session/cookie: state-changing endpoints authenticate per request with relayauth v2 signatures
// (register, profile, visibility, deregister, p2p, keys, relay send/poll/ack) or accept only
// self-verifying evidence (reviews), so there is no ambient authority for a cross-origin page to abuse.
// When exposing a self-hosted Hub to the internet, front it with a reverse proxy for TLS (the body size
// is capped, see limitBody; per-sender and per-IP rate limits are in limits.go).
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		// If-None-Match and ETag: a browser client of the A2A card and
		// JWKS endpoints revalidates its copy itself (registry.go).
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, If-None-Match, "+wireVersionHeader+", "+
			relayauth.HeaderAID+", "+relayauth.HeaderTS+", "+relayauth.HeaderSeq+", "+relayauth.HeaderSig)
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hAgentKEL publishes an agent's key event log.
//
// A KEL is public by construction — it is a log of key events, each one
// signed by the key it supersedes, and its whole design assumes anyone can
// replay it. This Hub has stored them since v0.1 and published none, which
// quietly made "anyone can verify a receipt" false: a receipt names the
// AID that signed it, and verifying that signature needs that AID's key
// history. Without this endpoint the only way to obtain one was to ask the
// requester nicely, so the audit worked exactly when a participant chose
// to cooperate — which is the property the whole scheme exists to remove.
//
// Publishing costs nothing and is not an authorization: holding the KEL
// lets you CHECK signatures, never make them.
func (s *Server) hAgentKEL(w http.ResponseWriter, r *http.Request) {
	s.serveAgentKEL(w, r.PathValue("aid"))
}

// hAgentKELLookup serves POST /agents/kel:lookup: GET /agents/{aid}/kel
// with the AID in the body (KeysLookupRequest), so that no request line
// names it [redteam:F3].
func (s *Server) hAgentKELLookup(w http.ResponseWriter, r *http.Request) {
	if aid, ok := lookupAID(w, r); ok {
		s.serveAgentKEL(w, aid)
	}
}

// serveAgentKEL answers a KEL lookup for aid (hAgentKEL, hAgentKELLookup).
func (s *Server) serveAgentKEL(w http.ResponseWriter, aid string) {
	// The hub's own history is served here too.
	//
	// It signs settlements, redemption receipts and vouchers, and every
	// one of those is worthless to a holder who cannot check the
	// signature. Until this line the hub was the one signer on the
	// network whose key nobody could look up — it published everyone
	// else's and not its own, so "you can verify what the custodian did"
	// was true of the objects and false of the system.
	//
	// Served from the same path as everyone else's rather than a special
	// one, because a verifier holding a receipt should not need to know
	// whether the signer happened to be a hub.
	if aid == s.hubAID {
		if kel, err := s.ownKEL(); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"aid": aid, "kel": base64.StdEncoding.EncodeToString(kel), "role": "hub"})
			return
		}
	}
	// Local first, then a peer's agent, then a peer hub itself.
	//
	// It served only locally registered agents, which broke the two cases
	// where a stranger most needs it. A receipt signed by an agent that
	// banks on a peer could not be checked at the hub the reader was
	// holding. And a witness attestation could not be checked at all: the
	// witness is a peer hub, /x402/witnesses tells the reader to verify
	// each signature, and the key to do it with was not obtainable from
	// this hub or named anywhere in the attestation. Evidence published
	// with no way to check it is not evidence.
	//
	// Where it came from is reported, because it changes what the answer
	// is worth: a local KEL is one this hub verified at registration, a
	// federated one is what a peer told it. Both are checkable against
	// the signature; only the reader can decide how much the difference
	// matters.
	if kel, err := s.store.AgentKEL(aid); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"aid": aid, "kel": base64.StdEncoding.EncodeToString(kel), "source": "local"})
		return
	}
	if kel, err := s.store.AnyKEL(aid); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"aid": aid, "kel": base64.StdEncoding.EncodeToString(kel), "source": "federated",
			"note": "this key history came from a peer, not from a registration here"})
		return
	}
	if events, err := s.peerKEL(aid); err == nil && len(events) > 0 {
		raw, merr := identity.MarshalKEL(events)
		if merr == nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"aid": aid, "kel": base64.StdEncoding.EncodeToString(raw), "source": "peer-hub",
				"role": "hub",
				"note": "this is a federation peer of this hub. Ask it directly for its own copy"})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error": "hub: " + aid + " is neither registered here, known from a peer, nor a peer hub"})
}

// hAgentCard serves an agent's own signed statement of what it offers.
//
// Published rather than kept internal, for the same reason the key
// history is: a claim nobody outside can check is a claim this hub is
// making on the agent's behalf. With the card and the KEL, anyone can
// confirm the directory entry is the agent's own words.
func (s *Server) hAgentCard(w http.ResponseWriter, r *http.Request) {
	raw, err := s.store.AgentCard(r.PathValue("aid"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(raw) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no card published for this agent"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// federatedAgents returns peer-learned agents, or nothing when discovery
// federation is not wired in.
func (s *Server) federatedAgents(capFilter string) []AgentView {
	if s.federated == nil {
		return nil
	}
	out, err := s.federated(capFilter)
	if err != nil {
		// A peer directory that cannot be read must not fail a query this
		// hub can answer from its own records.
		return nil
	}
	return out
}

// hLedger serves an account's entries, newest first, with the totals.
//
// The page was capped at 100 with nothing saying so, and an account with
// more than that had no way to know its own history was truncated.
// `anet reconcile` summed the page and compared it against the balance,
// so every busy account reported a discrepancy that was the cap rather
// than the ledger — dmax showed a balance of 866 against entries summing
// to -109.
//
// Total and sum cover the whole account regardless of the page, so a
// caller can reconcile without paging and can see when there is more.
//
// Served to the account holder only: the request must be signed by the
// AID in the path (relayauth v2, action "ledger"), and the signature
// covers the query, so ?limit is part of what was signed. Unsigned → 401.
// The entries name transaction ids that also appear in the counterparty's
// ledger, so a public ledger showed who paid whom (see hBalance).
func (s *Server) hLedger(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionLedger, signedBodyLimit)
	if !ok {
		return
	}
	aid := a.AID
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &limit)
	}
	entries, err := s.store.LedgerEntries(aid, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	total, sum, err := s.store.LedgerTotals(aid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := map[string]any{
		"aid": aid, "entries": entries,
		"total": total, "sum": sum, "returned": len(entries),
	}
	if total > len(entries) {
		out["truncated"] = true
		out["note"] = "entries is the newest page; total and sum cover the whole account. " +
			"Reconcile against sum, not against the page."
	}
	writeJSON(w, http.StatusOK, out)
}

// hVisibility records how far an agent is willing to be published.
//
// Authenticated with relayauth v2, action "visibility", by the agent in
// the path: this decides whether other hubs learn you exist, and a setting
// anyone could change for you is not a setting.
func (s *Server) hVisibility(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	if _, err := s.store.AgentKEL(aid); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}
	a, ok := s.authSelf(w, r, relayauth.ActionVisibility, signedBodyLimit)
	if !ok {
		return
	}
	var req struct {
		Visibility string `json:"visibility"`
	}
	if err := json.Unmarshal(a.Body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if err := s.store.SetVisibility(aid, req.Visibility); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": aid, "visibility": req.Visibility})
}

// readJSONBody decodes a bounded request body.
func readJSONBody(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(v)
}
