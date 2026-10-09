package aghub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/version"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Server is the Hub HTTP API over a Store.
type Server struct {
	store *Store
	// modules names the optional modules the application wired in; /stats
	// reports it. Set before serving (SetModules).
	modules []string
	// limits are the §3.7 bounds; registerLimiter is the token bucket
	// they configure; replay is the relayauth v2 replay protection (RC1,
	// auth2.go).
	limits          Limits
	registerLimiter *rateLimiter
	replay          *rc1State
	// dirLimiter bounds /directory:bucket per client address
	// (directory.go; a constant, not one of the limits), kelPushLimiter
	// /agents/kel:push (kelpush.go; KEL §2.12 KELPushRate).
	dirLimiter     *rateLimiter
	kelPushLimiter *rateLimiter
	// relay is what /relay/session and /relay/send keep in memory: the
	// sessions and the send buckets (session.go, hRelaySend).
	relay *relayState
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
	// hubKELSet, when set, lists the peer hubs' key histories pinned here,
	// for GET /hub/kels (hubkels.go). Nil in a build without federation.
	hubKELSet func() ([]HubKEL, error)
	// peerEndpoints, when set, answers where a peer hub can be reached.
	peerEndpoints func(aid string) string
	// publicURL is this hub's configured public base URL (publicurl.go);
	// empty means the origin of each request.
	publicURL string
	// fed, when set, is the federation module: the peers this hub
	// forwards to and asks for buckets (fed_home.go). Nil in a build
	// without federation. fedState is what the kernel keeps in memory of
	// them: resolved homes, refused credentials, peers' buckets.
	fed      Federation
	fedState *fedState
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
// to decide what to show. Call it before serving.
func (s *Server) SetModules(names []string) {
	s.modules = append([]string(nil), names...)
}

// NewServer wraps a store, with DefaultLimits.
//
// The server's first-contact sessions end with the deregistration of their
// AID and with every new event of its key history (sealed-sender SSR-H9);
// it registers that with the store here.
func NewServer(store *Store) *Server {
	s := &Server{store: store, replay: newRC1(time.Now().UnixMilli(), rc1Shards, rc1MemHigh, rc1MemLow),
		jwks:           newJWKSCache(jwksCacheBytes, a2acard.JWKS),
		dirLimiter:     newRateLimiter(DirBucketPerMinute/60.0, DirBucketBurst),
		kelPushLimiter: newRateLimiter(KELPushPerMinute/60.0, KELPushBurst),
		relay:          newRelayState(store.now), fedState: newFedState()}
	if err := s.SetLimits(DefaultLimits()); err != nil {
		panic(err) // the defaults are constants and valid
	}
	store.OnDeregistered(s.dropSessions)
	store.OnKELExtended(s.dropSessions)
	return s
}

// SetLimits replaces the §3.7 limits. Call it before serving: it rebuilds
// the rate limiters, so buckets in use are reset.
func (s *Server) SetLimits(l Limits) error {
	if err := l.Validate(); err != nil {
		return err
	}
	s.limits = l
	s.registerLimiter = newRateLimiter(l.RegisterPerMinute/60, l.RegisterBurst)
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
// Wire 3 (core CORE-V1) is a breaking change with no fallback: the
// negotiation, the one error body and the strict request decoding are in
// internal/wire3, shared with the federation module and /hub/identity.
const (
	wireVersion       = wire3.Version
	wireVersionHeader = wire3.Header
)

// WireVersion is the Hub wire contract version this build speaks.
const WireVersion = wireVersion

// RequiredAnet is the first anet release that speaks WireVersion. Every
// refusal that tells a node to upgrade names it (the 426 of wire3.Contract,
// the missing relayauth v2 headers, a review that still carries content),
// so they cannot name different releases.
const RequiredAnet = wire3.RequiredAnet

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
	mux.HandleFunc("GET /hub/kels", s.hHubKELs)
	// A key history this hub knows, extended by anyone who holds the
	// extension: how an agent tells a hub it no longer uses as its witness
	// that it rotated or deactivated (KEL H-4). See kelpush.go.
	mux.HandleFunc("POST "+KELPushPath, s.hKELPush)
	// The JWKS named by the jku of an agent's A2A card, derived from its
	// KEL (A2A-DESIGN §10.3, §10.5). See registry.go.
	mux.HandleFunc("GET /agents/{aid}/jwks.json", s.hJWKS)
	mux.HandleFunc("GET /agents/{aid}/balance", s.hBalance)
	mux.HandleFunc("GET /agents/{aid}/ledger", s.hLedger)
	// Encryption key sets (§3.7). See keys.go.
	mux.HandleFunc("GET /agents/{aid}/keys", s.hKeysGet)
	mux.HandleFunc("POST /agents/{aid}/keys", s.hKeysPost)
	// The directory, answered by bucket so that no query names the agent
	// it looks for (sealed-sender §2.9). See directory.go. There is no
	// lookup by AID for a sender: the routes that took one in the body
	// and the p2p rendezvous are gone and answer 404 (§2.7).
	mux.HandleFunc("POST /directory:bucket", s.hDirectoryBucket)
	mux.HandleFunc("POST /agents/{aid}/visibility", s.hVisibility)
	// The other half of registration: leaving. See deregister.go.
	mux.HandleFunc("POST /agents/{aid}/deregister", s.hDeregister)
	// The three endpoints x402 defines for a facilitator. This hub hosts
	// its own, which the spec permits outright — and for a ledger rail
	// there is nothing to separate from, because the balances are here.
	mux.HandleFunc("GET /x402/supported", s.hX402Supported)
	// Credit going back out.
	mux.HandleFunc("POST /x402/redeem", s.hRedeem)
	// What this hub owes, once per supply epoch: the latest epoch, the
	// signed chain of them and its head, the witnesses who have pinned it,
	// and each account's proof that its balance is counted. See supply.go
	// and witness.go.
	mux.HandleFunc("GET /x402/supply", s.hSupply)
	mux.HandleFunc("GET /x402/issuance", s.hIssuance)
	mux.HandleFunc("GET /x402/issuance/head", s.hIssuanceHead)
	mux.HandleFunc("POST /x402/witness", s.hWitnessSubmit)
	mux.HandleFunc("GET /x402/witnesses", s.hWitnesses)
	mux.HandleFunc("GET /agents/{aid}/liability-proof", s.hLiabilityProof)
	mux.HandleFunc("GET /agents/{aid}/redemptions", s.hRedemptions)
	// Reputation across hub boundaries — the signed evidence, never an
	// aggregate somebody else computed.
	//
	// The peer-facing review STREAM is deliberately absent here. It
	// belongs to the federation plane and is served at GET
	// /fed/v3/reviews by internal/federation, to peers only, behind the
	// discovery switch and the no_federation tag. The kernel served the same stream at GET
	// /federation/reviews behind neither, so a hub built -tags
	// no_federation — an organisation's internal hub, which has opted out
	// of federation entirely — still published every signed review it
	// held to anyone who asked. Nothing called the kernel copy: peers
	// sync from /fed/v3/reviews, and no daemon, CLI, script or page in
	// these repositories names /federation/reviews.
	mux.HandleFunc("GET /agents/{aid}/reputation", s.hReputation)
	mux.HandleFunc("POST /x402/verify", s.hX402Verify)
	mux.HandleFunc("POST /x402/settle", s.hX402Settle)
	// The x402 resource gateway is removed; its path answers 410
	// gateway_removed (see gateway.go).
	mux.HandleFunc("GET "+gatewayPath, hGatewayRemoved)
	// The A2A registry: verified A2A cards of agents registered here
	// (A2A-DESIGN §10.5). See registry.go.
	mux.HandleFunc("GET /a2a/v1/agents", s.hA2AAgents)
	mux.HandleFunc("GET /a2a/v1/agents/{aid}/card", s.hA2ACard)
	mux.HandleFunc("GET /graph", s.hGraph)
	mux.HandleFunc("GET /stats", s.hStats)
	// Relay (wire 3): sealed envelopes only. A send is not signed: a
	// first contact carries the MAC of a session its sender opened with
	// its signature (session.go), every later message a delivery
	// credential its recipient issued, which names no sender. poll and
	// ack are signed so only the mailbox owner can read and clear it. See
	// relay.go.
	mux.HandleFunc("POST /relay/session", s.hRelaySession)
	mux.HandleFunc("POST /relay/send", s.hRelaySend)
	mux.HandleFunc("POST /relay/poll", s.hRelayPoll)
	mux.HandleFunc("POST /relay/ack", s.hRelayAck)
	// A mailbox owner revokes delivery credentials it issued (revoke.go).
	mux.HandleFunc("POST /mailbox/revoke", s.hMailboxRevoke)
	// There is no guest mode (A2A-DESIGN §9 row 访客模式). The hub used to
	// relay a browser visitor's messages under a hub-held identity, which
	// made it a plaintext endpoint of the conversation; /guest/* is not
	// routed and answers 404.
	//
	// Agent-facing onboarding manual (AgentHansa-style): one URL an LLM agent reads to learn how to drive
	// the local `anet` CLI. Injects THIS hub's origin so the copy-paste commands point at the right Hub.
	mux.HandleFunc("GET /llms.txt", s.hLLMs)
	// Researcher directory: a filtered lens over the SAME registry (agents carrying the reserved
	// `research` cap). This is what a downstream consumer publishes into — one ecosystem, one registry, a
	// research sub-view. See web/research.html (client-side fetch of /agents?cap=research).
	mux.HandleFunc("GET /research", s.hResearch)
	// The self-contained web UI (starfield of the real registry). It has no chat: there is no guest
	// mode, and delegating needs a local anet daemon. Other static assets fall through.
	//
	// Everything no route above takes ends here: a GET or HEAD for a page
	// asset is served, and anything else — an unknown path, or a known one
	// with another method — is 404 not_found in the wire-3 error body, so
	// a client reads one shape of refusal whatever it got wrong.
	webFS := webRoot()
	fileSrv := http.FileServer(http.FS(webFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			wire3.Refuse(w, wire3.ReasonNotFound)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.hIndex(w, r)
			return
		}
		if _, err := fs.Stat(webFS, strings.TrimPrefix(path.Clean(r.URL.Path), "/")); err != nil {
			wire3.Refuse(w, wire3.ReasonNotFound)
			return
		}
		fileSrv.ServeHTTP(w, r)
	})
	return cors(wire3.Contract(s.limitBody(mux)))
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
// (works unchanged for the official Hub and any self-hosted deployment behind a TLS reverse proxy), and
// RequiredAnet into {{REQUIRED_ANET}}, so the manual names the release the 426 names.
func (s *Server) hLLMs(w http.ResponseWriter, r *http.Request) {
	b, err := llmsTxt()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := strings.NewReplacer("{{HUB_URL}}", s.origin(r), "{{REQUIRED_ANET}}", RequiredAnet).Replace(string(b))
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

// RegisterRequest is an agent's self-registration: its profile, its KEL
// (base64url CoreDet-CBOR, core G2), optionally its cards and its encryption
// key set; for a newcomer, the proof of work a challenge asked for; or, with
// check_only, only the question "would this hub take me" (core §2.12.2).
//
// The request is authenticated with relayauth v2 headers, action
// "register", verified against the KEL in this body (the agent may not be
// stored yet). The X-ANet-AID header must equal aid. Proof of key
// possession is what stops a stranger who knows the public KEL from
// overwriting the registration.
//
// It is decoded strictly (core CORE-E7): a member it does not list is 400
// bad_request, except "invite", which is 400 invite_removed — hubs no longer
// use invites, and a node still sending one is told so (LEC HN-5).
type RegisterRequest struct {
	AID     string   `json:"aid"`
	Name    string   `json:"name"`
	Caps    []string `json:"caps"`
	Summary string   `json:"summary"`
	Readme  string   `json:"readme"`
	KEL     string   `json:"kel"` // base64url(identity.MarshalKEL)
	// EncKeys is the agent's encryption key set: base64url of the
	// seal.SignedEncKeySet encoding (§3.1, core G2). Optional. A set that
	// does not decode or verify is reported in keys_status and does not
	// fail the registration; one that does not follow the stored set fails
	// it with 409 keys_rollback (PAY-A1 step 9, forward-secrecy FS-H4).
	EncKeys string `json:"enc_keys,omitempty"`
	// PrevSeq is the seq of the last key set the agent signed before
	// EncKeys (0 for none): required with enc_keys (PAY-A1 step 3), and
	// compared with the stored set's seq as POST /agents/{aid}/keys does
	// (step 9).
	PrevSeq *uint64 `json:"prev_seq,omitempty"`
	// A2ACard is the agent's signed A2A AgentCard as a JSON object.
	// Optional. It is verified against KEL and the stored card's
	// params.seq, stored as the exact bytes received when admitted, and
	// reported in card_status; it does not fail the registration (see
	// a2acard.go).
	A2ACard json.RawMessage `json:"a2a_card,omitempty"`
	// PoW answers a pow_required challenge: needed only by a newcomer this
	// hub admits through a sign-up window or open registration.
	PoW *RegisterPoW `json:"pow,omitempty"`
	// CheckOnly asks only whether this hub would take the AID: 200
	// {status: admitted|open} or 403 admission_required. Nothing is
	// written, no proof of work is asked, nothing is reserved (LEC HN-2).
	CheckOnly bool `json:"check_only,omitempty"`
}

// RegisterPoW is a proof of work: the challenge's seed and the nonce found
// for it, both base64url (hub-payment-privacy §2.2).
type RegisterPoW struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
}

// RegisterResponse is the /register answer. keys_status and card_status
// report the optional fields individually; keys_error and card_error
// explain a status other than ok, unchanged or absent. probation_until (unix
// ms) and trial (pending or granted) are there only for an account that
// came in through a sign-up window or open registration. revocations is
// how many unexpired revocations of the agent's delivery credentials this
// hub holds (the total of /mailbox/revoke): a daemon that revoked more
// pushes them again (sealed-sender SSR-D21). key_state_notice is the
// witness notice this hub states about the agent's key history (NoticeWire,
// base64url; notice.go), or key_state_notice_error why there is none
// (quarantine, not_admitted or not_witness; KEL H-13).
type RegisterResponse struct {
	AID                 string  `json:"aid"`
	Status              string  `json:"status"`
	KeysStatus          string  `json:"keys_status"`
	KeysError           string  `json:"keys_error,omitempty"`
	CardStatus          string  `json:"card_status"`
	CardError           string  `json:"card_error,omitempty"`
	ProbationUntil      *uint64 `json:"probation_until,omitempty"`
	Trial               string  `json:"trial,omitempty"`
	Revocations         uint64  `json:"revocations"`
	KeyStateNotice      string  `json:"key_state_notice,omitempty"`
	KeyStateNoticeError string  `json:"key_state_notice_error,omitempty"`
}

// CheckOnlyResponse is the /register answer to check_only: admitted (the
// AID is registered here or on the admission list) or open (it may register
// after a proof of work: open registration, or a sign-up window with room).
type CheckOnlyResponse struct {
	Status string `json:"status"`
}

// The check_only answers.
const (
	CheckAdmitted = "admitted"
	CheckOpen     = "open"
)

// maxRegisterBody caps a registration, separately from limitBody.
//
// The general ceiling is sized for relay envelopes, and registration
// inherited it: one unauthenticated POST could hand this hub a
// multi-megabyte body before anything examined its contents, which is the
// root of the capability-index amplification the constants in aghub.go
// bound. A registration carries a KEL, profile text, a capability list, a
// key set and an A2A card (at most maxA2ACardBytes). The largest plausible
// one is maxCapsPerAgent ids of maxCapIDLen bytes listed twice — once in
// caps, once as the skills of the A2A card — at roughly 130 KiB, so 1 MiB
// admits it with room for a long readme. An agent whose registration does
// not fit is refused with 413 rather than truncated.
const maxRegisterBody = 1 << 20

// registerKELReplays counts the KELs /register decoded and replayed. A test
// reads it to show that a registration refused at the admission gate cost
// no replay (PAY-A2, M-PAY-22).
var registerKELReplays atomic.Int64

// hRegister is POST /register, in the one order of hub-payment-privacy
// PAY-A1. Each step refuses with its own code and costs no more than the
// steps before it; nothing is written before step 10, and what step 4
// reserved is given back when a later step refuses.
//
//	0  X-ANet-Wire (wire3.Contract, before this handler)
//	1  the registration rate of the client's address
//	2  the body: size, strict decoding, invite_removed before bad_request
//	3  aid and kel present; X-ANet-AID == aid; caps; the pow's shape;
//	   enc_keys base64url, with prev_seq
//	4  the admission gate, for an AID not registered here
//	5  the KEL: decode, replay, derive the AID; a deactivated one is
//	   refused; the relayauth signature, under the tip of the submitted
//	   KEL (KEL H-3)
//	6  the KEL only extends what this hub holds (registered or departed);
//	   the times of its new events (KEL R-9, R-10)
//	7  the witness is this hub (KEL H-1; not for check_only)
//	8  check_only answers here
//	9  the key set follows the stored one (prev_seq, 409 keys_rollback);
//	   the key set and the A2A card are reported per field after the row
//	10 one transaction: the agent row and what admission writes beside it
//	11 a refusal after step 4 gives the reservation back
func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	// 1. Per client address, before anything else: an AID is one locally
	// generated key pair, so without this the per-sender send limit is
	// bypassed by registering a new sender (§2 X1, [C15f]).
	if ok, wait := s.registerLimiter.allow(clientIP(r)); !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
			Error: "Too many registrations from this address; retry after Retry-After."})
		return
	}
	// 2. The body, read whole because the signature covers these bytes.
	body, f := readRawBody(w, r, maxRegisterBody)
	if f != nil {
		if f.code == http.StatusRequestEntityTooLarge {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTooLarge,
				Error: fmt.Sprintf("A registration is at most %d bytes; send a smaller one.", maxRegisterBody)})
			return
		}
		wire3.Refuse(w, wire3.ReasonBadRequest)
		return
	}
	var req RegisterRequest
	if err := wire3.DecodeStrict(body, &req); err != nil {
		if carriesInvite(body) {
			wire3.Refuse(w, wire3.ReasonInviteRemoved)
			return
		}
		wire3.RefuseDecode(w, err)
		return
	}
	// 3. What the request must carry, checked on the request alone.
	auth, err := parseV2Headers(r)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: sentence(err)})
		return
	}
	if req.AID == "" || req.KEL == "" {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A registration carries aid and kel; add them and send again."})
		return
	}
	// A complete AID, before it is hashed into a proof of work, echoed in
	// admission_required or written to the log with the command an
	// operator copies to admit it: anything else in that line would be
	// the sender's text in the operator's shell.
	if !ValidAID(req.AID) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"aid\" is not a complete AID; send the agent's own AID as anet prints it."})
		return
	}
	if auth.AID != req.AID {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: relayauth.HeaderAID + " does not match the aid being registered; sign as the agent you register."})
		return
	}
	// The declared capability set is checked before the signature work:
	// it is the cheapest check, it needs nothing but the request itself,
	// and an oversized registration is the case worth rejecting cheaply.
	if err := validateCaps(req.Caps); err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: sentence(err)})
		return
	}
	// A key set comes with the seq it follows, and is base64url like every
	// binary value here (core CORE-E5): both are wire errors of the request,
	// not a stale or bad set, so they fail it whole.
	var encKeys []byte
	if req.EncKeys != "" {
		if req.PrevSeq == nil {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "A registration that carries enc_keys carries prev_seq too (the seq of the last key set signed before it, 0 for none); add it and send again."})
			return
		}
		if encKeys, err = wire3.DecodeB64URL("enc_keys", req.EncKeys); err != nil {
			wire3.RefuseDecode(w, err)
			return
		}
	}
	var powSeed, powNonce []byte
	if req.PoW != nil {
		var e1, e2 error
		powSeed, e1 = wire3.DecodeB64URL("pow.seed", req.PoW.Seed)
		powNonce, e2 = wire3.DecodeB64URL("pow.nonce", req.PoW.Nonce)
		if e1 != nil || e2 != nil || len(powSeed) != 32 || len(powNonce) < 1 || len(powNonce) > regpow.MaxNonce {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "The member \"pow\" must hold a 32-byte seed and a nonce of 1 to 32 bytes, both base64url; fix it and send again."})
			return
		}
	}
	// 4. The admission gate, only for an AID this hub does not hold as a
	// registration (one with only a tombstone in departed_kel is unknown
	// too). A registered AID re-registers on every start and whenever its
	// capabilities change, and is never gated (PAY-A2).
	now := s.store.now()
	// An AID registered now passes no gate, but its row must still be
	// there when step 10 writes: one deregistered meanwhile (revoked,
	// swept, left) is a newcomer again, and only the gate admits those.
	adm := &admissionWrite{via: viaRegistered}
	var hold *gateHold
	committed := false
	defer func() {
		if !committed {
			s.store.gate().release(hold)
		}
	}()
	checkStatus := CheckAdmitted
	if !s.store.KnowsAgent(req.AID) {
		g := s.store.gate()
		var refused bool
		adm, hold, checkStatus, refused = s.admissionGate(w, r, &req, powSeed, powNonce, g, now)
		if refused {
			return
		}
	}
	// 5. The KEL and the signature.
	registerKELReplays.Add(1)
	kelBytes, err := wire3.DecodeB64URL("kel", req.KEL)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The member \"kel\" is not base64url; encode the key history without padding and send again."})
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
		msg := "The key history does not decode; send the agent's own key history."
		if seal.ReasonOf(err) == seal.ReasonKELTooLarge {
			msg = fmt.Sprintf("The key history is too long: this hub, like every sender, accepts at most %d events and %d bytes.",
				seal.MaxKELEvents, seal.MaxKELBytes)
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid, Error: msg})
		return
	}
	states, err := identity.Replay(kel)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The key history does not replay; send the agent's own key history."})
		return
	}
	tip := states[len(states)-1]
	// The KEL must derive the claimed AID — a registration cannot claim an AID it does not control.
	if tip.AID != req.AID {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The key history does not derive the aid being registered; send that agent's own key history."})
		return
	}
	// A key history that ends in a dip says so itself, and the dip is
	// signed with the identity's recovery material: whoever sends it, the
	// identity is deactivated (KEL H-1 2). Said before the signature, which
	// no key can make for it any more (a dip's state holds none, KEL H-3).
	if tip.Status == identity.StatusDeactivated {
		wire3.Refuse(w, wire3.ReasonAIDDeactivated)
		return
	}
	// Proof of key possession, against the SUBMITTED KEL (the agent may
	// not be stored yet), under its tip (KEL H-3).
	if f := s.verifyV2(r, relayauth.ActionRegister, body, auth, kel); f != nil {
		writeAuthFailure(w, f)
		return
	}
	// 6. The KEL may only grow (§3.8), measured against the registration
	// or, for an agent that left, the tombstone it left (PAY-O1). The
	// registrant is the owner, so a shorter KEL than the one held is an old
	// copy or a rollback to before a rotation, and one that disagrees on an
	// event is a fork. Accepting either would let whoever holds a
	// superseded key take the registration back to the state that key
	// controls.
	held, err := s.store.KnownKEL(req.AID)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if held != nil {
		if err := identity.ExtendsKEL(held, kel); err != nil {
			refuseKELExtension(w, err)
			return
		}
	}
	// The events this hub has not held are checked against its clock (KEL
	// H-1 3, R-9, R-10): none later than now + 5 minutes; and one this hub
	// is the first to accept as its witness, no earlier than now − 5
	// minutes, so a key event cannot be dated back past a rotation.
	if err := s.checkNewEvents(held, kel, now); err != nil {
		refuseEventTime(w, err)
		return
	}
	// 7. Unless check_only, the tip names this hub as its witness (KEL H-1
	// 1): a hub registers only the agents it witnesses, and so it signs
	// notices for them. check_only comes before the agent designates its
	// witness, which it does only once a hub has said it would take it.
	if !req.CheckOnly && (tip.Toad != identity.ToadAgent || tip.Witness != s.hubAID) {
		wire3.Refuse(w, wire3.ReasonWitnessNotThisHub)
		return
	}
	// 8. check_only answers here: nothing is written and nothing reserved
	// (none was: the gate reserves only for a real registration).
	if req.CheckOnly {
		writeJSON(w, http.StatusOK, CheckOnlyResponse{Status: checkStatus})
		return
	}
	// 9. The key set follows the one stored here (FS-H4): checked before
	// anything is written, and again where the set is written below, after
	// the row (a publication that raced this one between the two is
	// answered the same way, with the row written: registering again is
	// harmless). The A2A card is reported per field after the row.
	if encKeys != nil {
		var rb *KeysRollbackError
		if err := s.store.KeysRollbackOf(req.AID, encKeys, *req.PrevSeq); errors.As(err, &rb) {
			refuseKeys(w, rb)
			return
		} else if err != nil {
			wire3.Internal(w, err)
			return
		}
	}
	// 10. One transaction: the row, and for a first registration how it came
	// in and the list's grant. RegisterAgent repeats the KEL extension
	// check inside it, for a concurrent registration of the same AID that
	// wrote between the check above and this write.
	if adm != nil {
		adm.now = now
	}
	admitted, err := s.store.registerAgent(req.AID, req.Name, req.Caps, kelBytes, kel, adm)
	if err != nil {
		switch {
		case errors.Is(err, ErrKELNotExtended):
			refuseKELExtension(w, err)
		case errors.Is(err, errWindowFilled), errors.Is(err, errNotAdmitted), errors.Is(err, errDeregisteredMeanwhile):
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonAdmissionRequired, Extra: map[string]any{"aid": req.AID}})
		default:
			wire3.Internal(w, err)
		}
		return
	}
	if admitted {
		committed = true
		s.store.gate().committed(hold)
	}
	// Optional profile carried on the registration (usually set later via /profile).
	if req.Summary != "" || req.Readme != "" {
		if err := s.store.PutProfile(req.AID, req.Summary, req.Readme); err != nil {
			wire3.Internal(w, err)
			return
		}
	}
	out := RegisterResponse{AID: req.AID, Status: "registered",
		KeysStatus: KeysStatusAbsent, CardStatus: CardStatusAbsent}
	// The key set and the A2A card are reported per field, after the
	// registration is written: a node whose key set does not verify, or
	// breaks the mailbox key rule (SSR-W9), is still registered and can
	// publish a corrected set with POST /agents/{aid}/keys, instead of being
	// unable to register at all. Only a set that does not follow the stored
	// one fails the registration (step 9).
	if encKeys != nil {
		status, err := s.store.PublishKeys(req.AID, encKeys, *req.PrevSeq, kel, time.Now())
		var rb *KeysRollbackError
		if errors.As(err, &rb) {
			refuseKeys(w, rb)
			return
		}
		out.KeysStatus, out.KeysError = keysStatusOf(status, err)
	}
	// Also when the field is absent: the stored card is re-verified
	// against the KEL just registered, which may have rotated away from
	// the key that signed it.
	out.CardStatus, out.CardError = s.store.RegisterA2ACard(req.AID, req.A2ACard, kel, time.Now())
	if out.CardStatus == CardStatusOK {
		logCardHome(req.AID, req.A2ACard, s.origin(r))
	}
	if st, err := s.store.trialStateOf(req.AID); err != nil {
		log.Printf("hub: reading the probation of %s: %v", req.AID, err)
	} else {
		out.ProbationUntil, out.Trial = st.ProbationUntil, st.Trial
	}
	// The registration is written; a count that cannot be read is
	// reported as 0, which makes the daemon push its revocations again
	// (idempotent) rather than fail a registration that took effect.
	if n, err := s.store.RevocationCount(req.AID); err != nil {
		log.Printf("hub: counting the revocations of a registering agent: %v", err)
	} else {
		out.Revocations = uint64(n)
	}
	out.KeyStateNotice, out.KeyStateNoticeError = s.noticeAnswer(req.AID)
	writeJSON(w, http.StatusOK, out)
}

// admissionGate is step 4 of PAY-A1 for an AID not registered here:
//
//	a. on the admission list: admitted, no proof of work, no quota, no
//	   probation;
//	b. open registration: check_only answers open; otherwise a proof of
//	   work (one hash), then a place in today's quota at every level of the
//	   client's network;
//	c. closed, with a sign-up window open and not full: check_only answers
//	   open; otherwise a proof of work, then one place of the window;
//	d. otherwise 403 admission_required.
//
// It writes the refusal itself and reports refused; otherwise it returns
// what the registration writes beside its row, the reservation to give
// back if a later step refuses, and the check_only answer.
func (s *Server) admissionGate(w http.ResponseWriter, r *http.Request, req *RegisterRequest,
	seed, nonce []byte, g *admissionGate, now time.Time) (adm *admissionWrite, hold *gateHold, status string, refused bool) {
	refuseAdmission := func() {
		// Logged, so an operator running a closed hub sees who knocked and
		// can admit it. /register is rate-limited per client address,
		// which bounds how fast one address can add to this log; the
		// address itself is never written (PAY-N7).
		log.Printf("hub: registration refused for %s (claimed, not yet proven): not on the admission list; "+
			"to let it in: anet-hub admit %s", req.AID, req.AID)
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonAdmissionRequired, Extra: map[string]any{"aid": req.AID}})
	}
	listed, err := s.store.isAdmitted(req.AID)
	if err != nil {
		wire3.Internal(w, err)
		return nil, nil, "", true
	}
	if listed {
		return &admissionWrite{via: viaList}, nil, CheckAdmitted, false
	}
	mode, err := s.store.AdmissionMode()
	if err != nil {
		wire3.Internal(w, err)
		return nil, nil, "", true
	}
	var win Window
	if mode != AdmissionOpen {
		var open bool
		if win, open, err = openWindow(s.store.db, now); err != nil {
			wire3.Internal(w, err)
			return nil, nil, "", true
		}
		if !open || win.Used >= win.Max {
			refuseAdmission()
			return nil, nil, "", true
		}
	}
	if req.CheckOnly {
		return nil, nil, CheckOpen, false
	}
	// The proof of work, before anything that costs this hub more than
	// one hash (PAY-A2): the KEL replay and the signature come after.
	if seed == nil || !g.checkPow(s.hubAID, req.AID, seed, nonce, now) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonPowRequired, Extra: map[string]any{"challenge": g.challenge(now)}})
		return nil, nil, "", true
	}
	if mode == AdmissionOpen {
		h, ok := g.reserveSignup(clientAddr(r), now)
		if !ok {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRegistrationQuota, RetryAfter: untilTomorrow(now)})
			return nil, nil, "", true
		}
		return &admissionWrite{via: viaOpen}, h, CheckOpen, false
	}
	h, ok := g.reserveWindow(win)
	if !ok {
		refuseAdmission()
		return nil, nil, "", true
	}
	return &admissionWrite{via: viaWindow, window: win.ID}, h, CheckOpen, false
}

// carriesInvite reports whether a registration body has a top-level member
// "invite" (hub-payment-privacy PAY-A1 step 2: invite_removed is answered
// before any other unknown member).
func carriesInvite(body []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	_, ok := m["invite"]
	return ok
}

// refuseKELExtension answers a KEL that does not extend the one held:
// 409 kel_fork or kel_rollback.
func refuseKELExtension(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrKELFork):
		wire3.Refuse(w, wire3.ReasonKELFork)
	case errors.Is(err, identity.ErrKELRollback):
		wire3.Refuse(w, wire3.ReasonKELRollback)
	default:
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The key history does not replay; send the agent's own key history."})
	}
}

// sentence turns an internal error into the one English sentence of an
// error body: capitalised, ending with a full stop.
func sentence(err error) string {
	m := strings.TrimPrefix(err.Error(), "hub: ")
	if m == "" {
		return ""
	}
	m = strings.ToUpper(m[:1]) + m[1:]
	if !strings.HasSuffix(m, ".") {
		m += "."
	}
	return m
}

// ProfileRequest updates an agent's self-authored profile. The request is
// authenticated with relayauth v2 headers, action "profile", verified
// against the agent's REGISTERED KEL. aid is optional; when present it must
// equal the X-ANet-AID header.
//
// There is no pricing member: prices are not public any more (they travel
// in the extended card the provider signs, end to end), so the body is
// decoded strictly and a pricing member is 400 bad_request like any member
// the route does not take.
type ProfileRequest struct {
	AID     string `json:"aid,omitempty"`
	Summary string `json:"summary"`
	Readme  string `json:"readme"`
}

func (s *Server) hProfile(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionProfile, signedBodyLimit)
	if !ok {
		return
	}
	var req ProfileRequest
	if err := wire3.DecodeStrict(a.Body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if req.AID != "" && req.AID != a.AID {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: "The member \"aid\" is not the AID in " + relayauth.HeaderAID + "; update your own profile, signed as yourself."})
		return
	}
	if err := s.store.PutProfile(a.AID, req.Summary, req.Readme); err != nil {
		if errors.Is(err, ErrNotRegistered) {
			// Deregistered between the signature check and the write.
			wire3.Refuse(w, wire3.ReasonUnknownAID)
			return
		}
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": a.AID, "status": "profile_updated"})
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

// --- relay handlers (wire 3) ---

// RelaySendResponse is the /relay/send answer (core §2.12.2): queued (a new
// row) or duplicate (the same envelope is already waiting), the rid the
// sender asks about later, and whether the recipient has stopped collecting
// its mail (liveness.go). via_hub names the hub that queued the envelope
// when it is not this one (federation).
type RelaySendResponse struct {
	Status         string `json:"status"`
	RID            string `json:"rid"`
	ViaHub         string `json:"via_hub,omitempty"`
	RecipientQuiet bool   `json:"recipient_quiet"`
}

// The /relay/send statuses.
const (
	RelayQueued    = "queued"
	RelayDuplicate = "duplicate"
)

// EnvelopeContentType is the Content-Type of a /relay/send body: the
// envelope itself (core §2.12.1).
const EnvelopeContentType = "application/vnd.anet.envelope+cbor"

// RelayPollRequest is the /relay/poll body (relayauth v2, action "poll").
//
// AfterID is optional: only envelopes with an id above it are returned,
// still oldest first and under the same limit and byte budget. Absent or 0
// is the whole mailbox, as before the field existed.
type RelayPollRequest struct {
	Limit   int   `json:"limit,omitempty"`
	AfterID int64 `json:"after_id,omitempty"`
}

// RelayEnvelopeView is one mailbox entry on the wire: the envelope
// (base64url, core G2) and when this hub accepted it (unix milliseconds,
// relay_message.created_at), which the daemon's arrival time and key
// deletion read (forward-secrecy FS-H5, engine H-3).
type RelayEnvelopeView struct {
	ID         int64  `json:"id"`
	Envelope   string `json:"envelope"`
	AcceptedAt uint64 `json:"accepted_at"`
}

// RelayPollResponse is the /relay/poll answer. More says whether envelopes
// the page could not hold remain past it (Store.RelayPoll, FS-H5).
// key_state_notice is the caller's witness notice from this hub, or
// key_state_notice_error why there is none (KEL H-5, H-13), as on
// /register: an agent that polls holds a fresh notice to carry in what it
// sends.
type RelayPollResponse struct {
	Messages            []RelayEnvelopeView `json:"messages"`
	More                bool                `json:"more"`
	KeyStateNotice      string              `json:"key_state_notice,omitempty"`
	KeyStateNoticeError string              `json:"key_state_notice_error,omitempty"`
}

// RelayAckRequest is the /relay/ack body (relayauth v2, action "ack").
type RelayAckRequest struct {
	IDs []int64 `json:"ids"`
}

// RelayAckResponse is the /relay/ack answer: how many rows were deleted.
type RelayAckResponse struct {
	Acked int `json:"acked"`
}

// relayState is what /relay/session and /relay/send keep in this process's
// memory only (sealed-sender §3.1): the sessions and the buckets of §2.12.
type relayState struct {
	sessions *sessionTable
	// sessionSend is each session holder's send bucket, by AID.
	sessionSend *bucketSet
	// caps is each delivery credential's bucket, by owner and cap_id.
	caps *bucketSet
	// firstContact is each recipient's first-contact bucket, by AID.
	firstContact *bucketSet
	// addrFailure is each client address's bucket of refused kind-1 sends
	// (clientIP: IPv4 address, IPv6 /64).
	addrFailure *bucketSet
	// fedSource is each peer hub's bucket at this hub as the home of the
	// recipients it forwards to (/fed/v3/forward, §4.2.7), by its AID.
	fedSource *bucketSet
}

func newRelayState(now func() time.Time) *relayState {
	return &relayState{sessions: newSessionTable(), sessionSend: newBucketSet(now), caps: newBucketSet(now),
		firstContact: newBucketSet(now), addrFailure: newBucketSet(now), fedSource: newBucketSet(now)}
}

// HeaderAccess carries the delivery credential of a send, base64url of the
// CoreDet encoding of seal.Access, byte for byte outer key 7 of the envelope
// (core §2.12.1).
const HeaderAccess = "X-ANet-Access"

// hRelaySend is POST /relay/send, in the one order of sealed-sender §4.2.1
// (SSR-H2). Each step refuses with its own code; no step before the one that
// refuses takes a token or writes a row. The one exception is the address
// bucket of step 1a, which a refused credential debits after its 403 has been
// answered (SSR-H3b), and never a send that went through.
//
//	0  X-ANet-Wire (wire3.Contract, before this handler)
//	1  the headers: Content-Type; no identity headers; X-ANet-Access, at most
//	   1 KiB, base64url, an access of kind 0 or 1; kind 1 without session
//	   headers, kind 0 with all of them; X-ANet-Home, if any, an AID
//	1a kind 1: the client address's bucket of refused credentials
//	2  before the body is read: kind 0, the session and X-ANet-TS, then its
//	   send bucket; kind 1, the credential (capPrecheck; for an owner
//	   registered at a peer, against its home's directory entry or its
//	   federated card, capPrecheckRemote), then its bucket
//	3  the body, at most MaxEnvelope
//	4  the envelope: seal.ParseOuter, outer key 7 the same bytes as the
//	   header, the recipient AID; env_digest
//	5  kind 0: the session MAC over the request; kind 1: seal.VerifyAccess,
//	   with the holder's proof over env_digest and owner == to
//	6  the recipient is registered here; else, once its home peer hub is
//	   resolved, the send goes to that one hub (forwardSend, SSR-H13) and
//	   steps 7 to 11 are the home's
//	7  the same envelope already waiting: duplicate, no token taken
//	7a non-contact mail no larger than the recipient's non-contact share
//	8  the buckets, all of them or none
//	9, 10 Store.RelayEnqueue: the redelivery count, the kid (FS-H1) and the
//	   mailbox, in the transaction that writes the row
//	11 queued, with the rid
//
// A kind-1 refusal at step 2 or 5 is the same status and the same bytes,
// whatever the cause (SSR-H3): an unknown owner, a bad signature, an old
// epoch, an expiry, a revocation, a proof for another envelope. The hub
// learns from a kind-1 send who it is for and under which credential; it
// never learns from it who sent it, and nothing of the request but the row
// is written.
func (s *Server) hRelaySend(w http.ResponseWriter, r *http.Request) {
	now := s.store.now()
	// 1. The headers.
	if !envelopeContentType(r) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A send carries the envelope itself as " + EnvelopeContentType + "; send it with that Content-Type."})
		return
	}
	for _, h := range []string{relayauth.HeaderAID, relayauth.HeaderSeq, relayauth.HeaderSig} {
		if len(r.Header.Values(h)) > 0 {
			wire3.Refuse(w, wire3.ReasonIdentityHeadersNotAllowed)
			return
		}
	}
	accessRaw, access, why := accessHeader(r)
	if why != "" {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadEnvelope, Error: why})
		return
	}
	var sid, mac []byte
	var ts uint64
	switch access.Kind {
	case seal.AccessKindCap:
		if len(r.Header.Values(relayauth.HeaderSession)) > 0 || len(r.Header.Values(relayauth.HeaderMAC)) > 0 {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "A send under a delivery credential carries no session; send it without " +
					relayauth.HeaderSession + " and " + relayauth.HeaderMAC + "."})
			return
		}
	default: // seal.AccessKindSession: accessHeader admits no other kind
		var ok bool
		if sid, mac, ts, ok = sessionHeaders(r); !ok {
			wire3.Refuse(w, wire3.ReasonSessionInvalid)
			return
		}
	}
	home, ok := homeHeader(r)
	if !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: relayauth.HeaderHome + " names a hub by its AID, once; fix it or send without it."})
		return
	}
	addr := clientIP(r)
	if access.Kind == seal.AccessKindCap {
		// 1a. Only the address: nothing that depends on the recipient has
		// been looked at, so the answer cannot say anything about it.
		if empty, wait := s.relay.addrFailure.peek(addr, rateAddrFailure); empty {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
				Error: "Too many refused delivery credentials came from this address; send again after the seconds in Retry-After."})
			return
		}
	}
	// 2. The credential, before the body is read.
	var sess *hubSession
	var capBody *seal.CapBody
	var mbox seal.Mbox
	var capHome string // the owner's home when it is a peer hub
	if access.Kind == seal.AccessKindSession {
		var ok bool
		if sess, ok = s.relay.sessions.get(sid, now); !ok || !withinSkew(ts, now, SessionSkew) {
			wire3.Refuse(w, wire3.ReasonSessionInvalid)
			return
		}
		if empty, wait := s.relay.sessionSend.peek(sess.aid, s.sessionRate(sess.aid)); empty {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait})
			return
		}
	} else {
		var ok bool
		if capBody, mbox, capHome, ok = s.capPrecheck(w, r, access, addr, home, now); !ok {
			return
		}
		if empty, wait := s.relay.caps.peek(capKey(capBody), capRate(capBody)); empty {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait})
			return
		}
	}
	// 3. The body: the envelope itself.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.limits.MaxEnvelope))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTooLarge,
				Error: fmt.Sprintf("An envelope is at most %d bytes here; send a smaller one.", s.limits.MaxEnvelope)})
			return
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: "The request body could not be read; send it again."})
		return
	}
	// 4. The envelope.
	outer, err := seal.ParseOuter(body)
	if err != nil {
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
		return
	}
	if !sameOuterAccess(body, accessRaw) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadEnvelope,
			Error: "Outer key 7 of the envelope is not the access in " + HeaderAccess + "; send the same bytes in both."})
		return
	}
	if err := wire3.CheckText("to", outer.To); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	// v030-todo(UX-7): outer key 8 (CUX-H1, core G23): 400 expired and
	// bad_exp, here, before any token is taken.
	digest, err := seal.EnvDigest(body)
	if err != nil {
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
		return
	}
	// 5. The credential, completed.
	if sess != nil {
		if err := relayauth.VerifySessionMAC(sess.key, sid, ts, r.Method, r.URL.RequestURI(), home, body, mac); err != nil {
			if errors.Is(err, relayauth.ErrNUL) {
				wire3.Refuse(w, wire3.ReasonBadRequest)
				return
			}
			wire3.Refuse(w, wire3.ReasonSessionInvalid)
			return
		}
	} else if err := seal.VerifyAccess(access, digest, mbox, outer.To, uint64(now.UnixMilli())); err != nil {
		s.refuseAccess(w, addr)
		return
	}
	// 6. The route. A credential admits only to its owner (step 5): to
	// this hub's mailbox when step 2 found the owner registered here, else
	// to the owner's home, which step 2 resolved (§4.2.6). A first contact
	// names an agent registered here, or one whose home this hub resolves;
	// any other recipient is unknown. A send for another hub is handed to
	// that one hub, after taking the sender's own bucket, and this hub
	// keeps nothing of it (forwardSend, SSR-H13).
	if capHome != "" {
		s.forwardSend(w, r, fwdSend{home: capHome, to: outer.To, envelope: body, access: accessRaw,
			take: bucketTake{s.relay.caps, capKey(capBody), capRate(capBody)}, addr: addr, capBody: capBody})
		return
	}
	if sess != nil {
		registered, err := s.store.agentRegistered(outer.To)
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		if !registered && s.delivering() {
			if to, ok := s.resolveRecipient(r.Context(), outer.To, home); ok {
				s.forwardSend(w, r, fwdSend{home: to, to: outer.To, envelope: body, access: accessRaw,
					take: bucketTake{s.relay.sessionSend, sess.aid, s.sessionRate(sess.aid)}, addr: addr})
				return
			}
		}
		if !registered {
			wire3.Refuse(w, wire3.ReasonRecipientUnknown)
			return
		}
	}
	// 7. The same envelope already waiting: the sender is told its rid, and
	// nothing is taken from any bucket (SSR-W15).
	if rid, ok, err := s.store.RelayQueued(outer.To, digest); err != nil {
		wire3.Internal(w, err)
		return
	} else if ok {
		s.answerRelay(w, RelayDuplicate, rid, outer.To)
		return
	}
	// 7a. Mail from a non-contact is no larger than the share it goes into.
	class, capID := seal.CapClassStranger, []byte(nil)
	if capBody != nil {
		class, capID = capBody.Class, capBody.CapID
	}
	q := s.store.QuotaFor(outer.To)
	if class == seal.CapClassStranger && int64(len(body)) > q.NonContactBytes {
		wire3.Refuse(w, wire3.ReasonTooLargeForStranger)
		return
	}
	// 8. The buckets: each looked at first, then all taken or none.
	var takes []bucketTake
	var refusals []wire3.Reason
	if sess != nil {
		takes = []bucketTake{
			{s.relay.sessionSend, sess.aid, s.sessionRate(sess.aid)},
			{s.relay.firstContact, outer.To, firstContactRate(q)},
		}
		refusals = []wire3.Reason{wire3.ReasonRateLimited, wire3.ReasonStrangersBusy}
	} else {
		takes = []bucketTake{{s.relay.caps, capKey(capBody), capRate(capBody)}}
		refusals = []wire3.Reason{wire3.ReasonRateLimited}
	}
	failed, wait := -1, time.Duration(0)
	for i, t := range takes {
		if empty, w := t.set.peek(t.key, t.rate); empty {
			failed, wait = i, w
			break
		}
	}
	if failed < 0 {
		failed, wait = takeAll(takes)
	}
	if failed >= 0 {
		// A send that raced its own duplicate in is a duplicate, not a
		// refusal.
		if rid, ok, err := s.store.RelayQueued(outer.To, digest); err == nil && ok {
			s.answerRelay(w, RelayDuplicate, rid, outer.To)
			return
		}
		wire3.Write(w, wire3.Refusal{Reason: refusals[failed], RetryAfter: wait})
		return
	}
	// 9, 10. The redelivery count, the kid (409 kid_stale, FS-H1) and the
	// mailbox, in the transaction that writes the row. A refusal gives the
	// tokens back.
	queued, err := s.store.RelayEnqueue(RelayItem{To: outer.To, Envelope: body, Digest: digest,
		Class: class, CapID: capID, Exp: outer.Exp, KID: outer.KID})
	if err != nil || queued.Duplicate {
		refundAll(takes)
	}
	var limited *RedeliveryLimitedError
	switch {
	case err == nil && queued.Duplicate:
		s.answerRelay(w, RelayDuplicate, queued.RID, outer.To)
	case err == nil:
		// 11.
		s.answerRelay(w, RelayQueued, queued.RID, outer.To)
	case errors.As(err, &limited):
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRedeliveryLimited, RetryAfter: limited.Wait})
	case errors.Is(err, ErrKidStale):
		wire3.Refuse(w, wire3.ReasonKidStale)
	case errors.Is(err, ErrMailboxFull):
		wire3.Refuse(w, wire3.ReasonMailboxFull)
	case errors.Is(err, ErrStrangersBusy):
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonStrangersBusy, RetryAfter: StrangersBusyRetry})
	case errors.Is(err, ErrBadEnvelope):
		// An envelope the relay table cannot hold as it is (an outer exp
		// past 2^63 - 1 ms) is the sender's mistake, not this hub's.
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
	default:
		wire3.Internal(w, err)
	}
}

// answerRelay is the 200 of a send: queued or duplicate, the rid, and
// whether the recipient has stopped collecting its mail. recipient_quiet is
// only ever said here, to a send that went through (§4.2.1).
func (s *Server) answerRelay(w http.ResponseWriter, status string, rid []byte, to string) {
	live, _ := s.store.LivenessOf(to)
	writeJSON(w, http.StatusOK, RelaySendResponse{Status: status, RID: wire3.EncodeB64URL(rid), RecipientQuiet: live.Quiet})
}

// refuseAccess answers a refused delivery credential: 403 access_invalid in
// the one body of SSR-H3, then debits the address bucket of step 1a
// (SSR-H3b).
func (s *Server) refuseAccess(w http.ResponseWriter, addr string) {
	wire3.Refuse(w, wire3.ReasonAccessInvalid)
	s.relay.addrFailure.take(addr, rateAddrFailure)
}

// capPrecheck is step 2 of a kind-1 send, before the body is read: the
// capability's body decodes strictly (with a class that has a bucket) and
// has the capability type tag; its owner is registered here and has a
// mailbox key; it was signed under the owner's current epoch, by that key;
// cap_exp is in the window of core §2.1; the owner has not revoked it. A
// refusal is answered by refuseAccess.
//
// An owner registered at a peer hub is checked against the mailbox key its
// home's directory entry or its federated card carries, and against the
// credentials its home refused instead of the revocation table, which only
// the home holds (capPrecheckRemote, §4.2.6, SSR-H14a); home is then that
// peer, and empty for an owner registered here. hint is the sender's
// X-ANet-Home.
//
// Every refusal costs one Ed25519 verification (SSR-H3a): one that comes
// before Cap.sig is checked verifies under equalVerifyKey and throws the
// result away, so that how long the answer takes does not say which check
// refused. Looking the owner up in this hub's database is the same work
// whether or not it is registered.
func (s *Server) capPrecheck(w http.ResponseWriter, r *http.Request, a *seal.Access, addr, hint string, now time.Time) (*seal.CapBody, seal.Mbox, string, bool) {
	refuse := func(equal bool) (*seal.CapBody, seal.Mbox, string, bool) {
		if equal {
			_ = verifyEd25519(equalVerifyKey, a.Cap.Body, a.Cap.Sig)
		}
		s.refuseAccess(w, addr)
		return nil, seal.Mbox{}, "", false
	}
	body, err := seal.UnmarshalCapBody(a.Cap.Body)
	if err != nil || body.Class != seal.CapClassContact && body.Class != seal.CapClassStranger || body.Type != seal.CapType {
		return refuse(true)
	}
	mbox, found, registered, err := s.store.ownerMboxOf(body.Owner)
	if err != nil {
		wire3.Internal(w, err)
		return nil, seal.Mbox{}, "", false
	}
	if !registered && s.delivering() {
		m, home, ok := s.capPrecheckRemote(w, r, a, body, addr, hint, now)
		return body, m, home, ok
	}
	if !found || mbox.Epoch == 0 || body.Epoch != mbox.Epoch || len(mbox.Pub) != ed25519.PublicKeySize {
		return refuse(true)
	}
	if !verifyEd25519(mbox.Pub, a.Cap.Body, a.Cap.Sig) {
		return refuse(false)
	}
	if !capExpOK(body.CapExp, uint64(now.UnixMilli())) {
		return refuse(false)
	}
	revoked, err := s.store.CapRevoked(body.Owner, body.CapID)
	if err != nil {
		wire3.Internal(w, err)
		return nil, seal.Mbox{}, "", false
	}
	if revoked {
		return refuse(false)
	}
	return body, mbox, "", true
}

// capExpOK is the window of core §2.1 seal.VerifyAccess checks cap_exp in:
// now - CapExpGraceMS <= cap_exp <= now + CapExpMaxAheadMS.
func capExpOK(capExp, now uint64) bool {
	lo := uint64(0)
	if now > seal.CapExpGraceMS {
		lo = now - seal.CapExpGraceMS
	}
	hi := now + seal.CapExpMaxAheadMS
	if hi < now {
		hi = math.MaxUint64
	}
	return lo <= capExp && capExp <= hi
}

// capKey is a delivery credential's bucket key: its owner and its id. The id
// is the issuer's choice, so it is keyed under its owner: no issuer can
// share, or drain, another's bucket.
func capKey(c *seal.CapBody) string { return c.Owner + "\x00" + string(c.CapID) }

// capRate is a delivery credential's bucket rate, by its class.
func capRate(c *seal.CapBody) relayRate {
	if c.Class == seal.CapClassContact {
		return rateContactCap
	}
	return rateStrangerCap
}

// sessionRate is the send bucket rate of a session holder: smaller during
// the probation of an account that came in through open registration or a
// sign-up window (SSR-H8).
func (s *Server) sessionRate(aid string) relayRate {
	if _, on := s.store.ProbationUntil(aid); on {
		return rateSessionSendProbation
	}
	return rateSessionSend
}

// envelopeContentType reports whether the request's Content-Type is exactly
// EnvelopeContentType, without parameters.
func envelopeContentType(r *http.Request) bool {
	vs := r.Header.Values("Content-Type")
	if len(vs) != 1 {
		return false
	}
	mt, params, err := mime.ParseMediaType(vs[0])
	return err == nil && mt == EnvelopeContentType && len(params) == 0
}

// accessHeader reads X-ANet-Access: one value, at most MaxAccessHeader
// characters, base64url, and a well-formed access of kind 0 or 1
// (decodeAccessHeader). why says what is wrong, empty when nothing is.
func accessHeader(r *http.Request) (raw []byte, a *seal.Access, why string) {
	vs := r.Header.Values(HeaderAccess)
	switch {
	case len(vs) != 1:
		return nil, nil, "A send carries its access in " + HeaderAccess + ", once; add it and send again."
	case len(vs[0]) > MaxAccessHeader:
		return nil, nil, fmt.Sprintf("%s is longer than %d characters; send the access the envelope carries.", HeaderAccess, MaxAccessHeader)
	}
	raw, err := wire3.DecodeB64URL(HeaderAccess, vs[0])
	if err != nil {
		return nil, nil, HeaderAccess + " is not base64url (no padding, no white space); encode the access that way and send again."
	}
	if a, err = decodeAccessHeader(raw); err != nil {
		return nil, nil, HeaderAccess + " is not an access of kind 0 or 1; send the access outer key 7 of the envelope holds."
	}
	return raw, a, ""
}

// decodeAccessHeader decodes the bytes of X-ANet-Access: the CoreDet
// encoding of a seal.Access and nothing else (no unknown key, one spelling),
// of kind 0 without a capability or a proof, or of kind 1 with a capability
// (a body and a 64-byte signature) and a 64-byte proof. Step 4 checks the
// same bytes again as outer key 7 (seal.ParseOuter).
func decodeAccessHeader(raw []byte) (*seal.Access, error) {
	var a seal.Access
	if err := coredet.UnmarshalStrict(raw, &a); err != nil {
		return nil, err
	}
	if re, err := coredet.Marshal(&a); err != nil || !bytes.Equal(re, raw) {
		return nil, errors.New("not the CoreDet encoding of an access")
	}
	switch a.Kind {
	case seal.AccessKindSession:
		if a.Cap != nil || a.Proof != nil {
			return nil, errors.New("a kind-0 access carries a capability or a proof")
		}
	case seal.AccessKindCap:
		if a.Cap == nil || a.Cap.Body == nil || len(a.Cap.Sig) != seal.SigLen || len(a.Proof) != seal.SigLen {
			return nil, errors.New("a kind-1 access needs a capability and a proof")
		}
	default:
		return nil, fmt.Errorf("access kind %d", a.Kind)
	}
	return &a, nil
}

// sameOuterAccess reports whether outer key 7 of env is, byte for byte, raw
// (core §2.12.1: X-ANet-Access is the same bytes as outer key 7).
func sameOuterAccess(env, raw []byte) bool {
	var fields map[uint64]cbor.RawMessage
	if err := coredet.Unmarshal(env, &fields); err != nil {
		return false
	}
	return bytes.Equal(fields[7], raw)
}

// sessionHeaders reads the session headers of a first contact: X-ANet-Session
// (16 bytes), X-ANet-MAC (32 bytes), both base64url, and X-ANet-TS in
// canonical decimal, each exactly once.
func sessionHeaders(r *http.Request) (sid, mac []byte, ts uint64, ok bool) {
	sidS, ok1 := singleHeader(r, relayauth.HeaderSession)
	macS, ok2 := singleHeader(r, relayauth.HeaderMAC)
	tsS, ok3 := singleHeader(r, relayauth.HeaderTS)
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, 0, false
	}
	var err error
	if sid, err = wire3.DecodeB64URLSize(relayauth.HeaderSession, sidS, relayauth.SessionIDLen); err != nil {
		return nil, nil, 0, false
	}
	if mac, err = wire3.DecodeB64URLSize(relayauth.HeaderMAC, macS, relayauth.SessionMACLen); err != nil {
		return nil, nil, 0, false
	}
	if ts, err = strconv.ParseUint(tsS, 10, 64); err != nil || strconv.FormatUint(ts, 10) != tsS {
		return nil, nil, 0, false
	}
	return sid, mac, ts, true
}

// homeHeader reads X-ANet-Home, the sender's hint of the recipient's hub: at
// most once, and an AID. Empty when there is none.
func homeHeader(r *http.Request) (string, bool) {
	vs := r.Header.Values(relayauth.HeaderHome)
	switch {
	case len(vs) == 0:
		return "", true
	case len(vs) > 1 || !ValidAID(vs[0]):
		return "", false
	}
	return vs[0], true
}

// withinSkew reports whether the unix-ms time ts is within skew of now.
func withinSkew(ts uint64, now time.Time, skew time.Duration) bool {
	if ts > uint64(1)<<62 {
		return false
	}
	d := now.UnixMilli() - int64(ts)
	if d < 0 {
		d = -d
	}
	return d <= skew.Milliseconds()
}

// hRelayPoll returns a page of the caller's own mailbox, from after_id on
// when the request names one, and whether more follows it (FS-H5).
func (s *Server) hRelayPoll(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionPoll, signedBodyLimit)
	if !ok {
		return
	}
	// An empty body asks for everything from the start; anything else is
	// decoded strictly (core CORE-E7).
	var req RelayPollRequest
	if len(a.Body) > 0 {
		if err := wire3.DecodeStrict(a.Body, &req); err != nil {
			wire3.RefuseDecode(w, err)
			return
		}
	}
	if req.AfterID < 0 || req.Limit < 0 {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The members limit and after_id cannot be negative; fix them and send again."})
		return
	}
	// Collecting mail is the liveness signal. Recorded here rather than
	// at a heartbeat endpoint because this is the thing that actually
	// matters: a node that asks for its mail is a node that will do the
	// work, and a node that has stopped asking will not, whatever else it
	// might still be answering.
	s.store.SeenPolling(a.AID)
	msgs, more, err := s.store.RelayPoll(a.AID, req.AfterID, req.Limit, s.limits.PollBudget)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := RelayPollResponse{Messages: make([]RelayEnvelopeView, 0, len(msgs)), More: more}
	for _, m := range msgs {
		out.Messages = append(out.Messages, RelayEnvelopeView{
			ID: m.ID, Envelope: wire3.EncodeB64URL(m.Payload), AcceptedAt: uint64(m.CreatedAt)})
	}
	out.KeyStateNotice, out.KeyStateNoticeError = s.noticeAnswer(a.AID)
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
// (register, profile, visibility, deregister, keys, relay send/poll/ack) or accept only
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

// AgentKELView is the GET /agents/{aid}/kel answer (core §2.12.2): the key
// history this hub holds for aid, base64url (CORE-E5), and whether aid is
// registered here. registered false means the history is the tombstone the
// agent left in departed_kel: it left, its admission was revoked, an
// operator removed it, or it was swept for never collecting its mail; its
// daemon goes back to joining (KEL D-27 row d, hub-payment-privacy §9.1).
type AgentKELView struct {
	AID        string `json:"aid"`
	KEL        string `json:"kel"`
	Registered bool   `json:"registered"`
}

// hAgentKEL publishes the key event log this hub holds for an AID.
//
// A KEL is public by construction — it is a log of key events, each one
// signed by the key it supersedes, and its whole design assumes anyone can
// replay it. Publishing it is not an authorization: holding the KEL lets
// you CHECK signatures, never make them. An agent's own daemon reads its
// record here (KEL D-27) and so does anet identity recover (D-45); a
// receipt or review an agent signed is checked against it.
//
// It answers for the AIDs this hub has a registration record of: an agent
// registered here, one that left (its tombstone, registered false), and
// this hub itself, whose history signs its receipts and notices (the same
// as GET /hub/identity). Anything else is 404 unknown_aid: an agent of
// another hub is read from that hub, or from its directory entry, which
// carries its KEL (sealed-sender §2.9); the key histories of the peer hubs
// this hub pins are GET /hub/kels (KEL H-16).
func (s *Server) hAgentKEL(w http.ResponseWriter, r *http.Request) {
	s.serveAgentKEL(w, r.PathValue("aid"))
}

// serveAgentKEL answers a KEL lookup for aid (hAgentKEL).
func (s *Server) serveAgentKEL(w http.ResponseWriter, aid string) {
	if aid != "" && aid == s.hubAID {
		kel, err := s.ownKEL()
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, AgentKELView{AID: aid, KEL: wire3.EncodeB64URL(kel), Registered: true})
		return
	}
	kel, registered, err := s.store.registrationKEL(aid)
	switch {
	case err != nil:
		wire3.Internal(w, err)
	case kel == nil:
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnknownAID,
			Error: "This hub has no registration of this AID, past or present; ask the hub the agent registers at."})
	default:
		writeJSON(w, http.StatusOK, AgentKELView{AID: aid, KEL: wire3.EncodeB64URL(kel), Registered: registered})
	}
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

// LedgerResponse is GET /agents/{aid}/ledger: the account's entries of the
// ledger window, oldest first (core §2.12.2; hub-payment-privacy PAY-L6).
type LedgerResponse struct {
	AID     string        `json:"aid"`
	Entries []LedgerEntry `json:"entries"`
	// Total and Sum cover every entry of the window, whatever the page;
	// Returned is how many this page lists.
	Total     int    `json:"total"`
	Sum       int64  `json:"sum"`
	Returned  int    `json:"returned"`
	Truncated bool   `json:"truncated,omitempty"`
	Note      string `json:"note,omitempty"`
	// WindowDays is always LedgerWindowDays; OldestSeq is the seq of the
	// earliest entry in the window, 0 when there is none.
	WindowDays uint   `json:"window_days"`
	OldestSeq  uint64 `json:"oldest_seq"`
}

// hLedger serves an account's entries of the ledger window: the newest page
// of them, oldest first, with the window's totals.
//
// The page was capped at 100 with nothing saying so, and an account with
// more than that had no way to know its own history was truncated.
// `anet reconcile` summed the page and compared it against the balance,
// so every busy account reported a discrepancy that was the cap rather
// than the ledger — host-d showed a balance of 866 against entries summing
// to -109.
//
// Total and sum cover the whole window regardless of the page. The window
// is 14 days (window_days) and the entries before it are deleted
// (janitor.go), so the sum is how the balance moved within the window, not
// the balance: oldest_seq says where the window starts, and a supply
// epoch's liability proof (ledger_hw) vouches for the balance at its close.
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
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &limit)
	}
	win, err := s.store.LedgerEntries(a.AID, limit)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := LedgerResponse{AID: a.AID, Entries: win.Entries, Total: win.Total, Sum: win.Sum,
		Returned: len(win.Entries), WindowDays: LedgerWindowDays, OldestSeq: win.OldestSeq}
	if win.Total > len(win.Entries) {
		out.Truncated = true
		out.Note = "entries is the newest page; total and sum cover every entry of the last window_days days. " +
			"Older entries are deleted, so sum is how the balance moved within the window, not the balance."
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
