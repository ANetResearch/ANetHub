package aghub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/tsir"

	"github.com/ANetResearch/ANetHub/internal/version"
)

// Server is the Hub HTTP API over a Store. guest is the guest-mode broker (nil until EnableGuestMode is
// called; anet-hub always calls it at startup, so guest mode is on and routes to any agent with quota>0).
type Server struct {
	store *Store
	guest *guestBroker
	// forwardUnknown, when set (by the application wiring, K207: kernel
	// never imports modules), offers a locally-unknown recipient to
	// federation peers. Returns (accepted, peerHubAID, error).
	forwardUnknown func(toAID, fromAID, kind, interactionID string, payload []byte) (bool, string, error)
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
func (s *Server) SetForwarder(f func(toAID, fromAID, kind, interactionID string, payload []byte) (bool, string, error)) {
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

// NewServer wraps a store.
func NewServer(store *Store) *Server { return &Server{store: store} }

// maxHubBody caps a request body. Registrations carry a KEL, reviews carry a receipt + review + the
// request TaskDoc + the interaction transcript — all small. Relay payloads, however, may now carry inline
// binary ATTACHMENTS (images/media/archives, single attachment ≤ 64 MiB, base64 ≈ +33%), so the cap is
// sized to admit one such payload plus overhead while still bounding a hostile POST. Keep the reverse
// proxy's client_max_body_size (deploy/hub/nginx-hub*.conf) in lockstep with this value.
// maxHubBody caps every relayed body.
//
// Raised with the daemon's control-plane limit so the two agree: a daemon
// that accepts a call it cannot relay has moved the failure from the
// caller's own machine to a stranger's hub, which is the worse place to
// discover it.
//
// A public hub should lower this. It is multi-tenant and the body is
// buffered, so the ceiling is what one caller can make this process hold
// — put a reverse proxy in front with a limit that matches what the
// operator is willing to allocate.
const maxHubBody = 1 << 30 // 1 GiB

// limitBody caps every request body (POSTs read JSON/base64; GETs have none). Defense-in-depth for a
// public deployment — pair it with a reverse proxy (TLS + rate limiting) when exposing the Hub.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxHubBody)
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
const (
	wireVersion       = 1
	wireVersionHeader = "X-ANet-Wire"
)

// wireContract stamps this hub's contract version on every response and
// turns away a caller speaking a newer one.
//
// A newer daemon is the case worth refusing: it may send fields this hub
// will silently drop, and a delegation that half-arrives is worse than one
// that is plainly rejected. An older or absent version is accepted — that
// is every daemon built before this header existed, and they work.
func wireContract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(wireVersionHeader, strconv.Itoa(wireVersion))
		if v := r.Header.Get(wireVersionHeader); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > wireVersion {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf(
						"this hub speaks wire contract %d, the caller speaks %d — upgrade the hub",
						wireVersion, n),
				})
				return
			}
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
	mux.HandleFunc("GET /agents/{aid}/card", s.hAgentCard)
	mux.HandleFunc("GET /agents/{aid}/balance", s.hBalance)
	mux.HandleFunc("GET /agents/{aid}/ledger", s.hLedger)
	mux.HandleFunc("POST /agents/{aid}/visibility", s.hVisibility)
	// The other half of registration: leaving. See deregister.go.
	mux.HandleFunc("POST /agents/{aid}/deregister", s.hDeregister)
	// The three endpoints x402 defines for a facilitator. This hub hosts
	// its own, which the spec permits outright — and for a ledger rail
	// there is nothing to separate from, because the balances are here.
	mux.HandleFunc("GET /x402/supported", s.hX402Supported)
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
	mux.HandleFunc("GET /federation/reviews", s.hFedReviews)
	mux.HandleFunc("GET /agents/{aid}/reputation", s.hReputation)
	mux.HandleFunc("POST /x402/verify", s.hX402Verify)
	mux.HandleFunc("POST /x402/settle", s.hX402Settle)
	// The resource server: pay here, work there. See gateway.go for why
	// this hands back a voucher instead of proxying the call.
	mux.HandleFunc("GET /x402/resource/{aid}/{capability}", s.hX402Resource)
	mux.HandleFunc("GET /graph", s.hGraph)
	mux.HandleFunc("GET /stats", s.hStats)
	// Relay broker (v0.1 centralized transport): send is open (payloads are end-to-end verifiable);
	// poll/ack are KEL-signature-authenticated so only the mailbox owner can read/clear it.
	mux.HandleFunc("POST /relay/send", s.hRelaySend)
	mux.HandleFunc("POST /relay/poll", s.hRelayPoll)
	mux.HandleFunc("POST /relay/ack", s.hRelayAck)
	// Guest mode (访客模式): a no-daemon visitor sends a few REAL messages to configured handler nodes,
	// brokered by the Hub. Always routed; each reports {enabled:false} when guest mode is off (see guest.go).
	mux.HandleFunc("POST /guest/start", s.hGuestStart)
	mux.HandleFunc("POST /guest/send", s.hGuestSend)
	mux.HandleFunc("POST /guest/poll", s.hGuestPoll)
	mux.HandleFunc("POST /guest/end", s.hGuestEnd)
	// Agent-facing onboarding manual (AgentHansa-style): one URL an LLM agent reads to learn how to drive
	// the local `anet` CLI. Injects THIS hub's origin so the copy-paste commands point at the right Hub.
	mux.HandleFunc("GET /llms.txt", s.hLLMs)
	// Researcher directory: a filtered lens over the SAME registry (agents carrying the reserved
	// `research` cap). This is what Research Galaxy publishes into — one ecosystem, one registry, a
	// research sub-view. See web/research.html (client-side fetch of /agents?cap=research).
	mux.HandleFunc("GET /research", s.hResearch)
	// The self-contained web UI (starfield of the real registry). Per-agent multimodal chat is native
	// in the SPA (no separate /chat surface). Other static assets fall through.
	fileSrv := http.FileServer(http.FS(webRoot()))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.hIndex(w, r)
			return
		}
		fileSrv.ServeHTTP(w, r)
	})
	return cors(wireContract(limitBody(mux)))
}

// hIndex serves the Hub SPA (a hand-written, self-contained page whose per-agent chat is natively the
// full Telegram-style multimodal conversation — no injection, no separate chat surface).
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
	out := strings.ReplaceAll(string(b), "{{HUB_URL}}", requestOrigin(r))
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
// hStats returns the headline landing metrics (agents / completed tasks / reviews / avg rating).
func (s *Server) hStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.store.Stats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
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
	writeJSON(w, http.StatusOK, map[string]any{"nodes": agents, "edges": edges})
}

// RegisterRequest is an agent's self-registration: its AgentCard + its KEL (base64 CoreDet-CBOR) + a
// signed challenge proving it holds the AID's key (so a public KEL cannot be replayed by a stranger to
// hijack the registration). Profile fields are optional here — they are usually set later via /profile.
type RegisterRequest struct {
	AID     string   `json:"aid"`
	Name    string   `json:"name"`
	Caps    []string `json:"caps"`
	Summary string   `json:"summary"`
	Readme  string   `json:"readme"`
	Pricing string   `json:"pricing"`
	// GuestMessages is how many guest-mode trial messages a visitor may send this agent (0 = opt out).
	// A nil pointer (field omitted) defaults to guestDefaultQuota — every agent accepts guests unless it
	// explicitly says otherwise.
	GuestMessages *int   `json:"guest_messages"`
	KEL           string `json:"kel"` // base64(identity.MarshalKEL)
	// Signed challenge: sign relayauth.Preimage("register", aid, ts) with the current key.
	TS          uint64 `json:"ts"`
	KeyStateSeq uint64 `json:"key_state_seq"`
	Sig         string `json:"sig"` // base64
	// Card is the agent's own signed statement of what it offers (an ADP
	// AgentCard). The challenge above proves who is calling and covers
	// none of what they said; only this makes Name and Caps attributable
	// to the agent rather than to this hub. Optional — a node running an
	// older build sends none, and still registers.
	Card json.RawMessage `json:"card"`
}

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AID == "" || req.KEL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aid + kel required"})
		return
	}
	kelBytes, err := base64.StdEncoding.DecodeString(req.KEL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kel not base64"})
		return
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
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
	// Proof of key possession: verify the signed challenge against the SUBMITTED KEL (the agent may not
	// be stored yet). This stops anyone who merely knows the public KEL from overwriting a registration.
	if err := verifyChallenge(kel, relayauth.ActionRegister, req.AID, req.TS, req.KeyStateSeq, req.Sig); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "register challenge invalid: " + err.Error()})
		return
	}
	quota := guestDefaultQuota
	if req.GuestMessages != nil {
		quota = *req.GuestMessages
	}
	if quota < 0 {
		quota = 0
	} else if quota > guestMaxQuota {
		quota = guestMaxQuota
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
	firstTime := !s.store.KnowsAgent(req.AID)
	if err := s.store.PutAgent(req.AID, req.Name, req.Caps, quota, kelBytes); err != nil {
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
	if firstTime {
		// A grant on arrival, so a new node can try a paid capability
		// before anyone has funded it. A network where nothing works
		// until an operator notices you is a network nobody evaluates.
		if err := s.store.GrantOnRegistration(req.AID); err != nil {
			log.Printf("hub: registration grant for %s: %v", req.AID, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": req.AID, "status": "registered"})
}

// ProfileRequest updates an agent's self-authored profile. It is authenticated by a signed challenge
// (proves the caller holds the AID's key) verified against the agent's REGISTERED KEL.
type ProfileRequest struct {
	AID         string `json:"aid"`
	Summary     string `json:"summary"`
	Readme      string `json:"readme"`
	Pricing     string `json:"pricing"`
	TS          uint64 `json:"ts"`
	KeyStateSeq uint64 `json:"key_state_seq"`
	Sig         string `json:"sig"` // base64 of a signature over relayauth.Preimage("profile", aid, ts)
}

func (s *Server) hProfile(w http.ResponseWriter, r *http.Request) {
	var req ProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aid required"})
		return
	}
	if err := s.authRelay(relayauth.ActionProfile, RelayAuthRequest{
		AID: req.AID, TS: req.TS, KeyStateSeq: req.KeyStateSeq, Sig: req.Sig,
	}); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.PutProfile(req.AID, req.Summary, req.Readme, req.Pricing); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": req.AID, "status": "profile_updated"})
}

// UploadReviewRequest carries the provider-signed receipt and the requester-signed review (both base64
// CoreDet-CBOR), PLUS the raw interaction content — the signed request TaskDoc bytes and the deliverable
// bytes. The Hub re-hashes the content and checks it against the receipt's request_cid / result_cid, so
// the displayed goal + deliverable are cryptographically bound to what the provider signed.
type UploadReviewRequest struct {
	Receipt     string `json:"receipt"`     // base64(evidence.Receipt.Marshal)
	Review      string `json:"review"`      // base64(evidence.Review.Marshal)
	RequestDoc  string `json:"request_doc"` // base64 of the signed request TaskDoc bytes (Sum == receipt.request_cid)
	Deliverable string `json:"deliverable"` // base64 of the deliverable bytes (Sum == receipt.result_cid)
}

func (s *Server) hUploadReview(w http.ResponseWriter, r *http.Request) {
	var req UploadReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Receipt == "" || req.Review == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt + review required"})
		return
	}
	if req.RequestDoc == "" || req.Deliverable == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request_doc + deliverable required (a review must carry its verified interaction content)"})
		return
	}
	rcBytes, err1 := base64.StdEncoding.DecodeString(req.Receipt)
	rvBytes, err2 := base64.StdEncoding.DecodeString(req.Review)
	docBytes, err3 := base64.StdEncoding.DecodeString(req.RequestDoc)
	delivBytes, err4 := base64.StdEncoding.DecodeString(req.Deliverable)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "receipt/review/content not base64"})
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
	detail, err := s.verify(rc, rv, docBytes, delivBytes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.PutReview(rv, detail); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "store: " + err.Error()})
		return
	}
	// Keep the bytes that were verified, not only what they meant. A peer
	// asking for this review later needs the objects to check for itself;
	// handing it our conclusion would make federated reputation a chain of
	// hubs trusting hubs.
	if err := s.store.PutReviewBlob(rv.InteractionID, rcBytes, rvBytes, docBytes, delivBytes); err != nil {
		log.Printf("hub: review evidence not kept for %s: %v", rv.InteractionID, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"interaction_id": rv.InteractionID, "status": "accepted"})
}

// verify is the heart of the trust model. Two halves, deliberately split:
// what only this Hub can know (has this interaction been rated, are these
// agents registered here) stays here; the interlock itself — same
// interaction, right parties, review anchored to this receipt, content
// hashing to the signed anchors, both signatures live — is
// evidence.VerifyInterlock, so a third party holding the same files
// reaches the same verdict without trusting this Hub.
//
// Any failure ⇒ the review is rejected and never displayed. On success it
// returns the verified, displayable content extracted from those bytes.
func (s *Server) verify(rc *evidence.Receipt, rv *evidence.Review, requestDoc, deliverable []byte) (ReviewDetail, error) {
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

	// Everything else is arithmetic over the objects, and it lives in
	// ANetCore so that anyone holding these files reaches this same
	// verdict without trusting this Hub — which is the whole content of
	// "the Hub cannot fake a rating".
	if err := evidence.VerifyInterlock(rc, rv, requestDoc, deliverable, provKEL, reqKEL); err != nil {
		return zero, err
	}
	return ReviewDetail{
		Goal:        goalFromTaskDoc(requestDoc),
		Deliverable: string(deliverable),
		RequestCID:  rc.RequestCID,
		ResultCID:   rc.ResultCID,
		CompletedAt: rc.CompletedAt,
	}, nil
}

// goalFromTaskDoc re-derives the human-readable goal from the (already CID-verified) request TaskDoc
// bytes. Because those bytes hash to the receipt's signed request_cid, the returned goal is bound to the
// interaction; a decode miss just yields "" (the deliverable still carries the verified content).
func goalFromTaskDoc(docBytes []byte) string {
	var td tsir.TaskDoc
	if err := coredet.Unmarshal(docBytes, &td); err != nil || len(td.Tasks) == 0 {
		return ""
	}
	if b := td.Tasks[0].Intent.Body; b != "" {
		return b
	}
	return td.Tasks[0].Intent.Summary
}

func (s *Server) hAgents(w http.ResponseWriter, r *http.Request) {
	// ?cap= is answered from the capability index rather than by
	// post-filtering a prose search. Same parameter, same comma-OR
	// meaning, two things it can now do that it could not: match a
	// structured id exactly, and match a family by prefix.
	//
	// It does not fall back to the prose search when nothing matches.
	// "who serves cas.put" and "who mentions cas.put" are different
	// questions, and answering the second when asked the first sends work
	// to a provider that will refuse it.
	if capID := strings.TrimSpace(r.URL.Query().Get("cap")); capID != "" {
		agents, err := s.store.FindByCapability(capID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Agents learned from peer hubs answer the same question, and
		// carry the home hub that says where to reach them. Local first:
		// an agent this hub can deliver to directly is a better answer
		// than one behind another hop.
		agents = append(agents, s.federatedAgents(capID)...)
		if agents == nil {
			agents = []AgentView{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
		return
	}
	agents, err := s.store.ListAgents(r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if agents == nil {
		agents = []AgentView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// --- relay broker handlers ---

// RelaySendRequest posts one message into a recipient's mailbox. The payload is opaque, base64-encoded
// bytes the recipient verifies end-to-end (a signed delegation or a provider-signed result); the Hub
// only checks the recipient is registered and moves the bytes.
type RelaySendRequest struct {
	ToAID         string `json:"to_aid"`
	FromAID       string `json:"from_aid"`
	Kind          string `json:"kind"` // "delegate" | "message" | "result"
	InteractionID string `json:"interaction_id"`
	Payload       string `json:"payload"` // base64
}

func (s *Server) hRelaySend(w http.ResponseWriter, r *http.Request) {
	var req RelaySendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ToAID == "" || req.Payload == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "to_aid + payload required"})
		return
	}
	if req.Kind != RelayKindDelegate && req.Kind != RelayKindResult && req.Kind != RelayKindMessage {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind must be delegate|result|message"})
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload not base64"})
		return
	}
	// The recipient must be a registered agent, so the relay only holds mail for real mailboxes.
	// A recipient unknown HERE may still live on a federated peer (K208 delivery federation).
	if _, err := s.store.AgentKEL(req.ToAID); err != nil {
		if s.forwardUnknown != nil {
			if ok, peer, ferr := s.forwardUnknown(req.ToAID, req.FromAID, req.Kind, req.InteractionID, payload); ok {
				writeJSON(w, http.StatusOK, map[string]any{"status": "forwarded", "via_hub": peer})
				return
			} else if ferr != nil {
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
	// send would be asserting that it is not. Saying what it knows is the
	// honest middle: accepted, and here is the one fact you would want.
	live, _ := s.store.LivenessOf(req.ToAID)
	id, err := s.store.RelayEnqueue(req.ToAID, req.FromAID, req.Kind, req.InteractionID, payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := map[string]any{"id": id, "status": "queued"}
	if live.Quiet {
		out["recipient_quiet"] = true
		out["warning"] = fmt.Sprintf(
			"queued, but %s has not collected its mail for %s — it may not be running",
			req.ToAID, live.QuietFor)
	}
	writeJSON(w, http.StatusOK, out)
}

// RelayAuthRequest carries the signed challenge that authenticates a mailbox owner (poll/ack). The
// caller signs relayauth.Preimage(action, aid, ts) with its KEL current key.
type RelayAuthRequest struct {
	AID         string  `json:"aid"`
	TS          uint64  `json:"ts"` // unix millis (bounded skew, replay window)
	KeyStateSeq uint64  `json:"key_state_seq"`
	Sig         string  `json:"sig"` // base64
	Limit       int     `json:"limit,omitempty"`
	IDs         []int64 `json:"ids,omitempty"`
}

// relayMessageView is the wire shape of a mailbox message (payload base64).
type relayMessageView struct {
	ID            int64  `json:"id"`
	FromAID       string `json:"from_aid"`
	Kind          string `json:"kind"`
	InteractionID string `json:"interaction_id"`
	Payload       string `json:"payload"` // base64
	CreatedAt     string `json:"created_at"`
}

func (s *Server) hRelayPoll(w http.ResponseWriter, r *http.Request) {
	var req RelayAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.authRelay(relayauth.ActionPoll, req); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	// Collecting mail is the liveness signal. Recorded here rather than
	// at a heartbeat endpoint because this is the thing that actually
	// matters: a node that asks for its mail is a node that will do the
	// work, and a node that has stopped asking will not, whatever else it
	// might still be answering.
	s.store.SeenPolling(req.AID)
	msgs, err := s.store.RelayPoll(req.AID, req.Limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]relayMessageView, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, relayMessageView{
			ID: m.ID, FromAID: m.FromAID, Kind: m.Kind, InteractionID: m.InteractionID,
			Payload: base64.StdEncoding.EncodeToString(m.Payload), CreatedAt: m.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

func (s *Server) hRelayAck(w http.ResponseWriter, r *http.Request) {
	var req RelayAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if err := s.authRelay(relayauth.ActionAck, req); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	n, err := s.store.RelayAck(req.AID, req.IDs)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"acked": n})
}

// authRelay verifies a mailbox owner's signed challenge against its REGISTERED KEL, within the replay
// window. On success the caller provably controls req.AID and may read/clear that mailbox (or edit its
// profile). Used for poll/ack/profile — all of which act on an already-registered agent.
func (s *Server) authRelay(action string, req RelayAuthRequest) error {
	return s.store.VerifyAgentChallenge(action, req.AID, req.TS, req.KeyStateSeq, req.Sig)
}

// VerifyAgentChallenge authenticates a signed action challenge from a
// REGISTERED agent. Exported so sibling hub modules (taskboard, federation)
// share one auth scheme without re-implementing it.
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
	return identity.VerifyObject(kel, aid, keyStateSeq, ts, relayauth.Preimage(action, aid, ts), sig)
}

func (s *Server) hAgent(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	av, reviews, err := s.store.GetAgent(aid)
	if err != nil {
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
// browser session/cookie: state-changing endpoints authenticate per-request via KEL signatures
// (register/profile/relay poll+ack) or accept only self-verifying evidence (reviews, relayed payloads),
// so there is no ambient authority for a cross-origin page to abuse. `relay/send` is intentionally
// unauthenticated (a mailbox drop-box); the payload is end-to-end verifiable, so the worst a stranger can
// do is enqueue bytes the recipient drops. When exposing a self-hosted Hub to the internet, front it with
// a reverse proxy for TLS + rate limiting (the body size is already capped, see limitBody).
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
	aid := r.PathValue("aid")
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
	kel, err := s.store.AgentKEL(aid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"aid": aid,
		"kel": base64.StdEncoding.EncodeToString(kel),
	})
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

// hLedger explains a balance. Public, like the balance: an account on a
// ledger somebody else keeps is exactly the thing its owner must be able
// to audit without asking permission.
func (s *Server) hLedger(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.LedgerEntries(r.PathValue("aid"), 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": r.PathValue("aid"), "entries": entries})
}

// hVisibility records how far an agent is willing to be published.
//
// Authenticated with the same signed challenge as everything else an
// agent says about itself: this decides whether other hubs learn you
// exist, and a setting anyone could change for you is not a setting.
func (s *Server) hVisibility(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	var req struct {
		Visibility  string `json:"visibility"`
		TS          uint64 `json:"ts"`
		KeyStateSeq uint64 `json:"key_state_seq"`
		Sig         string `json:"sig"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	kelBytes, err := s.store.AgentKEL(aid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := verifyChallenge(kel, relayauth.ActionProfile, aid, req.TS, req.KeyStateSeq, req.Sig); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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
