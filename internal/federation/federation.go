// Package federation implements K208 delivery federation (集连, sub-plane A):
// hub-to-hub forwarding of sealed envelopes. The hub signs the
// ForwardEnvelope with its own AID (hubid) — that signature means "this flow
// passed my quota and policy checks", never content endorsement. Since
// forward v2 (A2A-DESIGN §3.9) the envelope names only the destination:
// the sender, the message kind and the interaction are inside the sealed
// payload and are neither forwarded nor stored by either hub.
package federation

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"
	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/seamerr"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// MaxHop bounds transit (K208 §4.2).
const MaxHop = 3

// DedupeWindow is the payload-CID idempotency window (K208: 7 days).
const DedupeWindow = 7 * 24 * time.Hour

// Peer is one statically configured federation peer (K208 v0.1: no hub
// auto-discovery).
type Peer struct {
	AID      string `json:"aid"`
	Endpoint string `json:"endpoint"` // e.g. "https://hub.example.org"
}

// Config is federation.json in the hub data dir; absent file = federation off.
type Config struct {
	Delivery string `json:"delivery"` // "off" | "allowlist"
	// Discovery is the second sub-plane and switches independently
	// (K208 §0): delivery is federated by default, discovery by choice. A
	// hub may carry a peer's traffic without also publishing its
	// directory, and those are genuinely different decisions.
	Discovery string `json:"discovery"` // "off" | "allowlist"
	// Home is this hub's own public endpoint, sent as the routing hint on
	// every card it serves. A card without one tells a peer who exists
	// and not where to reach them.
	Home  string `json:"home"`
	Peers []Peer `json:"peers"`
	// Witness controls whether this hub pins its peers' issuance chain
	// heads. Absent means on.
	//
	// Default on because it costs one HTTP request per peer per interval
	// and it is the only thing that makes a peer's credit supply auditable
	// by anyone other than that peer. A hub that federates has already
	// decided to have a relationship with these peers; holding a signed
	// record of what their ledger looked like is part of what that
	// relationship is worth.
	//
	// Set "off" to disable. An operator who does not want to store
	// statements about other people's ledgers, or who does not want their
	// own hub's signature appearing on somebody else's audit trail, has a
	// legitimate reason to decline.
	Witness string `json:"witness,omitempty"` // "" | "on" | "off"
}

// WitnessEnabled reports whether this hub pins its peers' chain heads.
func (c Config) WitnessEnabled() bool {
	return c.Witness != "off" && len(c.Peers) > 0
}

// LoadConfig reads dir/federation.json (absent → off).
func LoadConfig(dir string) (Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, "federation.json"))
	if os.IsNotExist(err) {
		return Config{Delivery: "off"}, nil
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("federation.json: %w", err)
	}
	if c.Delivery == "" {
		c.Delivery = "off"
	}
	return c, nil
}

// LocalDelivery is what federation needs from the hub kernel — wired by the
// application, so this module never imports the kernel's internals.
//
// Enqueue receives only the destination and the sealed envelope. It
// returns an error wrapping ErrMailboxFull when the destination's quota is
// reached, and one wrapping ErrBadEnvelope when the bytes are not a sealed
// envelope for the destination.
type LocalDelivery interface {
	HasAgent(aid string) bool
	Enqueue(toAID string, envelope []byte) (int64, error)
}

// ErrMailboxFull reports a destination mailbox at its quota, on this hub
// (from LocalDelivery.Enqueue, answered 507 MAILBOX_FULL) or at a peer
// (from TryForward, after the peer answered 507).
var ErrMailboxFull error = &seamError{msg: "federation: destination mailbox full", kind: seamMailboxFull}

// seamError is a federation sentinel that the hub kernel also recognises
// as the matching internal/seamerr sentinel, through errors.Is, without
// referring to this package.
//
// The kernel tests the errors its federation hooks return in code that
// every build links. When it named federation.ErrMailboxFull there, a hub
// built with -tags no_federation still linked federation symbols, which
// the subtractive-tag symbol check forbids (A2A-DESIGN §16). The value is
// a pointer to a constant composite literal so that it is initialised
// statically: an initialiser that read another package's variable would
// be run by this package's init function, and a no_federation build would
// then link that function because the kernel imports this package.
type seamError struct {
	msg  string
	kind int
}

const (
	seamMailboxFull = iota + 1
	seamNoKeys
)

func (e *seamError) Error() string { return e.msg }

// Is reports the kernel sentinel of the same meaning as equal.
func (e *seamError) Is(target error) bool {
	switch e.kind {
	case seamMailboxFull:
		return target == seamerr.ErrMailboxFull
	case seamNoKeys:
		return target == seamerr.ErrNoKeys
	}
	return false
}

// ErrBadEnvelope reports a payload that is not a sealed envelope for the
// destination.
var ErrBadEnvelope = errors.New("federation: payload is not a sealed envelope for the destination")

// ForwardVersion is the /fed/v1/forward envelope version this build
// speaks. Version 2 removed from_aid, kind and interaction_id from the
// envelope and from its signature preimage. A version-1 envelope is
// refused with VERSION_UNSUPPORTED; there is no fallback, because a v1
// peer forwards plaintext payloads with sender metadata that this hub
// must not store.
const ForwardVersion = 2

// Envelope is the K208 §4.2 ForwardEnvelope, version 2: the destination,
// the sealed envelope and the routing fields that loop and hop checks
// need. Nothing about the sender is in it.
type Envelope struct {
	V            uint64   `json:"v"`
	OriginHubAID string   `json:"origin_hub_aid"`
	DestAID      string   `json:"dest_aid"`
	Payload      string   `json:"payload"` // base64 of the sealed envelope
	PayloadCID   string   `json:"payload_cid"`
	Hop          uint64   `json:"hop"`
	SeenHubs     []string `json:"seen_hubs"`
	TS           uint64   `json:"ts"`
	KeyStateSeq  uint64   `json:"key_state_seq"`
	Sig          string   `json:"sig"` // base64, origin hub KEL signature
}

// preimage is the CoreDet-CBOR canonical bytes the hub signature covers
// (_CONVENTIONS §2/§4: int keys, sig outside, arrays author-ordered).
// Keys 4, 5 and 6 (from_aid, kind, interaction_id in v1) are retired and
// not reused.
func (e *Envelope) preimage(payload []byte) ([]byte, error) {
	seen := make([]any, 0, len(e.SeenHubs))
	for _, h := range e.SeenHubs {
		seen = append(seen, h)
	}
	m := map[uint64]any{
		1: e.V, 2: e.OriginHubAID, 3: e.DestAID,
		7: payload, 8: e.PayloadCID, 9: e.Hop, 11: e.TS,
	}
	if len(seen) > 0 {
		m[10] = seen
	}
	return coredet.Marshal(m)
}

// Service is one hub's federation face.
type Service struct {
	cfg     Config
	id      *hubid.Identity
	local   LocalDelivery
	dir     Directory
	keys    KeySource
	db      *sql.DB
	http    *http.Client
	witness Witness
	// maxEnvelope bounds a forwarded envelope; the forward body cap is
	// derived from it. Set by SetMaxEnvelope to the kernel's limit.
	maxEnvelope int64
	// replay remembers accepted /fed/v2/keys request signatures.
	replay *replayGuard
	// round counts sync passes, so a full re-read can be scheduled
	// without a second timer. Touched only from the sync loop.
	round int
	// a2aStreamStatus is each peer's last HTTP status on /fed/v2/cards,
	// so that a peer not yet upgraded is logged once rather than every
	// round. Touched only from the sync loop.
	a2aStreamStatus map[string]int
	// kelFetches is each peer's first fetch of its KEL (peerKEL), by
	// peer AID, under kelFetchesMu.
	kelFetchesMu sync.Mutex
	kelFetches   map[string]*peerKELFetch
}

// peerKELFetch serializes the fetches of one peer's KEL and remembers how
// the last ones ended.
type peerKELFetch struct {
	mu      sync.Mutex // held for the fetch
	ended   time.Time  // when the last fetch ended
	err     error      // how it failed; nil when it pinned
	refused time.Time  // zero, or when the peer last served a KEL that does not prove its AID
}

// testHookPeerKELAsked, when a test sets it, is called by each use of a
// peer's KEL that found none pinned, once it has noted when it asked and
// before it waits for the fetch in progress, if any.
var testHookPeerKELAsked func()

// peerKELRetry is how long after the peer served a KEL that does not prove
// its AID the next fetch waits.
const peerKELRetry = time.Minute

// errUnprovenPeerKEL is a fetched KEL that does not replay to the peer's
// AID (provenPeerKEL).
var errUnprovenPeerKEL = errors.New("does not prove the peer's AID")

// SetDirectory wires the discovery sub-plane. Separate from New because
// the two sub-planes switch independently and a hub running only delivery
// should not have to supply a directory it will never serve.
func (s *Service) SetDirectory(d Directory) { s.dir = d }

func New(dir string, cfg Config, id *hubid.Identity, local LocalDelivery) (*Service, error) {
	db, err := sql.Open("sqlite", filepath.Join(dir, "federation.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS fed_dedupe (payload_cid TEXT PRIMARY KEY, ts INTEGER NOT NULL);
-- Each accepted forward prunes entries older than DedupeWindow; without this
-- the DELETE reads a week of payload CIDs per message (ANet docs/notes/0036).
CREATE INDEX IF NOT EXISTS idx_fed_dedupe_ts ON fed_dedupe(ts);
CREATE TABLE IF NOT EXISTS fed_peer_kel (aid TEXT PRIMARY KEY, kel BLOB NOT NULL, fetched_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_cursor (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_review_cursor (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_cursor_v2 (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
`); err != nil {
		db.Close()
		return nil, err
	}
	if err := dropUnprovenPeerKELs(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Service{cfg: cfg, id: id, local: local, db: db,
		http:        &http.Client{Timeout: 10 * time.Second},
		maxEnvelope: defaultMaxEnvelope, replay: newReplayGuard(),
		a2aStreamStatus: map[string]int{}, kelFetches: map[string]*peerKELFetch{}}, nil
}

// defaultMaxEnvelope matches the kernel's default envelope limit
// (A2A-DESIGN §3.7).
const defaultMaxEnvelope = 96 << 20

// SetMaxEnvelope aligns the forward body cap with the kernel's envelope
// limit, so that an envelope this hub's own senders may send is not
// refused by the peers it is forwarded to, or the reverse.
func (s *Service) SetMaxEnvelope(n int64) {
	if n > 0 {
		s.maxEnvelope = n
	}
}

// forwardBodyLimit is the largest forward request: the base64 of the
// largest envelope plus room for the rest of the JSON.
func (s *Service) forwardBodyLimit() int64 {
	return (s.maxEnvelope+2)/3*4 + 64<<10
}

func (s *Service) Close() error { return s.db.Close() }

// Enabled reports whether delivery federation is on.
func (s *Service) Enabled() bool { return s.cfg.Delivery != "off" && len(s.cfg.Peers) > 0 }

// PeerAIDs is the hubs this one is configured to talk to.
//
// Used to answer "whose ledgers will you clear against" on
// /x402/supported. Gated on the same switch SettleAtPeer is gated on, so
// the list never advertises a network a settlement would then be refused
// for.
func (s *Service) PeerAIDs() []string {
	if !s.DiscoveryEnabled() && !s.Enabled() {
		return nil
	}
	out := make([]string, 0, len(s.cfg.Peers))
	for _, p := range s.cfg.Peers {
		out = append(out, p.AID)
	}
	return out
}

// PeerEndpoint is where a peer hub can be reached, or empty if it is not
// a peer of this one.
func (s *Service) PeerEndpoint(aid string) string {
	if p := s.peer(aid); p != nil {
		return p.Endpoint
	}
	return ""
}

func (s *Service) peer(aid string) *Peer {
	for i := range s.cfg.Peers {
		if s.cfg.Peers[i].AID == aid {
			return &s.cfg.Peers[i]
		}
	}
	return nil
}

// peerKEL returns the pinned KEL for a peer, fetching it from the peer's
// /hub/identity on first contact (pin-on-first-fetch; rotation re-fetch is a
// registered follow-up).
//
// A fetched KEL is pinned only when it replays to the configured peer AID
// (provenPeerKEL). The "aid" the peer serves beside it is a claim; the
// replay is the proof, as at every other place a KEL enters this tree.
// Without it a peer, or anyone in the middle of an http:// endpoint on the
// first fetch, could have this hub pin and republish someone else's key
// history under the peer's AID, and every later check of that peer's
// signatures would fail against it until an operator edited the database
// [redteam:F34].
//
// A KEL that is not pinned is fetched again on the next use, and a use can
// be an unauthenticated request (GET /agents/{peer}/kel on the kernel, a
// repeated /x402/settle whose receipt the peer signed). So the fetches of
// one peer's KEL are made one at a time, a use that waited for a fetch
// that failed gets its failure rather than fetching again, and after the
// peer served a KEL that does not prove its AID (a peer, or someone in the
// middle of an http:// endpoint, serving somebody else's KEL, or the
// peer's own with garbage after it) the next fetch waits peerKELRetry.
// Otherwise each such request was an outbound fetch and a replay of
// whatever came back [redteam:F34]. A fetch that failed on the way (the
// peer down, a non-200) holds nothing off: the next use after it tries
// again, so a merchant's retry after the peer is back completes.
func (s *Service) peerKEL(p *Peer) ([]identity.SignedEvent, error) {
	if kel, err := s.pinnedPeerKEL(p.AID); err == nil || err != sql.ErrNoRows {
		return kel, err
	}
	s.kelFetchesMu.Lock()
	f := s.kelFetches[p.AID]
	if f == nil {
		f = &peerKELFetch{}
		s.kelFetches[p.AID] = f
	}
	s.kelFetchesMu.Unlock()
	asked := time.Now()
	if testHookPeerKELAsked != nil {
		testHookPeerKELAsked()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Pinned while this call waited for another's fetch.
	if kel, err := s.pinnedPeerKEL(p.AID); err == nil || err != sql.ErrNoRows {
		return kel, err
	}
	if f.err != nil && f.ended.After(asked) {
		return nil, f.err // the fetch this call waited for
	}
	if wait := peerKELRetry - time.Since(f.refused); !f.refused.IsZero() && wait > 0 {
		return nil, fmt.Errorf("peer %s's key history is not pinned: it last served one that %v; next fetch in %s",
			p.AID, errUnprovenPeerKEL, wait.Round(time.Second))
	}
	kel, err := s.fetchPeerKEL(p)
	f.ended, f.err = time.Now(), err
	switch {
	case err == nil:
		f.refused = time.Time{}
	case errors.Is(err, errUnprovenPeerKEL):
		f.refused = f.ended
	}
	return kel, err
}

// pinnedPeerKEL is the KEL pinned for peer aid, or sql.ErrNoRows.
func (s *Service) pinnedPeerKEL(aid string) ([]identity.SignedEvent, error) {
	var blob []byte
	if err := s.db.QueryRow(`SELECT kel FROM fed_peer_kel WHERE aid=?`, aid).Scan(&blob); err != nil {
		return nil, err
	}
	return identity.UnmarshalKEL(blob)
}

// fetchPeerKEL fetches p's KEL from its /hub/identity and pins it when it
// replays to p.AID.
func (s *Service) fetchPeerKEL(p *Peer) ([]identity.SignedEvent, error) {
	resp, err := s.http.Get(p.Endpoint + "/hub/identity")
	if err != nil {
		return nil, fmt.Errorf("peer kel fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer kel fetch: %s answered %s", p.Endpoint+"/hub/identity", resp.Status)
	}
	var out struct{ AID, KEL string }
	if err := json.NewDecoder(io.LimitReader(resp.Body, peerIdentityLimit)).Decode(&out); err != nil {
		return nil, err
	}
	if out.AID != p.AID {
		return nil, fmt.Errorf("peer identity mismatch: served %s, configured %s", out.AID, p.AID)
	}
	blob, err := base64.StdEncoding.DecodeString(out.KEL)
	if err != nil {
		return nil, err
	}
	kel, err := provenPeerKEL(blob, p.AID)
	if err != nil {
		return nil, fmt.Errorf("peer %s served a key history that %v; not pinned: %w", p.AID, err, errUnprovenPeerKEL)
	}
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO fed_peer_kel (aid, kel, fetched_at) VALUES (?,?,?)`,
		p.AID, blob, time.Now().UnixMilli()); err != nil {
		return nil, err
	}
	return kel, nil
}

// peerIdentityLimit bounds a peer's /hub/identity answer, which is an AID
// and a KEL.
const peerIdentityLimit = 1 << 20

// provenPeerKEL decodes a peer hub's KEL and checks that it replays to aid,
// the AID this hub is configured to peer with.
//
// It is decoded under the caps every sender applies to a KEL
// (seal.ParseKEL), and the AID is checked on the inception first: it is
// the icp's, and costs one verification, where replaying all of a KEL that
// is somebody else's costs one per event.
func provenPeerKEL(blob []byte, aid string) ([]identity.SignedEvent, error) {
	kel, err := seal.ParseKEL(blob)
	if err != nil {
		return nil, fmt.Errorf("does not decode: %w", err)
	}
	if icp, err := identity.Replay(kel[:1]); err != nil || icp[0].AID != aid {
		if err != nil {
			return nil, fmt.Errorf("does not replay: %v", err)
		}
		return nil, fmt.Errorf("replays to %s, not to %s", icp[0].AID, aid)
	}
	states, err := identity.Replay(kel)
	if err != nil || len(states) == 0 {
		return nil, fmt.Errorf("does not replay: %v", err)
	}
	if got := states[len(states)-1].AID; got != aid {
		return nil, fmt.Errorf("replays to %s, not to %s", got, aid)
	}
	return kel, nil
}

// dropUnprovenPeerKELs deletes pinned peer KELs that do not replay to the
// AID they are pinned under: pins written before peerKEL checked. The next
// use of that peer fetches its KEL again, and pins it only if it proves
// the peer's AID.
func dropUnprovenPeerKELs(db *sql.DB) error {
	rows, err := db.Query(`SELECT aid, kel FROM fed_peer_kel`)
	if err != nil {
		return err
	}
	var bad []string
	for rows.Next() {
		var aid string
		var blob []byte
		if err := rows.Scan(&aid, &blob); err != nil {
			rows.Close()
			return err
		}
		if _, err := provenPeerKEL(blob, aid); err != nil {
			log.Printf("hub: federation: dropping the pinned key history of peer %s, which %v", aid, err)
			bad = append(bad, aid)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, aid := range bad {
		if _, err := db.Exec(`DELETE FROM fed_peer_kel WHERE aid=?`, aid); err != nil {
			return err
		}
	}
	return nil
}

// ---- inbound ----

// Handler serves the federation routes: /fed/v1/forward, /fed/v1/cards,
// /fed/v1/reviews, /fed/v2/keys/{aid} and /fed/v2/cards.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fed/v1/forward", s.hForward)
	mux.HandleFunc("GET /fed/v1/cards", s.hCards)
	mux.HandleFunc("GET /fed/v1/reviews", s.hFedReviewStream)
	mux.HandleFunc("GET /fed/v2/keys/{aid}", s.hKeys)
	// The A2A card stream (A2A-DESIGN §10.6). /fed/v1/cards stays until
	// every peer reads v2.
	mux.HandleFunc("GET /fed/v2/cards", s.hA2ACards)
	return mux
}

func fedErr(w http.ResponseWriter, code int, label string, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": label, "detail": detail})
}

func (s *Service) hForward(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "federation disabled")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.forwardBodyLimit()))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			fedErr(w, http.StatusRequestEntityTooLarge, "TOO_LARGE",
				fmt.Sprintf("forward body exceeds %d bytes", s.forwardBodyLimit()))
			return
		}
		fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		return
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		return
	}
	if env.V != ForwardVersion {
		fedErr(w, http.StatusBadRequest, "VERSION_UNSUPPORTED", fmt.Sprintf(
			"this hub accepts forward envelope v%d only (anet-hub wire 2); the origin hub sent v%d "+
				"and must be upgraded before it can forward here", ForwardVersion, env.V))
		return
	}
	peer := s.peer(env.OriginHubAID)
	if peer == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "origin hub not in peer table")
		return
	}
	if env.Hop > MaxHop {
		fedErr(w, http.StatusBadRequest, "HOP_EXCEEDED", "")
		return
	}
	for _, h := range env.SeenHubs {
		if h == s.id.AID {
			fedErr(w, http.StatusBadRequest, "HOP_EXCEEDED", "loop: this hub already relayed the envelope")
			return
		}
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", "payload not base64")
		return
	}
	// The body cap above leaves room for the JSON around the payload, so
	// the envelope itself is checked against the exact limit here, the
	// same limit /relay/send applies to a local sender.
	if int64(len(payload)) > s.maxEnvelope {
		fedErr(w, http.StatusRequestEntityTooLarge, "TOO_LARGE",
			fmt.Sprintf("envelope is %d bytes, this hub accepts at most %d", len(payload), s.maxEnvelope))
		return
	}
	cid, err := anetcid.SumRaw(payload)
	if err != nil || cid != env.PayloadCID {
		fedErr(w, http.StatusBadRequest, "MALFORMED", "payload_cid mismatch")
		return
	}
	kel, err := s.peerKEL(peer)
	if err != nil {
		fedErr(w, http.StatusBadGateway, "POLICY_REFUSED", "peer kel unavailable: "+err.Error())
		return
	}
	pre, err := env.preimage(payload)
	if err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		return
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", "sig not base64")
		return
	}
	if err := identity.VerifyObject(kel, env.OriginHubAID, env.KeyStateSeq, env.TS, pre, sig); err != nil {
		fedErr(w, http.StatusUnauthorized, "INVALID_SIGNATURE", err.Error())
		return
	}
	// The destination check runs before anything is written to
	// fed_dedupe. UNKNOWN_DESTINATION is a statement about this instant
	// — the recipient is not registered here right now — not about the
	// payload, and the recipient may register a moment later. Recording
	// the CID for a refused forward would make the 7-day window swallow
	// every subsequent legitimate redelivery of the same bytes as
	// DUPLICATE, with both hubs seeing a 2xx and no message arriving.
	if !s.local.HasAgent(env.DestAID) {
		fedErr(w, http.StatusNotFound, "UNKNOWN_DESTINATION", env.DestAID)
		return
	}
	// Idempotency: second delivery of the same payload is a success
	// no-op. The claim is taken before the enqueue rather than after,
	// because INSERT OR IGNORE on the primary key is the only mutual
	// exclusion available here — two concurrent deliveries of one CID
	// would otherwise both pass the check and both enqueue. The cost is
	// that the claim and the enqueue cannot be one transaction (the
	// mailbox is the hub kernel's store, reached through the
	// LocalDelivery seam, not this database), so a failed enqueue has to
	// release the claim explicitly below.
	res, err := s.db.Exec(`INSERT OR IGNORE INTO fed_dedupe (payload_cid, ts) VALUES (?,?)`, env.PayloadCID, time.Now().UnixMilli())
	if err != nil {
		// Accepting without a durable claim would turn the peer's retry
		// into a second delivery, so refuse and let it retry instead.
		fedErr(w, http.StatusServiceUnavailable, "POLICY_REFUSED", "dedupe store unavailable: "+err.Error())
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusOK, map[string]string{"status": "DUPLICATE"})
		return
	}
	if _, err := s.local.Enqueue(env.DestAID, payload); err != nil {
		// Nothing was delivered, so the claim must not outlive the
		// attempt; otherwise the peer's retry is answered DUPLICATE and
		// the payload is lost.
		_, _ = s.db.Exec(`DELETE FROM fed_dedupe WHERE payload_cid=?`, env.PayloadCID)
		switch {
		case errors.Is(err, ErrMailboxFull):
			fedErr(w, http.StatusInsufficientStorage, "MAILBOX_FULL", err.Error())
		case errors.Is(err, ErrBadEnvelope):
			fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		default:
			fedErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		}
		return
	}
	_, _ = s.db.Exec(`DELETE FROM fed_dedupe WHERE ts < ?`, time.Now().Add(-DedupeWindow).UnixMilli())
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// ---- egress ----

// TryForward offers a locally-undeliverable sealed envelope to each peer
// in order; the first 202 wins. 404 means "not my agent" and the walk
// continues. A peer answering 507 ends the walk with an error wrapping
// ErrMailboxFull: the destination lives there and its mailbox is full.
func (s *Service) TryForward(destAID string, envelope []byte) (bool, string, error) {
	if !s.Enabled() {
		return false, "", nil
	}
	payload := envelope
	cid, err := anetcid.SumRaw(payload)
	if err != nil {
		return false, "", err
	}
	env := Envelope{
		V: ForwardVersion, OriginHubAID: s.id.AID, DestAID: destAID,
		Payload:    base64.StdEncoding.EncodeToString(payload),
		PayloadCID: cid, Hop: 1, SeenHubs: []string{s.id.AID}, TS: uint64(time.Now().UnixMilli()),
	}
	pre, err := env.preimage(payload)
	if err != nil {
		return false, "", err
	}
	sig, seq := s.id.Sign(pre)
	env.Sig, env.KeyStateSeq = base64.StdEncoding.EncodeToString(sig), seq

	body, _ := json.Marshal(env)
	var lastErr error
	for _, p := range s.cfg.Peers {
		resp, err := s.http.Post(p.Endpoint+"/fed/v1/forward", "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		code := resp.StatusCode
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		switch code {
		case http.StatusAccepted, http.StatusOK: // queued or idempotent duplicate
			return true, p.AID, nil
		case http.StatusNotFound:
			continue
		case http.StatusInsufficientStorage:
			return false, "", fmt.Errorf("%w at peer %s: %s", ErrMailboxFull, p.AID, strings.TrimSpace(string(detail)))
		default:
			// The peer's own explanation is kept: a VERSION_UNSUPPORTED
			// from a peer that has not been upgraded to forward v2 is the
			// case an operator most needs to read.
			lastErr = fmt.Errorf("peer %s: HTTP %d: %s", p.AID, code, strings.TrimSpace(string(detail)))
		}
	}
	return false, "", lastErr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// test seams (kept in the main file so the preimage and CID rules stay in
// one place; no behavioral surface).
func sumRawForTest(b []byte) (string, error) { return anetcid.SumRaw(b) }
func nowMillisForTest() uint64               { return uint64(time.Now().UnixMilli()) }

// ---- sub-plane B: discovery federation (K208 §5) ----

// Directory is what discovery federation needs from the hub kernel. Kept
// separate from LocalDelivery because the two sub-planes switch
// independently, and a hub running only one should not have to implement
// the other's seam.
type Directory interface {
	// CardsSince serves this hub's own opted-in cards after a cursor.
	CardsSince(cursor int64, limit int, home string) ([]FedCardView, int64, error)
	// AdmitFedCard verifies and stores a card learned from a peer, with
	// the encryption key set the entry carried (nil when none). An
	// error wrapping ErrRefusedForNow means the refusal may stop
	// applying, and the cursor must not advance past that card.
	AdmitFedCard(peerAID string, card, kel, keys []byte, home string) error
	// ReviewsSince serves this hub's own opted-in reviews after a cursor,
	// as opaque JSON. Opaque because federation moves the bytes and the
	// kernel decides what they mean — a module that understood the shape
	// of a review would be a module with an opinion about reputation.
	ReviewsSince(cursor int64, limit int) ([]json.RawMessage, int64, error)
	// AdmitFedReview verifies and stores a review learned from a peer.
	AdmitFedReview(peerAID string, review json.RawMessage) error
	// A2ACardsSince serves the A2A card stream (/fed/v2/cards, A2A-DESIGN
	// §10.6): the verified A2A cards of this hub's own agents that opted
	// in, and the withdrawals of cards it stopped publishing, in fed_seq
	// order after a cursor.
	A2ACardsSince(cursor int64, limit int, home string) ([]FedA2ACardView, int64, error)
	// AdmitFedA2ACard admits one A2A card stream entry learned from a
	// peer, dispatching on its Format (FormatA2ACard or FormatWithdrawal;
	// the sync loop skips any other). An error wrapping ErrRefusedForNow
	// holds the cursor, as for AdmitFedCard.
	AdmitFedA2ACard(peerAID string, entry FedA2ACardView) error
}

// ErrRefusedForNow marks a refusal that may stop applying.
//
// Part of the Directory contract rather than an implementation detail,
// because it is the sync loop that has to act on it. A malformed card, a
// bad signature or a subject that does not match its key history is
// wrong for ever and the stream should move past it. "This agent is
// registered here" is a fact about today, and moving past it loses the
// card the moment the fact changes.
var ErrRefusedForNow = errors.New("federation: refused for now")

// FedCardView is one entry of the sync stream, as the kernel hands it over.
// Keys is the agent's seal.SignedEncKeySet encoding, or nil.
type FedCardView struct {
	Card   []byte
	KEL    []byte
	Keys   []byte
	Home   string
	FedSeq int64
}

type fedCardWire struct {
	Card   json.RawMessage `json:"card"`
	KEL    string          `json:"kel"`
	Keys   string          `json:"keys,omitempty"` // base64 of the seal.SignedEncKeySet encoding
	Home   string          `json:"home"`
	FedSeq int64           `json:"fed_seq"`
}

// fullResyncEvery is how many sync rounds pass between full re-reads of
// a peer's directory. At the steady two-minute cadence this is about
// every half hour, so a directory that lost an entry heals well inside
// an hour without anyone restarting anything.
const fullResyncEvery = 15

// DiscoveryEnabled reports whether this hub publishes and pulls directories.
func (s *Service) DiscoveryEnabled() bool {
	return s.cfg.Discovery != "" && s.cfg.Discovery != "off" && len(s.cfg.Peers) > 0
}

// hCards serves GET /fed/v1/cards?cursor=<c>.
//
// Unauthenticated on purpose. Everything it serves is an agent's own
// signed card, published by an agent that asked to be federated — there
// is nothing here a caller could learn that the agent did not choose to
// say, and requiring a signature to read public statements would only
// stop the honest.
func (s *Service) hCards(w http.ResponseWriter, r *http.Request) {
	if !s.DiscoveryEnabled() || s.dir == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "discovery federation disabled")
		return
	}
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	cards, next, err := s.dir.CardsSince(cursor, 200, s.cfg.Home)
	if err != nil {
		fedErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	out := make([]fedCardWire, 0, len(cards))
	for _, c := range cards {
		cw := fedCardWire{
			Card: json.RawMessage(c.Card), KEL: base64.StdEncoding.EncodeToString(c.KEL),
			Home: c.Home, FedSeq: c.FedSeq,
		}
		if len(c.Keys) > 0 {
			cw.Keys = base64.StdEncoding.EncodeToString(c.Keys)
		}
		out = append(out, cw)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"cursor": next, "cards": out})
}

// hFedReviewStream serves GET /fed/v1/reviews?cursor=<c>.
//
// Unauthenticated for the same reason as the card stream: every review
// here is a signature the reviewer already published, over an interaction
// the provider already receipted. There is nothing to withhold from a
// reader that the parties did not choose to say.
func (s *Service) hFedReviewStream(w http.ResponseWriter, r *http.Request) {
	if !s.DiscoveryEnabled() || s.dir == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "discovery federation disabled")
		return
	}
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	revs, next, err := s.dir.ReviewsSince(cursor, 100)
	if err != nil {
		fedErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	if revs == nil {
		revs = []json.RawMessage{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"cursor": next, "reviews": revs})
}

// syncReviews pulls each peer's reputation stream forward by one page.
//
// A separate cursor from the card stream, because the two advance at
// different rates and sharing one would have a busy review stream drag
// the directory along with it — or a quiet one hold it back.
func (s *Service) syncReviews(ctx context.Context) (admitted, refused int) {
	if !s.DiscoveryEnabled() || s.dir == nil {
		return 0, 0
	}
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		cursor := s.peerReviewCursor(p.AID)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/fed/v1/reviews?cursor=%d", strings.TrimSuffix(p.Endpoint, "/"), cursor), nil)
		if err != nil {
			continue
		}
		resp, err := s.http.Do(req)
		if err != nil {
			log.Printf("hub: reputation sync %s: %v", p.AID, err)
			continue
		}
		var out struct {
			Cursor  int64             `json:"cursor"`
			Reviews []json.RawMessage `json:"reviews"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out)
		resp.Body.Close()
		if derr != nil {
			log.Printf("hub: reputation sync %s: %v", p.AID, derr)
			continue
		}
		for _, rv := range out.Reviews {
			if err := s.dir.AdmitFedReview(p.AID, rv); err != nil {
				log.Printf("hub: federated review from %s refused: %v", p.AID, err)
				refused++
				continue
			}
			admitted++
		}
		if out.Cursor > cursor {
			s.setPeerReviewCursor(p.AID, out.Cursor)
		}
	}
	return admitted, refused
}

func (s *Service) peerReviewCursor(aid string) int64 {
	var c int64
	_ = s.db.QueryRow(`SELECT cursor FROM fed_review_cursor WHERE peer_aid=?`, aid).Scan(&c)
	return c
}

func (s *Service) setPeerReviewCursor(aid string, c int64) {
	_, _ = s.db.Exec(
		`INSERT INTO fed_review_cursor(peer_aid, cursor) VALUES(?,?)
		 ON CONFLICT(peer_aid) DO UPDATE SET cursor=excluded.cursor`, aid, c)
}

// SyncOnce pulls each peer's directory forward by one page.
//
// Per peer, because a peer that is down or lying must not stop the
// others: its cursor simply does not advance, and the next attempt asks
// for the same page. A card that fails admission is dropped and the
// cursor still advances past it — refusing to move would let one bad card
// from one peer wedge that peer's stream forever.
func (s *Service) SyncOnce(ctx context.Context) (admitted, refused int) {
	if !s.DiscoveryEnabled() || s.dir == nil {
		return 0, 0
	}
	// Every so often, re-read a peer's directory from the beginning.
	//
	// The cursor is an optimisation and it can be wrong. A card refused
	// for a reason that later stopped applying, a bug in admission, a
	// database restored from a backup taken after the cursor moved — each
	// leaves an agent the peer is publishing and this hub will never ask
	// for again. Holding the cursor at a transient refusal prevents that
	// going forward; this recovers the ones already lost, including every
	// cause not yet thought of.
	//
	// Admission is idempotent (the card table upserts on subject), so a
	// full pass costs a re-read and changes nothing that is already
	// right. Rare enough not to matter, frequent enough that a directory
	// heals within the hour rather than at the next restart.
	s.round++
	full := s.round%fullResyncEvery == 0

	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		cursor := s.peerCursor(p.AID)
		if full {
			log.Printf("hub: federation full resync from %s", p.AID)
			cursor = 0
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/fed/v1/cards?cursor=%d", strings.TrimSuffix(p.Endpoint, "/"), cursor), nil)
		if err != nil {
			continue
		}
		resp, err := s.http.Do(req)
		if err != nil {
			log.Printf("hub: federation sync %s: %v", p.AID, err)
			continue
		}
		var out struct {
			Cursor int64         `json:"cursor"`
			Cards  []fedCardWire `json:"cards"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out)
		resp.Body.Close()
		if derr != nil {
			log.Printf("hub: federation sync %s: %v", p.AID, derr)
			continue
		}
		var stall int64
		for _, c := range out.Cards {
			kel, kerr := base64.StdEncoding.DecodeString(c.KEL)
			if kerr != nil {
				refused++
				continue
			}
			home := c.Home
			if home == "" {
				// A peer that names no home still tells us who exists;
				// its own endpoint is the honest fallback for where they
				// are reachable.
				home = p.Endpoint
			}
			// The key set is advisory: one that does not decode is passed
			// as absent and the card is still admitted.
			var keys []byte
			if c.Keys != "" {
				if k, kerr := base64.StdEncoding.DecodeString(c.Keys); kerr == nil {
					keys = k
				}
			}
			if err := s.dir.AdmitFedCard(p.AID, c.Card, kel, keys, home); err != nil {
				log.Printf("hub: federation card from %s refused: %v", p.AID, err)
				refused++
				// A refusal that may stop applying must not be skipped
				// past. Advancing over it loses the card for ever the
				// moment the reason goes away — which is what happened
				// in production: a peer's card was refused because that
				// agent was registered here, the agent later moved, and
				// the directory never learned it existed.
				//
				// Holding the cursor here means a peer that keeps
				// sending such a card stalls its own stream. That is
				// visible in the log every round, which is the right
				// place for it: silently dropping an agent from the
				// directory is the failure nobody notices.
				if errors.Is(err, ErrRefusedForNow) {
					stall = c.FedSeq
					break
				}
				continue
			}
			admitted++
		}
		switch {
		case stall > 0 && stall > cursor:
			s.setPeerCursor(p.AID, stall-1)
		case out.Cursor > cursor:
			s.setPeerCursor(p.AID, out.Cursor)
		}
		if full && out.Cursor > 0 && stall == 0 {
			// A full pass that admitted everything leaves the cursor
			// where the peer says the end is, so the next ordinary round
			// picks up from there rather than replaying the directory.
			s.setPeerCursor(p.AID, out.Cursor)
		}
	}
	// The A2A card stream rides the same tick and the same full-resync
	// schedule, with its own cursor (a2acards.go).
	aa, ar := s.syncA2ACards(ctx, full)
	admitted, refused = admitted+aa, refused+ar
	// Reputation rides the same tick. Cards say who exists; reviews say
	// how they have done. Pulling one without the other gives a directory
	// full of strangers with no standing, which is a directory nobody can
	// choose from.
	ra, rr := s.syncReviews(ctx)
	return admitted + ra, refused + rr
}

func (s *Service) peerCursor(aid string) int64 {
	var c int64
	_ = s.db.QueryRow(`SELECT cursor FROM fed_cursor WHERE peer_aid=?`, aid).Scan(&c)
	return c
}

func (s *Service) setPeerCursor(aid string, c int64) {
	_, _ = s.db.Exec(
		`INSERT INTO fed_cursor(peer_aid, cursor) VALUES(?,?)
		 ON CONFLICT(peer_aid) DO UPDATE SET cursor=excluded.cursor`, aid, c)
}

// ---- cross-hub settlement (the clearing half of discovery federation) ----

// SettleAtPeer asks the hub that owns a ledger to settle a payment on it.
//
// The provider's hub cannot settle a balance it does not keep, and
// refusing would make a paid capability unusable across a federation. So
// it forwards, and the answer comes back with the settling hub's signed
// receipt — which is what lets the asking hub credit its own payee on
// another hub's word and still be able to show what that word was.
//
// Only allowlisted peers, and only the peer whose AID the network names.
// A settlement request routed by the caller would be a request to credit
// whoever the caller chose.
func (s *Service) SettleAtPeer(ctx context.Context, network string, body []byte) ([]byte, string, error) {
	if !s.DiscoveryEnabled() && !s.Enabled() {
		return nil, "", fmt.Errorf("federation disabled")
	}
	const prefix = "hub:"
	if !strings.HasPrefix(network, prefix) {
		return nil, "", fmt.Errorf("not a hub ledger: %q", network)
	}
	peerAID := strings.TrimPrefix(network, prefix)
	p := s.peer(peerAID)
	if p == nil {
		return nil, "", fmt.Errorf("hub %s is not a peer of this one", peerAID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(p.Endpoint, "/")+"/x402/settle", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, peerAID, err
}

// PeerKEL exposes a peer's verified key history, so the kernel can check
// a settlement receipt the peer signed.
func (s *Service) PeerKEL(peerAID string) ([]identity.SignedEvent, error) {
	p := s.peer(peerAID)
	if p == nil {
		return nil, fmt.Errorf("hub %s is not a peer of this one", peerAID)
	}
	return s.peerKEL(p)
}

// ---- witnessing a peer's issuance chain ----

// Witness is what the kernel supplies so federation can pin peer heads.
//
// A seam rather than an import, like Directory and LocalDelivery: the
// kernel owns the chain and the signing key, federation owns the peers
// and the polling. Neither needs to know how the other works.
type Witness interface {
	// Attest signs and stores this hub's observation of a peer's head,
	// returning the marshalled attestation to send back to that peer.
	Attest(peerAID, headID string, seq uint64) ([]byte, error)
}

// SetWitness wires the witnessing seam.
func (s *Service) SetWitness(w Witness) { s.witness = w }

// WitnessOnce pins each peer's current issuance head.
//
// Per peer, and failures are logged rather than fatal: a peer that is
// down, or running a build with no issuance chain, must not stop the
// others being witnessed.
//
// The attestation is stored locally first and sent to the peer second.
// That order is the whole point — evidence about a party that only that
// party holds is not evidence, so the copy that matters is the one this
// hub keeps. Sending it is a courtesy that lets the peer show a reader
// where to start looking.
func (s *Service) WitnessOnce(ctx context.Context) (pinned int) {
	if !s.cfg.WitnessEnabled() || s.witness == nil {
		return 0
	}
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		endpoint := strings.TrimSuffix(p.Endpoint, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/x402/issuance/head", nil)
		if err != nil {
			continue
		}
		resp, err := s.http.Do(req)
		if err != nil {
			log.Printf("hub: witness %s: %v", p.AID, err)
			continue
		}
		var head struct {
			ChainDID string `json:"chain_did"`
			Seq      uint64 `json:"seq"`
			HeadID   string `json:"head_id"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&head)
		resp.Body.Close()
		if derr != nil {
			log.Printf("hub: witness %s: %v", p.AID, derr)
			continue
		}
		// HeadID alone says whether there is a head. Seq must not be part
		// of this test: an AEL's first record is seq 0, so a chain
		// holding exactly one record — the opening entry every upgraded
		// hub starts with — was skipped as though it had nothing to pin.
		// On the live topology that meant one hub witnessed the other and
		// was never witnessed back.
		if head.HeadID == "" {
			continue // nothing issued yet; there is no head to pin
		}
		// The peer must be attesting to its own chain. A peer serving
		// somebody else's chain_did would have this hub sign a statement
		// about a third party it never looked at.
		if head.ChainDID != p.AID {
			log.Printf("hub: witness %s: served a head for %s, not itself", p.AID, head.ChainDID)
			continue
		}
		raw, err := s.witness.Attest(p.AID, head.HeadID, head.Seq)
		if err != nil {
			log.Printf("hub: witness %s: %v", p.AID, err)
			continue
		}
		pinned++
		s.sendAttestation(ctx, endpoint, raw)
	}
	return pinned
}

// sendAttestation offers the attestation back to the peer. Best-effort:
// the copy that matters is already stored here.
func (s *Service) sendAttestation(ctx context.Context, endpoint string, raw []byte) {
	body, err := json.Marshal(map[string]string{
		"attestation": base64.StdEncoding.EncodeToString(raw)})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/x402/witness", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := s.http.Do(req); err == nil {
		resp.Body.Close()
	}
}
