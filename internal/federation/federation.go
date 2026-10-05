// Package federation is a hub's federation with its peer hubs, v3
// (sealed-sender §2.8, §4.2.6, §4.2.7; core G3, G21): the routes under
// /fed/v3 that peers call, each signed by the asking hub with relayauth v2
// and checked by authPeer, and the requests this hub makes to them.
//
// Delivery (sub-plane A): a send whose recipient is registered at a peer is
// handed on, by the sender's hub, to that one home hub (/fed/v3/forward);
// the request is the envelope and its delivery credential, and names no
// sender. Finding the home and the recipient's keys goes by directory
// bucket (/fed/v3/directory:bucket), never by AID. Discovery (sub-plane B):
// the A2A card stream (/fed/v3/cards) and the review stream
// (/fed/v3/reviews), pulled by each hub from its peers.
//
// The hub signs its requests to peers with its own AID (hubid); that
// signature means "this request is this hub's", never an endorsement of
// what it carries. The kernel's checks and state stay in the kernel
// (Kernel); this package moves the bytes and authenticates the peers.
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

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"
	_ "modernc.org/sqlite"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

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

// Service is one hub's federation face.
type Service struct {
	cfg     Config
	id      *hubid.Identity
	dir     Directory
	kernel  Kernel
	db      *sql.DB
	witness Witness
	// http carries the requests to peers that are not signed (a peer's
	// /hub/identity, its issuance head, a settlement), each bounded by its
	// Timeout; the signed ones go through signer, bounded by their
	// contexts. Both check the wire every answer states (wire).
	http *http.Client
	wire *peerWire
	// signer signs this hub's requests to its peers (signer.go).
	signer *Signer
	// now is the clock (time.Now; a test's).
	now func() time.Time
	// round counts sync passes, so a full re-read can be scheduled
	// without a second timer. Touched only from the sync loop.
	round int
	// a2aStreamStatus is each peer's last HTTP status on /fed/v3/cards,
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

// New opens the federation module of the hub id, whose data directory is
// dir. The kernel is wired afterwards (SetKernel), as is the directory.
func New(dir string, cfg Config, id *hubid.Identity) (*Service, error) {
	db, err := sql.Open("sqlite", filepath.Join(dir, "federation.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS fed_peer_kel (aid TEXT PRIMARY KEY, kel BLOB NOT NULL, fetched_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_review_cursor (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_cursor_v3 (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
`); err != nil {
		db.Close()
		return nil, err
	}
	if err := dropUnprovenPeerKELs(db); err != nil {
		db.Close()
		return nil, err
	}
	s := &Service{cfg: cfg, id: id, db: db, now: time.Now,
		a2aStreamStatus: map[string]int{}, kelFetches: map[string]*peerKELFetch{}}
	// Every request to a peer states the hub wire (core CORE-V1), and
	// every answer of a peer is checked for it (peerwire.go).
	s.wire = newPeerWire(wire3.Transport(nil), func() time.Time { return s.now() })
	s.http = &http.Client{Timeout: 10 * time.Second, Transport: s.wire}
	s.signer = NewSigner(id, &http.Client{Transport: s.wire})
	return s, nil
}

// defaultMaxEnvelope matches the kernel's default envelope limit
// (A2A-DESIGN §3.7); /fed/v3/forward uses the kernel's own (Kernel).
const defaultMaxEnvelope = 96 << 20

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

// ---- the peers of delivery, as the kernel asks for them ----

// DeliveryPeers is the hubs this one forwards to and asks for buckets, in
// the order of the peer table; none when delivery federation is off.
func (s *Service) DeliveryPeers() []string {
	if !s.Enabled() {
		return nil
	}
	out := make([]string, 0, len(s.cfg.Peers))
	for _, p := range s.cfg.Peers {
		out = append(out, p.AID)
	}
	return out
}

// IsDeliveryPeer reports whether hubAID is a hub this one forwards to.
func (s *Service) IsDeliveryPeer(hubAID string) bool { return s.deliveryPeer(hubAID) != nil }

// deliveryPeer is the peer hubAID when delivery federation is on, or nil.
func (s *Service) deliveryPeer(hubAID string) *Peer {
	if !s.Enabled() {
		return nil
	}
	return s.peer(hubAID)
}

// DeliveryPeerAt is the AID of the delivery peer whose endpoint is the hub
// URL home (a federated card's home, sealed-sender SSR-H12 step 3), or ""
// when no delivery peer is at that URL. Scheme and host compare without
// case, and a trailing slash does not count.
func (s *Service) DeliveryPeerAt(home string) string {
	if !s.Enabled() || home == "" {
		return ""
	}
	want := endpointKey(home)
	for _, p := range s.cfg.Peers {
		if endpointKey(p.Endpoint) == want {
			return p.AID
		}
	}
	return ""
}

// endpointKey normalises a hub URL for comparison.
func endpointKey(u string) string {
	u = strings.TrimRight(strings.TrimSpace(u), "/")
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		host, path, _ := strings.Cut(rest, "/")
		u = strings.ToLower(u[:i]) + "://" + strings.ToLower(host)
		if path != "" {
			u += "/" + path
		}
	}
	return u
}

// errNotADeliveryPeer is the error of a request to a hub that is not a
// delivery peer, or while delivery federation is off.
func errNotADeliveryPeer(aid string) error {
	return fmt.Errorf("federation: %s is not a peer this hub delivers to", aid)
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

// Handler serves the federation routes, all under /fed/v3 (core G21) and
// all signed by a peer hub (authPeer):
//
//	POST /fed/v3/forward            an envelope for an agent registered here (forward_v3.go)
//	POST /fed/v3/directory:bucket   a bucket of this hub's directory (bucket.go)
//	GET  /fed/v3/cards              the A2A card stream (a2acards.go)
//	GET  /fed/v3/reviews            the review stream (below)
//
// The v0.2 routes (/fed/v1/forward, /fed/v1/reviews, /fed/v2/keys/{aid},
// /fed/v2/cards) are gone and answer 404 with the rest of what no route
// takes; so is the ADP card stream, /fed/v1/cards.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fed/v3/forward", s.hForward)
	mux.HandleFunc("POST /fed/v3/directory:bucket", s.hBucket)
	mux.HandleFunc("GET /fed/v3/cards", s.hA2ACards)
	mux.HandleFunc("GET /fed/v3/reviews", s.hFedReviewStream)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { wire3.Refuse(w, wire3.ReasonNotFound) })
	return mux
}

// ---- sub-plane B: discovery federation (K208 §5) ----

// Directory is what discovery federation needs from the hub kernel. Kept
// separate from Kernel because the two sub-planes switch independently,
// and a hub running only one should not have to implement the other's
// seam.
type Directory interface {
	// ReviewsSince serves this hub's own opted-in reviews after a cursor,
	// as opaque JSON. Opaque because federation moves the bytes and the
	// kernel decides what they mean — a module that understood the shape
	// of a review would be a module with an opinion about reputation.
	ReviewsSince(cursor int64, limit int) ([]json.RawMessage, int64, error)
	// AdmitFedReview verifies and stores a review learned from a peer.
	AdmitFedReview(peerAID string, review json.RawMessage) error
	// A2ACardsSince serves the A2A card stream (/fed/v3/cards, A2A-DESIGN
	// §10.6): the verified A2A cards of this hub's own agents that opted
	// in, and the withdrawals of cards it stopped publishing, in fed_seq
	// order after a cursor.
	A2ACardsSince(cursor int64, limit int, home string) ([]FedA2ACardView, int64, error)
	// AdmitFedA2ACard admits one A2A card stream entry learned from a
	// peer, dispatching on its Format (FormatA2ACard or FormatWithdrawal;
	// the sync loop skips any other). An error wrapping ErrRefusedForNow
	// means the refusal may stop applying, and the cursor must not advance
	// past that entry.
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

// fullResyncEvery is how many sync rounds pass between full re-reads of
// a peer's directory. At the steady two-minute cadence this is about
// every half hour, so a directory that lost an entry heals well inside
// an hour without anyone restarting anything.
const fullResyncEvery = 15

// DiscoveryEnabled reports whether this hub publishes and pulls directories.
func (s *Service) DiscoveryEnabled() bool {
	return s.cfg.Discovery != "" && s.cfg.Discovery != "off" && len(s.cfg.Peers) > 0
}

// hFedReviewStream serves GET /fed/v3/reviews?cursor=<c> (core §2.12.2,
// relayauth fed_reviews), to the peers of the discovery sub-plane.
//
// v030-todo(PAY-6): the entries are still the v0.2 review records
// ({cursor, reviews}); the stream serves review/2 entries.
func (s *Service) hFedReviewStream(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.authPeer(w, r, relayauth.ActionFedReviews, s.DiscoveryEnabled() && s.dir != nil, 0, nil); !ok {
		return
	}
	cursor, ok := streamCursor(w, r)
	if !ok {
		return
	}
	revs, next, err := s.dir.ReviewsSince(cursor, 100)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if revs == nil {
		revs = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"cursor": next, "reviews": revs})
}

// streamCursor reads the cursor of a stream request: absent is 0, anything
// else a non-negative integer in canonical decimal, or 400 bad_request.
func streamCursor(w http.ResponseWriter, r *http.Request) (int64, bool) {
	q := r.URL.Query()
	if _, ok := q["cursor"]; !ok {
		return 0, true
	}
	v := q.Get("cursor")
	c, err := strconv.ParseInt(v, 10, 64)
	if len(q["cursor"]) != 1 || err != nil || c < 0 || strconv.FormatInt(c, 10) != v {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The query member \"cursor\" is the cursor of the previous page, a non-negative integer; send it once, or not at all to start from the beginning."})
		return 0, false
	}
	return c, true
}

// streamTimeout bounds one page of a stream a peer serves.
const streamTimeout = 10 * time.Second

// getStream asks the peer p for one page of the stream at path after
// cursor, signed for action, and decodes the JSON answer into out. A peer
// answering other than 200 is reported by its status, and the caller
// decides whether to say so.
func (s *Service) getStream(ctx context.Context, p *Peer, path, action string, cursor int64, out any, limit int64) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, streamTimeout)
	defer cancel()
	resp, err := s.signer.Do(ctx, p.AID, action, Request{Method: http.MethodGet,
		URL: fmt.Sprintf("%s%s?cursor=%d", strings.TrimSuffix(p.Endpoint, "/"), path, cursor)})
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return resp.StatusCode, strings.TrimSpace(string(detail)), nil
	}
	return http.StatusOK, "", json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out)
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
		var out struct {
			Cursor  int64             `json:"cursor"`
			Reviews []json.RawMessage `json:"reviews"`
		}
		status, detail, err := s.getStream(ctx, p, "/fed/v3/reviews", relayauth.ActionFedReviews, cursor, &out, 16<<20)
		if err != nil {
			log.Printf("hub: reputation sync %s: %v", p.AID, err)
			continue
		}
		if status != http.StatusOK {
			log.Printf("hub: reputation sync %s: HTTP %d: %s", p.AID, status, detail)
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

// SyncOnce pulls each peer's directory forward by one page: its A2A card
// stream (a2acards.go) and its reputation stream.
//
// Per peer, because a peer that is down or lying must not stop the
// others: its cursor simply does not advance, and the next attempt asks
// for the same page. An entry that fails admission for good is dropped and
// the cursor still advances past it — refusing to move would let one bad
// card from one peer wedge that peer's stream forever; one refused for now
// (ErrRefusedForNow) holds the cursor, so it is read again once the
// refusal stops applying.
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
	if full {
		log.Printf("hub: federation full resync from every peer")
	}
	admitted, refused = s.syncA2ACards(ctx, full)
	// Reputation rides the same tick. Cards say who exists; reviews say
	// how they have done. Pulling one without the other gives a directory
	// full of strangers with no standing, which is a directory nobody can
	// choose from.
	ra, rr := s.syncReviews(ctx)
	return admitted + ra, refused + rr
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
// A seam rather than an import, like Directory and Kernel: the
// kernel owns the chain and the signing key, federation owns the peers
// and the polling. Neither needs to know how the other works.
type Witness interface {
	// Attest signs and stores this hub's observation of a peer's head,
	// returning the marshalled attestation to send back to that peer.
	Attest(peerAID, headID string, seq uint64) ([]byte, error)
}

// SetWitness wires the witnessing seam.
func (s *Service) SetWitness(w Witness) { s.witness = w }

// WitnessOnce pins each peer's current supply epoch chain head.
//
// Per peer, and failures are logged rather than fatal: a peer that is
// down, or that has published no epoch yet, must not stop the others being
// witnessed.
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
		// The head of the peer's supply epoch chain: {seq, id}, or {}
		// before its first epoch (hub-payment-privacy §2.3). It moves once
		// per epoch. What this hub signs is what the peer served as its
		// own head, so the attestation names the peer's AID as the chain.
		var head struct {
			Seq uint64 `json:"seq"`
			ID  string `json:"id"`
		}
		derr := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&head)
		resp.Body.Close()
		if derr != nil {
			log.Printf("hub: witness %s: %v", p.AID, derr)
			continue
		}
		// The id alone says whether there is a head. Seq must not be part
		// of this test: an AEL's first record is seq 0, so a chain
		// holding exactly one record was skipped as though it had nothing
		// to pin. On the live topology that meant one hub witnessed the
		// other and was never witnessed back.
		if head.ID == "" {
			continue // no epoch published yet; there is no head to pin
		}
		raw, err := s.witness.Attest(p.AID, head.ID, head.Seq)
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
		"attestation": base64.RawURLEncoding.EncodeToString(raw)})
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
