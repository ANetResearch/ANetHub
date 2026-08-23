// Package federation implements K208 delivery federation (集连, sub-plane A):
// hub-to-hub forwarding of end-to-end-signed payloads. The hub signs the
// ForwardEnvelope with its own AID (hubid) — that signature means "this flow
// passed my quota and policy checks", never content endorsement. Agent
// payloads stay end-to-end verifiable regardless of federation.
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
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	_ "modernc.org/sqlite"

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
type LocalDelivery interface {
	HasAgent(aid string) bool
	Enqueue(toAID, fromAID, kind, interactionID string, payload []byte) (int64, error)
}

// Envelope is the K208 §4.2 ForwardEnvelope. Hub-visible relay metadata
// (from/kind/interaction) rides alongside the opaque end-to-end payload —
// the receiving hub needs it to file the message into a mailbox.
type Envelope struct {
	V             uint64   `json:"v"`
	OriginHubAID  string   `json:"origin_hub_aid"`
	DestAID       string   `json:"dest_aid"`
	FromAID       string   `json:"from_aid"`
	Kind          string   `json:"kind"`
	InteractionID string   `json:"interaction_id,omitempty"`
	Payload       string   `json:"payload"` // base64
	PayloadCID    string   `json:"payload_cid"`
	Hop           uint64   `json:"hop"`
	SeenHubs      []string `json:"seen_hubs"`
	TS            uint64   `json:"ts"`
	KeyStateSeq   uint64   `json:"key_state_seq"`
	Sig           string   `json:"sig"` // base64, origin hub KEL signature
}

// preimage is the CoreDet-CBOR canonical bytes the hub signature covers
// (_CONVENTIONS §2/§4: int keys, sig outside, arrays author-ordered).
func (e *Envelope) preimage(payload []byte) ([]byte, error) {
	seen := make([]any, 0, len(e.SeenHubs))
	for _, h := range e.SeenHubs {
		seen = append(seen, h)
	}
	m := map[uint64]any{
		1: e.V, 2: e.OriginHubAID, 3: e.DestAID, 4: e.FromAID, 5: e.Kind,
		7: payload, 8: e.PayloadCID, 9: e.Hop, 11: e.TS,
	}
	if e.InteractionID != "" {
		m[6] = e.InteractionID
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
	db      *sql.DB
	http    *http.Client
	witness Witness
	// round counts sync passes, so a full re-read can be scheduled
	// without a second timer. Touched only from the sync loop.
	round int
}

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
CREATE TABLE IF NOT EXISTS fed_peer_kel (aid TEXT PRIMARY KEY, kel BLOB NOT NULL, fetched_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_cursor (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_review_cursor (peer_aid TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
`); err != nil {
		db.Close()
		return nil, err
	}
	return &Service{cfg: cfg, id: id, local: local, db: db, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (s *Service) Close() error { return s.db.Close() }

// Enabled reports whether delivery federation is on.
func (s *Service) Enabled() bool { return s.cfg.Delivery != "off" && len(s.cfg.Peers) > 0 }

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
func (s *Service) peerKEL(p *Peer) ([]identity.SignedEvent, error) {
	var blob []byte
	err := s.db.QueryRow(`SELECT kel FROM fed_peer_kel WHERE aid=?`, p.AID).Scan(&blob)
	if err == sql.ErrNoRows {
		resp, ferr := s.http.Get(p.Endpoint + "/hub/identity")
		if ferr != nil {
			return nil, fmt.Errorf("peer kel fetch: %w", ferr)
		}
		defer resp.Body.Close()
		var out struct{ AID, KEL string }
		if ferr := json.NewDecoder(resp.Body).Decode(&out); ferr != nil {
			return nil, ferr
		}
		if out.AID != p.AID {
			return nil, fmt.Errorf("peer identity mismatch: served %s, configured %s", out.AID, p.AID)
		}
		blob, ferr = base64.StdEncoding.DecodeString(out.KEL)
		if ferr != nil {
			return nil, ferr
		}
		if _, ferr := s.db.Exec(`INSERT OR REPLACE INTO fed_peer_kel (aid, kel, fetched_at) VALUES (?,?,?)`,
			p.AID, blob, time.Now().UnixMilli()); ferr != nil {
			return nil, ferr
		}
	} else if err != nil {
		return nil, err
	}
	return identity.UnmarshalKEL(blob)
}

// ---- inbound ----

// Handler serves POST /fed/v1/forward.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fed/v1/forward", s.hForward)
	mux.HandleFunc("GET /fed/v1/cards", s.hCards)
	mux.HandleFunc("GET /fed/v1/reviews", s.hFedReviewStream)
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 100<<20))
	if err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		return
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		fedErr(w, http.StatusBadRequest, "MALFORMED", err.Error())
		return
	}
	if env.V != 1 {
		fedErr(w, http.StatusBadRequest, "VERSION_UNSUPPORTED", fmt.Sprintf("v=%d", env.V))
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
	// idempotency: second delivery of the same payload is a success no-op
	res, err := s.db.Exec(`INSERT OR IGNORE INTO fed_dedupe (payload_cid, ts) VALUES (?,?)`, env.PayloadCID, time.Now().UnixMilli())
	if err == nil {
		if n, _ := res.RowsAffected(); n == 0 {
			writeJSON(w, http.StatusOK, map[string]string{"status": "DUPLICATE"})
			return
		}
	}
	_, _ = s.db.Exec(`DELETE FROM fed_dedupe WHERE ts < ?`, time.Now().Add(-DedupeWindow).UnixMilli())
	if !s.local.HasAgent(env.DestAID) {
		fedErr(w, http.StatusNotFound, "UNKNOWN_DESTINATION", env.DestAID)
		return
	}
	if _, err := s.local.Enqueue(env.DestAID, env.FromAID, env.Kind, env.InteractionID, payload); err != nil {
		fedErr(w, http.StatusInternalServerError, "MALFORMED", err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// ---- egress ----

// TryForward offers a locally-undeliverable message to each peer in order;
// the first 202 wins. 404 means "not my agent" and the walk continues.
func (s *Service) TryForward(destAID, fromAID, kind, interactionID string, payload []byte) (bool, string, error) {
	if !s.Enabled() {
		return false, "", nil
	}
	cid, err := anetcid.SumRaw(payload)
	if err != nil {
		return false, "", err
	}
	env := Envelope{
		V: 1, OriginHubAID: s.id.AID, DestAID: destAID, FromAID: fromAID, Kind: kind,
		InteractionID: interactionID, Payload: base64.StdEncoding.EncodeToString(payload),
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
		resp.Body.Close()
		switch code {
		case http.StatusAccepted, http.StatusOK: // queued or idempotent duplicate
			return true, p.AID, nil
		case http.StatusNotFound:
			continue
		default:
			lastErr = fmt.Errorf("peer %s: HTTP %d", p.AID, code)
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
	// AdmitFedCard verifies and stores a card learned from a peer. An
	// error wrapping ErrRefusedForNow means the refusal may stop
	// applying, and the cursor must not advance past that card.
	AdmitFedCard(peerAID string, card, kel []byte, home string) error
	// ReviewsSince serves this hub's own opted-in reviews after a cursor,
	// as opaque JSON. Opaque because federation moves the bytes and the
	// kernel decides what they mean — a module that understood the shape
	// of a review would be a module with an opinion about reputation.
	ReviewsSince(cursor int64, limit int) ([]json.RawMessage, int64, error)
	// AdmitFedReview verifies and stores a review learned from a peer.
	AdmitFedReview(peerAID string, review json.RawMessage) error
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
type FedCardView struct {
	Card   []byte
	KEL    []byte
	Home   string
	FedSeq int64
}

type fedCardWire struct {
	Card   json.RawMessage `json:"card"`
	KEL    string          `json:"kel"`
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
		out = append(out, fedCardWire{
			Card: json.RawMessage(c.Card), KEL: base64.StdEncoding.EncodeToString(c.KEL),
			Home: c.Home, FedSeq: c.FedSeq,
		})
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
			if err := s.dir.AdmitFedCard(p.AID, c.Card, kel, home); err != nil {
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
		if head.Seq == 0 || head.HeadID == "" {
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
