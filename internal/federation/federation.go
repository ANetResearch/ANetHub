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
	cfg   Config
	id    *hubid.Identity
	local LocalDelivery
	dir   Directory
	db    *sql.DB
	http  *http.Client
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
	// AdmitFedCard verifies and stores a card learned from a peer.
	AdmitFedCard(peerAID string, card, kel []byte, home string) error
}

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
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		cursor := s.peerCursor(p.AID)
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
				continue
			}
			admitted++
		}
		if out.Cursor > cursor {
			s.setPeerCursor(p.AID, out.Cursor)
		}
	}
	return admitted, refused
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
