// Package federation implements K208 delivery federation (集连, sub-plane A):
// hub-to-hub forwarding of end-to-end-signed payloads. The hub signs the
// ForwardEnvelope with its own AID (hubid) — that signature means "this flow
// passed my quota and policy checks", never content endorsement. Agent
// payloads stay end-to-end verifiable regardless of federation.
package federation

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	Peers    []Peer `json:"peers"`
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
	db    *sql.DB
	http  *http.Client
}

func New(dir string, cfg Config, id *hubid.Identity, local LocalDelivery) (*Service, error) {
	db, err := sql.Open("sqlite", filepath.Join(dir, "federation.db")+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS fed_dedupe (payload_cid TEXT PRIMARY KEY, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fed_peer_kel (aid TEXT PRIMARY KEY, kel BLOB NOT NULL, fetched_at INTEGER NOT NULL);
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
