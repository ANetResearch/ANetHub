package aghub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
)

// Cards make a registration attributable to the agent that made it.
//
// The register challenge signs an action, an AID and a timestamp. It
// proves who is calling and covers nothing they said, so this hub could
// change an agent's name or capability list and no party could tell —
// including the agent. That is tolerable for a hub someone chose to
// trust. It is not tolerable for a directory other people search, and it
// becomes untenable the moment directories federate, where the whole
// property being relied on is that a peer can hide a card and never
// invent one.
//
// A card is an ADP AgentCard: subject, capabilities, a monotonic seq and
// a detached JWS over the lot. ANetCore implements the signing, the
// admission gate and the high-water rule, so this file is bookkeeping.

// cardMajors is the schema major this hub admits.
var cardMajors = map[uint16]bool{1: true}

// admitCard verifies a card against the registrant's own key history and
// stores it.
//
// Failure is not fatal to the registration. A node running an older build
// sends no card at all, and refusing it would make an upgrade of this hub
// look like an outage to everyone who had not upgraded — so a
// registration without a verifiable card still registers, and simply has
// nothing attributable behind it.
func (s *Store) AdmitCard(aid string, raw json.RawMessage, kel []identity.SignedEvent) error {
	if len(raw) == 0 {
		return nil
	}
	var card adp.AgentCard
	if err := json.Unmarshal(raw, &card); err != nil {
		return fmt.Errorf("card malformed: %w", err)
	}
	// A card must speak for the agent registering it. Admitting one whose
	// subject is somebody else would let any registrant publish claims in
	// another agent's name — the exact forgery cards exist to prevent.
	if card.SubjectDID != aid {
		return fmt.Errorf("card subject %s is not the registrant %s", card.SubjectDID, aid)
	}
	high, err := s.cardHighWater(aid)
	if err != nil {
		return err
	}
	if _, err := adp.AdmitCard(&card, time.Now(), high, kel, cardMajors, nil); err != nil {
		return fmt.Errorf("card refused: %w", err)
	}
	// fed_seq advances on every store, updates included: a peer that
	// already synced this agent must see it change, and a cursor keyed to
	// first-insertion would silently stop at the first version.
	var next int64
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(fed_seq),0)+1 FROM agent_card`).Scan(&next); err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO agent_card(aid, seq, card, stored_at, fed_seq) VALUES(?,?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, card=excluded.card,
		   stored_at=excluded.stored_at, fed_seq=excluded.fed_seq`,
		aid, card.Seq, []byte(raw), time.Now().UTC().Format(time.RFC3339Nano), next)
	return err
}

func (s *Store) cardHighWater(aid string) (uint64, error) {
	var seq uint64
	err := s.db.QueryRow(`SELECT seq FROM agent_card WHERE aid=?`, aid).Scan(&seq)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return 0, nil
	}
	return seq, err
}

// AgentCard returns the signed card an agent published, if any.
func (s *Store) AgentCard(aid string) (json.RawMessage, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&raw)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// Visibility tiers (K208 §5.2, registry group anr:fed.visibility).
//
// hub-local is the default and the conservative choice is the point: a
// directory that federated by default would publish once, for everyone
// who never thought about it, and a card cannot be recalled from a hub
// that already has it.
//
// It is a request, not a guarantee, and saying so matters. A hub holding
// your card can publish it whatever you asked; what the tiers control is
// what an honest hub does. Integrity is the property cryptography gives
// you here — a peer can hide your card and can never invent one — and
// privacy is a policy you are trusting the hub with, exactly as you
// trusted it with the card.
const (
	VisibilityHubLocal  = "hub-local"
	VisibilityFederated = "federated"
	VisibilityPublic    = "public"
)

func validVisibility(v string) bool {
	switch v {
	case VisibilityHubLocal, VisibilityFederated, VisibilityPublic:
		return true
	}
	return false
}

// SetVisibility records how far an agent is willing to be published.
func (s *Store) SetVisibility(aid, v string) error {
	if !validVisibility(v) {
		return fmt.Errorf("hub: unknown visibility %q", v)
	}
	_, err := s.db.Exec(`UPDATE agent SET visibility=? WHERE aid=?`, v, aid)
	return err
}

// FedCard is one entry of the federation sync stream.
//
// The KEL travels with the card so a consuming hub can admit it without
// asking anyone — the same self-contained shape a delegation uses. Home
// is the routing hint: which hub this agent actually lives on, and so
// where work for it has to go.
type FedCard struct {
	Card   json.RawMessage `json:"card"`
	KEL    string          `json:"kel"`  // base64
	Home   string          `json:"home"` // the agent's home hub endpoint
	FedSeq int64           `json:"fed_seq"`
}

// CardsSince serves the federation sync stream: cards published HERE, by
// agents who opted in, after the caller's cursor.
//
// One hop, deliberately (K208 §5.2). Only cards registered directly with
// this hub are served, never cards learned from a peer — transitive
// discovery is an open question, and a directory that forwarded what it
// heard would let one hub's policy decision propagate as everyone's.
func (s *Store) CardsSince(cursor int64, limit int, home string) ([]FedCard, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.Query(
		`SELECT c.aid, c.card, c.fed_seq, a.kel
		   FROM agent_card c JOIN agent a ON a.aid = c.aid
		  WHERE c.fed_seq > ? AND a.visibility IN (?, ?)
		  ORDER BY c.fed_seq LIMIT ?`,
		cursor, VisibilityFederated, VisibilityPublic, limit)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	out := []FedCard{}
	next := cursor
	for rows.Next() {
		var aid string
		var card, kel []byte
		var seq int64
		if err := rows.Scan(&aid, &card, &seq, &kel); err != nil {
			return nil, cursor, err
		}
		out = append(out, FedCard{
			Card: json.RawMessage(card), KEL: base64.StdEncoding.EncodeToString(kel),
			Home: home, FedSeq: seq,
		})
		next = seq
	}
	return out, next, rows.Err()
}

// AdmitFedCard verifies a card learned from a peer and stores it.
//
// Verified against the KEL that travelled with it, and the KEL is checked
// to belong to the card's subject — otherwise a peer could pair any card
// with any key history and both would "verify". A peer hub can decline to
// tell us about an agent; this is what stops it inventing one.
func (s *Store) AdmitFedCard(peerAID string, fc FedCard) error {
	var card adp.AgentCard
	if err := json.Unmarshal(fc.Card, &card); err != nil {
		return fmt.Errorf("federated card malformed: %w", err)
	}
	kelBytes, err := base64.StdEncoding.DecodeString(fc.KEL)
	if err != nil {
		return fmt.Errorf("federated card kel not base64: %w", err)
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		return fmt.Errorf("federated card kel malformed: %w", err)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		return fmt.Errorf("federated card kel does not replay: %w", err)
	}
	if got := states[len(states)-1].AID; got != card.SubjectDID {
		return fmt.Errorf("federated card subject %s but key history is %s", card.SubjectDID, got)
	}
	// An agent that registered HERE speaks for itself; a peer's copy must
	// never overwrite it, or a peer could redirect our own agents' work
	// to itself by claiming to be their home.
	var local int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, card.SubjectDID).Scan(&local); err != nil {
		return err
	}
	if local > 0 {
		return fmt.Errorf("federated card for %s, which is registered here", card.SubjectDID)
	}
	var high uint64
	_ = s.db.QueryRow(`SELECT seq FROM fed_card WHERE aid=?`, card.SubjectDID).Scan(&high)
	if _, err := adp.AdmitCard(&card, time.Now(), high, kel, cardMajors, nil); err != nil {
		return fmt.Errorf("federated card refused: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO fed_card(aid, seq, card, kel, home, peer_aid, stored_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, card=excluded.card, kel=excluded.kel,
		   home=excluded.home, peer_aid=excluded.peer_aid, stored_at=excluded.stored_at`,
		card.SubjectDID, card.Seq, []byte(fc.Card), kelBytes, fc.Home, peerAID,
		time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// FedDirectory adapts the store to federation's Directory seam, so the
// federation module never imports the kernel's internals.
type FedDirectory struct{ S *Store }

func (d FedDirectory) CardsSince(cursor int64, limit int, home string) ([]federation.FedCardView, int64, error) {
	cards, next, err := d.S.CardsSince(cursor, limit, home)
	if err != nil {
		return nil, cursor, err
	}
	out := make([]federation.FedCardView, 0, len(cards))
	for _, c := range cards {
		kel, derr := base64.StdEncoding.DecodeString(c.KEL)
		if derr != nil {
			return nil, cursor, derr
		}
		out = append(out, federation.FedCardView{
			Card: []byte(c.Card), KEL: kel, Home: c.Home, FedSeq: c.FedSeq,
		})
	}
	return out, next, nil
}

// ReviewsSince and AdmitFedReview complete the Directory seam. Federation
// carries the bytes; what a review means stays here, because a module
// with an opinion about reputation is a module that would need to be
// trusted about it.
func (d FedDirectory) ReviewsSince(cursor int64, limit int) ([]json.RawMessage, int64, error) {
	revs, next, err := d.S.ReviewsSince(cursor, limit)
	if err != nil {
		return nil, cursor, err
	}
	out := make([]json.RawMessage, 0, len(revs))
	for _, r := range revs {
		b, merr := json.Marshal(r)
		if merr != nil {
			return nil, cursor, merr
		}
		out = append(out, b)
	}
	return out, next, nil
}

func (d FedDirectory) AdmitFedReview(peerAID string, raw json.RawMessage) error {
	var fr FedReview
	if err := json.Unmarshal(raw, &fr); err != nil {
		return err
	}
	return d.S.AdmitFedReview(peerAID, fr)
}

func (d FedDirectory) AdmitFedCard(peerAID string, card, kel []byte, home string) error {
	return d.S.AdmitFedCard(peerAID, FedCard{
		Card: json.RawMessage(card), KEL: base64.StdEncoding.EncodeToString(kel), Home: home,
	})
}

// FederatedAgents returns agents learned from peer hubs, for discovery.
//
// Kept separate from the local directory and marked with their home hub:
// which hub an agent lives on decides where work for it is delivered, and
// a directory that forgot would answer with agents it cannot reach.
func (s *Store) FederatedAgents(capFilter string) ([]AgentView, error) {
	q := `SELECT aid, card, home FROM fed_card`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentView
	for rows.Next() {
		var aid, home string
		var raw []byte
		if err := rows.Scan(&aid, &raw, &home); err != nil {
			return nil, err
		}
		var card adp.AgentCard
		if json.Unmarshal(raw, &card) != nil {
			continue
		}
		if capFilter != "" && !cardServes(&card, capFilter) {
			continue
		}
		out = append(out, AgentView{
			AID: aid, Name: card.Name, Caps: card.Capabilities,
			Listed: len(card.Capabilities) > 0, HomeHub: home,
		})
	}
	return out, rows.Err()
}

// cardServes applies the same exact/prefix/comma rules the local index
// uses, so a federated agent answers the same question a local one does.
func cardServes(card *adp.AgentCard, filter string) bool {
	for _, term := range strings.Split(filter, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		for _, c := range card.Capabilities {
			if strings.HasSuffix(term, "*") {
				if strings.HasPrefix(c, strings.TrimSuffix(term, "*")) {
					return true
				}
				continue
			}
			if c == term {
				return true
			}
		}
	}
	return false
}
