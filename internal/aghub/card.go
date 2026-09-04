package aghub

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetHub/internal/federation"
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
	// Same bound as the register path. The register path caps the
	// capability list on its way in, but a card carries its own list and
	// reaches the directory by a different route: Store.FederatedAgents
	// puts card capabilities into every /agents response. Bounding one
	// entrance and not the other leaves the amplification intact and
	// only moves which request opens it.
	if err := validateCaps(card.Capabilities); err != nil {
		return fmt.Errorf("card refused: %w", err)
	}
	high, err := s.cardHighWater(aid)
	if err != nil {
		return err
	}
	if _, err := adp.AdmitCard(&card, time.Now(), high, kel, cardMajors, nil); err != nil {
		return fmt.Errorf("card refused: %w", err)
	}
	stored, err := s.cardToStore(aid, raw)
	if err != nil {
		return err
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
		aid, card.Seq, []byte(stored), nowStamp(), next)
	return err
}

// cardToStore decides what the agent_card row holds for a card that has
// just been admitted: the card itself, or the card kept inside a standing
// withdrawal.
//
// A withdrawal outlives a republished card deliberately. Letting a fresh
// card overwrite it would cancel, silently, a withdrawal no peer had read
// yet: the row would go back to being an ordinary card, the sync stream
// would carry nothing in its place, and every peer still holding the old
// copy would go on publishing an agent this hub no longer federates. A
// withdrawal is lifted where it was raised — by the agent asking to be
// published again (SetVisibility) — and by nothing else.
func (s *Store) cardToStore(aid string, raw json.RawMessage) (json.RawMessage, error) {
	var stored []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return raw, nil
	}
	if err != nil {
		return nil, err
	}
	w, withdrawn := parseWithdrawal(stored)
	if !withdrawn {
		return raw, nil
	}
	published, err := s.federatesCard(aid)
	if err != nil {
		return nil, err
	}
	if published {
		return raw, nil
	}
	w.Card = raw
	w.At = nowStamp()
	return marshalWithdrawal(w)
}

func (s *Store) cardHighWater(aid string) (uint64, error) {
	var seq uint64
	err := s.db.QueryRow(`SELECT seq FROM agent_card WHERE aid=?`, aid).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return seq, err
}

// AgentCard returns the signed card an agent published, if any.
func (s *Store) AgentCard(aid string) (json.RawMessage, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	// A withdrawn row still answers for the agent here when it has a card
	// to answer with. Narrowing a visibility means "do not tell other
	// hubs about me", not "stop being an agent on this one"; a
	// deregistration means both, and its withdrawal carries no card.
	if w, withdrawn := parseWithdrawal(raw); withdrawn {
		return w.Card, nil
	}
	return json.RawMessage(raw), nil
}

// federatesCard reports whether this hub currently publishes this agent's
// card to peers. An agent that is not registered here publishes nothing.
func (s *Store) federatesCard(aid string) (bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT visibility FROM agent WHERE aid=?`, aid).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return federates(v), nil
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

// federates reports whether a tier means "tell other hubs".
func federates(v string) bool {
	return v == VisibilityFederated || v == VisibilityPublic
}

// SetVisibility records how far an agent is willing to be published, and
// moves its card on the federation stream to match.
//
// The move is the half that was missing. /fed/v1/cards is an increment
// ordered by fed_seq — a peer asks for what changed after the cursor it
// holds — and this wrote agent.visibility without touching
// agent_card.fed_seq. Opting in therefore reached a peer whose cursor had
// already passed the row only when the periodic full re-read came round,
// about half an hour later; opting out never reached it at all, because a
// row the query stops selecting produces no entry to read. A visibility
// change is a change to the facts about this card, and the stream is
// defined as the changes after a cursor.
func (s *Store) SetVisibility(aid, v string) error {
	if !validVisibility(v) {
		return fmt.Errorf("hub: unknown visibility %q", v)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var before string
	err := s.db.QueryRow(`SELECT visibility FROM agent WHERE aid=?`, aid).Scan(&before)
	if errors.Is(err, sql.ErrNoRows) {
		// Refused rather than silently applied. The UPDATE matches no row
		// for an agent that is not registered here, and reporting success
		// left the caller unable to tell a visibility that took effect
		// from one that went nowhere. It also keeps a departed agent's
		// withdrawal out of reach of a caller that could otherwise
		// republish the card it withdrew.
		return fmt.Errorf("hub: %s is not registered here", aid)
	}
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE agent SET visibility=? WHERE aid=?`, v, aid); err != nil {
		return err
	}
	if before == v {
		// Nothing changed, so nothing is owed to a peer. Bumping fed_seq
		// on a no-op would put a re-send of an unchanged card in front of
		// every peer each time a node re-asserted its settings.
		return nil
	}
	if federates(before) && !federates(v) {
		return withdrawCard(s.db, aid, withdrawNotFederated, true)
	}
	// Opting in, or moving between two published tiers: either way the
	// card belongs on the stream again, and a standing withdrawal is
	// lifted here because this is where the agent asks to be published.
	return s.republishCard(aid)
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

// ---- withdrawing a card from the federation stream ----

// A withdrawal is how this hub says it has STOPPED publishing a card.
//
// /fed/v1/cards is an increment ordered by fed_seq: a peer asks for what
// changed after the cursor it holds. Both ways of un-publishing a card
// used to be expressed as a row that stops matching — deregistration ran
// DELETE FROM agent_card, and narrowing a visibility left the row in place
// but outside the query's WHERE — and a row that stops matching produces
// no entry at all. A peer whose cursor was already past it therefore
// learned nothing, kept its copy, and went on publishing an agent this hub
// no longer publishes, with no mechanism that could ever correct it.
// Found by reading both paths against the cursor contract they feed.
//
// A withdrawal is this hub's own statement, not an adp.CardTombstone. A
// tombstone is self-signed by its subject (ADP §2.3, §5.4) and this hub
// does not hold the agent's key: the deregistration challenge signs an
// action and a timestamp, not a revocation, so there is nothing here to
// build a conformant one from. The authority a withdrawal needs is the
// authority a peer already extends to this hub's directory — a hub may
// decline to publish a card at all, and this is that same decision taken
// later.
//
// The cost, stated rather than hidden: a hub that lied could make one of
// its own agents disappear from a peer's directory. It could equally have
// never published the card. What it still cannot do is publish anything
// the agent did not sign, which is the property the signature carries and
// which none of this touches.
const withdrawAction = "withdraw"

// withdrawalPrefix is the first bytes of every marshalled withdrawal.
//
// Exact because Action is declared first in fedWithdrawal and
// encoding/json emits struct fields in declaration order. It exists so
// CardsSince can select withdrawals in SQL alongside published cards;
// filtering in Go alone would mean reading every row after the cursor, and
// on a hub whose agents are mostly hub-local — the default tier — a peer
// would spend dozens of two-minute rounds walking unpublished rows before
// reaching the first card it can use. The prefix is a pre-filter only:
// parseWithdrawal decides what a selected row actually is, so a card that
// happened to start with these bytes is skipped rather than served.
const withdrawalPrefix = `{"action":"withdraw"`

// Why a card stopped being published.
const (
	withdrawDeparted     = "deregistered"
	withdrawNotFederated = "visibility-narrowed"
)

// fedWithdrawal is both the agent_card row and the sync-stream entry.
//
// One shape for both because the column is what the stream serves: a peer
// receives these bytes, and there is no second place for the row to say
// something the stream does not.
//
// Card is the exception and never travels — wire() strips it. An agent
// that narrowed its visibility is still an agent here: /agents/{aid}/card
// and the payment gateway both read this column, and dropping the card
// would make "do not tell other hubs about me" also mean "stop working
// here". A departed agent's withdrawal carries no card, because the
// routing is exactly what leaving gives up.
type fedWithdrawal struct {
	Action  string          `json:"action"`
	AgentID string          `json:"agent_id"`
	Reason  string          `json:"reason,omitempty"`
	At      string          `json:"at,omitempty"`
	Card    json.RawMessage `json:"card,omitempty"`
}

// wire is what a peer receives: the withdrawal without the card it
// withdraws.
func (w fedWithdrawal) wire() (json.RawMessage, error) {
	w.Card = nil
	return marshalWithdrawal(w)
}

func marshalWithdrawal(w fedWithdrawal) (json.RawMessage, error) {
	w.Action = withdrawAction
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// parseWithdrawal reports whether some stored or received bytes are a
// withdrawal rather than a card.
//
// Two keys are tested, not one. A card is stored exactly as its signer
// sent it — the ADP pre-image covers the struct, so unknown JSON keys ride
// along unsigned — and an agent could therefore put "action":"withdraw"
// inside its own card. No card can be missing subject_did, because
// AdmitCard refuses a card whose subject is not the registrant. Testing
// the action alone would let an agent forge a withdrawal for itself, and
// on the receiving side for anyone.
func parseWithdrawal(raw []byte) (fedWithdrawal, bool) {
	if len(raw) == 0 {
		return fedWithdrawal{}, false
	}
	var probe struct {
		Action     string `json:"action"`
		SubjectDID string `json:"subject_did"`
	}
	if json.Unmarshal(raw, &probe) != nil ||
		probe.Action != withdrawAction || probe.SubjectDID != "" {
		return fedWithdrawal{}, false
	}
	var w fedWithdrawal
	if json.Unmarshal(raw, &w) != nil {
		return fedWithdrawal{}, false
	}
	return w, true
}

// cardStore is the subset of *sql.DB and *sql.Tx these helpers use, so the
// same code runs inside the deregistration transaction and outside it.
type cardStore interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// bumpCard rewrites a card row and moves it to the head of the federation
// stream.
//
// The move is the point. fed_seq is the stream's only ordering, so a
// change that leaves fed_seq alone is a change no peer past that row can
// observe, however plainly the row now says something else.
func bumpCard(x cardStore, aid string, card json.RawMessage) error {
	var next int64
	if err := x.QueryRow(`SELECT COALESCE(MAX(fed_seq),0)+1 FROM agent_card`).Scan(&next); err != nil {
		return err
	}
	_, err := x.Exec(`UPDATE agent_card SET card=?, stored_at=?, fed_seq=? WHERE aid=?`,
		[]byte(card), nowStamp(), next, aid)
	return err
}

// withdrawCard stops publishing an agent's card and tells the peers.
//
// wasPublished is the visibility BEFORE the change that prompted this, and
// it has to be passed rather than read: SetVisibility has already written
// the new tier by the time it gets here, and reading it back would say
// "never published" about the card it is in the middle of withdrawing.
//
// A card that was never on the stream is removed instead of withdrawn. A
// withdrawal names an AID, and announcing one for an agent no peer was
// ever told about would publish on the way out exactly what the hub-local
// tier existed to keep unpublished.
func withdrawCard(x cardStore, aid, reason string, wasPublished bool) error {
	var stored []byte
	err := x.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	w, already := parseWithdrawal(stored)
	if !already && !wasPublished {
		_, derr := x.Exec(`DELETE FROM agent_card WHERE aid=?`, aid)
		return derr
	}
	if !already {
		w = fedWithdrawal{AgentID: aid, Card: json.RawMessage(stored)}
	}
	if reason == withdrawDeparted {
		w.Card = nil
	}
	w.Reason = reason
	w.At = nowStamp()
	b, merr := marshalWithdrawal(w)
	if merr != nil {
		return merr
	}
	return bumpCard(x, aid, b)
}

// republishCard puts an agent's card back on the stream: it lifts a
// standing withdrawal when there is one, and moves the row either way so a
// peer that has already read past it learns the card is published again.
func (s *Store) republishCard(aid string) error {
	var stored []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		// A node from before cards, or one that has not sent one yet.
		// Its next card carries its own fed_seq.
		return nil
	}
	if err != nil {
		return err
	}
	card := json.RawMessage(stored)
	if w, withdrawn := parseWithdrawal(stored); withdrawn {
		if len(w.Card) == 0 {
			// A departed agent's withdrawal has no card to restore. The
			// row stays a withdrawal and is re-announced, because a peer
			// that has not read it yet still has to drop what it holds.
			w.At = nowStamp()
			b, merr := marshalWithdrawal(w)
			if merr != nil {
				return merr
			}
			return bumpCard(s.db, aid, b)
		}
		card = w.Card
	}
	return bumpCard(s.db, aid, card)
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
	// LEFT JOIN, and a second arm on the WHERE, because a withdrawal has
	// to be served in exactly the two cases the old JOIN + visibility test
	// discarded: the agent row is gone (it deregistered) and the agent row
	// says hub-local (it narrowed). Those are the rows that make a
	// withdrawal necessary, and the query carrying the cards excluded
	// precisely them.
	//
	// The prefix test is a pre-filter, not the decision. parseWithdrawal
	// below decides what a row is, so a card whose unsigned JSON happens
	// to start with these bytes is dropped by the visibility test rather
	// than served as a withdrawal.
	rows, err := s.db.Query(
		`SELECT c.card, c.fed_seq, a.kel, COALESCE(a.visibility,'')
		   FROM agent_card c LEFT JOIN agent a ON a.aid = c.aid
		  WHERE c.fed_seq > ?
		    AND (a.visibility IN (?, ?) OR CAST(c.card AS TEXT) LIKE ?)
		  ORDER BY c.fed_seq LIMIT ?`,
		cursor, VisibilityFederated, VisibilityPublic, withdrawalPrefix+"%", limit)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	out := []FedCard{}
	next := cursor
	for rows.Next() {
		var card, kel []byte
		var seq int64
		var visibility string
		if err := rows.Scan(&card, &seq, &kel, &visibility); err != nil {
			return nil, cursor, err
		}
		// The cursor advances past every row the query returned, whether
		// or not it produced an entry. A row selected by the prefix test
		// and then rejected would otherwise be re-read for ever.
		next = seq
		if w, withdrawn := parseWithdrawal(card); withdrawn {
			b, merr := w.wire()
			if merr != nil {
				return nil, cursor, merr
			}
			// No key history travels with a withdrawal: there is no
			// signature in it to check, and a departed agent has no agent
			// row left to take one from.
			out = append(out, FedCard{Card: b, Home: home, FedSeq: seq})
			continue
		}
		if !federates(visibility) {
			continue
		}
		out = append(out, FedCard{
			Card: json.RawMessage(card), KEL: base64.StdEncoding.EncodeToString(kel),
			Home: home, FedSeq: seq,
		})
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
	if w, withdrawn := parseWithdrawal(fc.Card); withdrawn {
		return s.retireFedCard(peerAID, w)
	}
	var card adp.AgentCard
	if err := json.Unmarshal(fc.Card, &card); err != nil {
		return fmt.Errorf("federated card malformed: %w", err)
	}
	// A peer hub is not a trusted input. It applies its own limits to
	// what it admits, but nothing makes its limits ours, and a card
	// learned from a peer lands in the same /agents responses as a local
	// one.
	if err := validateCaps(card.Capabilities); err != nil {
		return fmt.Errorf("federated card refused: %w", err)
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
		// Transient, and saying so matters. This agent is registered here
		// TODAY; if it leaves tomorrow the peer's card becomes admissible
		// and the sync must be able to pick it up. A caller that treated
		// every refusal alike would advance its cursor past this card and
		// never see it again — which is exactly what happened in
		// production, and the agent stayed missing from the directory
		// long after the reason had gone away.
		return fmt.Errorf("%w: %s is registered here", federation.ErrRefusedForNow, card.SubjectDID)
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

// retireFedCard drops a peer-learned card that its home hub has stopped
// publishing.
//
// Scoped to the peer that taught us the card. fed_card records where each
// row came from, and without that test any peer could clear another peer's
// agents out of this directory by announcing withdrawals for them. A hub
// may retract what it published and nothing else — the same boundary that
// lets it hide a card without being able to invent one.
//
// A withdrawal for an agent registered HERE is therefore also harmless: it
// can only reach fed_card, never the local registry.
func (s *Store) retireFedCard(peerAID string, w fedWithdrawal) error {
	if w.AgentID == "" {
		return fmt.Errorf("federated withdrawal names no agent")
	}
	_, err := s.db.Exec(`DELETE FROM fed_card WHERE aid=? AND peer_aid=?`, w.AgentID, peerAID)
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
