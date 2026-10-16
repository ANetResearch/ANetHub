package aghub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
)

// What the federation card stream shares with the rest of the kernel: the
// visibility tiers an agent chooses, the withdrawal a hub publishes when it
// stops publishing a card, the key set that travels with a card, and the
// Directory seam the federation module reads the kernel through.
//
// The stream itself is the A2A card stream (fed_a2acard.go). The signed
// ADP card and its stream are gone with the public prices they carried: an
// agent's directory entry is its signed A2A card, verified here at
// registration (a2acard.go).

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
// moves its A2A card on the federation stream to match.
//
// The move is half of the change. The stream is an increment ordered by
// fed_seq — a peer asks for what changed after the cursor it holds — so a
// visibility written without moving the card would reach a peer whose
// cursor had passed the row only at the next full re-read when opting in,
// and never when opting out, because a row the query stops selecting
// produces no entry to read.
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
		// from one that went nowhere.
		return fmt.Errorf("hub: %s is not registered here", aid)
	}
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE agent SET visibility=? WHERE aid=?`, v, aid); err != nil {
		return err
	}
	if before == v {
		// Nothing changed, so nothing is owed to a peer. Moving the card
		// on a no-op would put a re-send of an unchanged card in front of
		// every peer each time a node re-asserted its settings.
		return nil
	}
	return a2aVisibilityChanged(s.db, aid, before, v)
}

// ---- withdrawing a card from the federation stream ----

// A withdrawal is how this hub says it has STOPPED publishing a card.
//
// The stream is an increment ordered by fed_seq, and a card that stops
// being published by its row simply ceasing to match produces no entry at
// all: a peer whose cursor was already past it would keep its copy and go
// on publishing an agent this hub no longer publishes. So stopping is an
// entry of its own (a2a_card_withdrawal, fed_a2acard.go).
//
// A withdrawal is this hub's own statement, not something the agent
// signed: this hub does not hold the agent's key. The authority it needs is
// the authority a peer already extends to this hub's directory — a hub may
// decline to publish a card at all, and this is that same decision taken
// later. A hub that lied could make one of its own agents disappear from a
// peer's directory; it could equally have never published the card. What
// it still cannot do is publish anything the agent did not sign.
const withdrawAction = "withdraw"

// Why a card stopped being published (and withdrawDelisted, fed_a2acard.go).
const (
	withdrawDeparted     = "deregistered"
	withdrawNotFederated = "visibility-narrowed"
)

// fedWithdrawal is a withdrawal as the stream serves it. The entry's
// format (federation.FormatWithdrawal) says it is one; nothing an agent
// signs can make its card read as a withdrawal.
type fedWithdrawal struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	Reason  string `json:"reason,omitempty"`
	At      string `json:"at,omitempty"`
}

// wire is the withdrawal's stream bytes.
func (w fedWithdrawal) wire() (json.RawMessage, error) {
	w.Action = withdrawAction
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// cardStore is the subset of *sql.DB and *sql.Tx the stream helpers use, so
// the same code runs inside the deregistration transaction and outside it.
type cardStore interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// ---- the key set that travels with a card ----

// fedKeysToStore decides which key set a peer-learned card's row keeps
// after a stream entry for aid arrives.
//
// The entry's key set is advisory: a card is admitted whether or not its
// keys verify, and keys that fail are not stored. Accepted keys follow the
// consumer rule of §3.1: a higher seq replaces the stored set, an equal
// seq with identical set bytes is the same set, a lower seq or an equal
// seq with different content is ignored. In every case the set must pass
// seal.VerifyEncKeySet with expectAID = aid against the entry's KEL, so a
// peer cannot attach another AID's keys to this card.
func fedKeysToStore(aid string, incoming, stored []byte, kel []identity.SignedEvent) []byte {
	if len(incoming) == 0 {
		return stored
	}
	signed, err := seal.UnmarshalSignedEncKeySet(incoming)
	if err != nil {
		return stored
	}
	var seen *seal.Seen
	if len(stored) > 0 {
		if prev, perr := seal.UnmarshalSignedEncKeySet(stored); perr == nil {
			if set, serr := decodeEncKeySet(prev.Set); serr == nil {
				seen = &seal.Seen{Seq: set.Seq, Set: prev.Set}
			}
			// A stored set signed under a key state the entry's KEL has since retired
			// binds nothing and can never be used again: its seq is no floor against a lower one. Kept as
			// one, whoever held the old key could pin the floor out of the owner's
			// reach (T-1 RT-F1c).
			if offered, oerr := decodeEncKeySet(signed.Set); seen != nil && oerr == nil && seen.Seq > offered.Seq {
				if _, verr := seal.VerifyEncKeySet(prev, aid, kel, uint64(time.Now().UnixMilli())); verr != nil &&
					seal.ReasonOf(verr) == seal.ReasonBadKeyState {
					seen = nil
				}
			}
		}
	}
	d, err := seal.DecideHighWaterSigned(seen, signed)
	if err != nil || (d != seal.Replace && d != seal.Same) {
		return stored
	}
	if _, err := seal.VerifyEncKeySet(signed, aid, kel, uint64(time.Now().UnixMilli())); err != nil {
		return stored
	}
	canon, err := signed.Marshal()
	if err != nil {
		return stored
	}
	return canon
}

// decodeEncKeySet reads the seq of a stored set. The encoding is
// CoreDet-CBOR, which seal decodes; DecideHighWaterSigned exposes only the
// decision, so the stored seq is read here.
func decodeEncKeySet(set []byte) (*seal.EncKeySet, error) {
	var ks seal.EncKeySet
	if err := coredet.Unmarshal(set, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// ---- the Directory seam ----

// FedDirectory adapts the store to federation's Directory seam, so the
// federation module never imports the kernel's internals.
//
// PeerKEL resolves a peer hub's key history (federation.Service.PeerKEL):
// a peer's review comes with that peer's attestation, which is checked
// against it (CORE-L8). Without it no peer's review is admitted.
type FedDirectory struct {
	S       *Store
	PeerKEL func(peerAID string) ([]identity.SignedEvent, error)
}

// ReviewsSince and AdmitFedReview complete the Directory seam (the card
// stream's half is in fed_a2acard.go). Federation carries the bytes; what
// a review means stays here (reviews.go), because a module with an opinion
// about reputation is a module that would need to be trusted about it.
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

// AdmitFedReview admits one entry of peerAID's review stream. Members it
// does not know are ignored: what is stored is only what was checked.
func (d FedDirectory) AdmitFedReview(peerAID string, raw json.RawMessage) error {
	var e FedReviewEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("the review stream entry is not JSON of the review/2 shape: %w", err)
	}
	var kel []identity.SignedEvent
	if d.PeerKEL != nil {
		k, err := d.PeerKEL(peerAID)
		if err != nil {
			return fmt.Errorf("%w: the key history of %s: %v", federation.ErrRefusedForNow, peerAID, err)
		}
		kel = k
	}
	return d.S.AdmitFedReview(peerAID, kel, e)
}

var _ federation.Directory = FedDirectory{}

// FederatedAgents returns agents learned from peer hubs, for discovery:
// the listed A2A cards of fed_a2a_card, named and with the capability ids
// of their cards.
//
// Kept separate from the local directory and marked with their home hub:
// which hub an agent lives on decides where work for it is delivered, and
// a directory that forgot would answer with agents it cannot reach.
func (s *Store) FederatedAgents(capFilter string) ([]AgentView, error) {
	return s.federatedA2AAgents(capFilter)
}

// capsServe applies the exact/prefix/comma rules the local index uses
// (Store.FindByCapability) to a peer-learned agent's capability ids, so a
// federated agent answers the same question a local one does.
func capsServe(caps []string, filter string) bool {
	for _, term := range strings.Split(filter, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		for _, c := range caps {
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
