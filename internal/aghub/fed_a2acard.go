package aghub

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/federation"
)

// Federation of A2A cards: GET /fed/v2/cards (A2A-DESIGN §10.6).
//
// Publishing side: the stream serves, in fed_seq order, the A2A cards of
// agents registered here that passed admission (a2acard.go), are still
// listed (verified_at set) and opted into federation (visibility
// federated or public), each with the agent's KEL and encryption key set;
// and a withdrawal for every card this hub stopped publishing. A
// withdrawal is a row of a2a_card_withdrawal, written when the agent
// leaves, narrows its visibility, or its card stops verifying against its
// KEL. agent_a2a_card and a2a_card_withdrawal share one fed_seq sequence
// (nextA2AFedSeq), so one cursor orders both.
//
// The same invariant as v1 (card.go) keeps the stream truthful: a card
// becomes publishable again only with a new fed_seq, above any withdrawal
// of it, so a peer reading in order ends with the card. The withdrawal is
// then deleted, because the card entry supersedes it for every peer
// whatever its cursor.
//
// Receiving side: fed_a2a_card holds the cards learned from peers, kept
// apart from the local registry like fed_card. Admission is the local
// admission (verifyA2ACardFor, a2acard.CheckHighWater) with the entry's
// KEL as the resolver, after the KEL extension rule of §3.8. A withdrawal
// does not delete the row: it delists it and keeps the high-water mark and
// the KEL, so that the peer that withdrew a card cannot then republish an
// older one, or one over a shorter KEL, as though it were new.

// Why a card stopped being published, beyond the two reasons card.go has.
const withdrawDelisted = "card-no-longer-verifies"

// migrateFedA2ACard creates the tables of the A2A card stream.
func (s *Store) migrateFedA2ACard() error {
	for _, q := range []string{
		// Cards this hub stopped publishing, one row per agent, on the
		// agent_a2a_card fed_seq sequence.
		`CREATE TABLE IF NOT EXISTS a2a_card_withdrawal (
		   aid TEXT PRIMARY KEY,
		   reason TEXT NOT NULL,
		   at TEXT NOT NULL,
		   fed_seq INTEGER NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_a2a_withdrawal_fedseq ON a2a_card_withdrawal(fed_seq)`,
		// A2A cards learned from peers. verified_at NULL: withdrawn by
		// the peer that taught it; the row is then the high-water mark
		// and the KEL, and is not listed. home is where the agent lives:
		// the card's relay interface when it names one, else the entry's
		// home. name and caps are the card's name and skill ids, for
		// /agents.
		`CREATE TABLE IF NOT EXISTS fed_a2a_card (
		   aid TEXT PRIMARY KEY,
		   seq INTEGER NOT NULL,
		   payload_hash BLOB NOT NULL,
		   card BLOB NOT NULL,
		   kel BLOB NOT NULL,
		   keys BLOB,
		   home TEXT NOT NULL,
		   peer_aid TEXT NOT NULL,
		   name TEXT NOT NULL DEFAULT '',
		   caps TEXT NOT NULL DEFAULT '[]',
		   search TEXT NOT NULL DEFAULT '',
		   verified_at TEXT,
		   stored_at TEXT NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS fed_a2a_skill (
		   aid TEXT NOT NULL,
		   skill_id TEXT NOT NULL,
		   PRIMARY KEY (aid, skill_id)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_fed_a2a_skill ON fed_a2a_skill(skill_id)`,
		`CREATE TABLE IF NOT EXISTS fed_a2a_tag (
		   aid TEXT NOT NULL,
		   tag TEXT NOT NULL,
		   PRIMARY KEY (aid, tag)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_fed_a2a_tag ON fed_a2a_tag(tag)`,
	} {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate federated a2a card: %w", err)
		}
	}
	return nil
}

// ---- publishing ----

// FedA2ACard is one entry of the A2A card stream as the store serves it.
// Card is the agent's card bytes, or for FormatWithdrawal the withdrawal
// (fedWithdrawal without a card); KEL and Keys are empty on a withdrawal.
type FedA2ACard struct {
	Format string
	Card   json.RawMessage
	KEL    []byte
	Keys   []byte
	Home   string
	FedSeq int64
}

// A2ACardsSince serves the A2A card stream after cursor: at most limit
// entries, and the cursor to ask after next.
//
// One hop, as CardsSince: only cards registered here, never cards learned
// from a peer.
func (s *Store) A2ACardsSince(cursor int64, limit int, home string) ([]FedA2ACard, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT kind, aid, fed_seq, card, kel, keyset, reason, at FROM (
		   SELECT 1 AS kind, c.aid AS aid, c.fed_seq AS fed_seq, c.card AS card, a.kel AS kel,
		          k.keyset AS keyset, '' AS reason, '' AS at
		     FROM agent_a2a_card c JOIN agent a ON a.aid = c.aid
		     LEFT JOIN agent_keys k ON k.aid = c.aid
		    WHERE c.fed_seq > ? AND c.verified_at IS NOT NULL AND a.visibility IN (?, ?)
		   UNION ALL
		   SELECT 2, w.aid, w.fed_seq, NULL, NULL, NULL, w.reason, w.at
		     FROM a2a_card_withdrawal w WHERE w.fed_seq > ?
		 ) ORDER BY fed_seq LIMIT ?`,
		cursor, VisibilityFederated, VisibilityPublic, cursor, limit)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	out := []FedA2ACard{}
	next := cursor
	for rows.Next() {
		var kind int
		var aid, reason, at string
		var seq int64
		var card, kel, keys []byte
		if err := rows.Scan(&kind, &aid, &seq, &card, &kel, &keys, &reason, &at); err != nil {
			return nil, cursor, err
		}
		next = seq
		if kind == 2 {
			b, err := fedWithdrawal{AgentID: aid, Reason: reason, At: at}.wire()
			if err != nil {
				return nil, cursor, err
			}
			out = append(out, FedA2ACard{Format: federation.FormatWithdrawal, Card: b, Home: home, FedSeq: seq})
			continue
		}
		out = append(out, FedA2ACard{Format: federation.FormatA2ACard, Card: json.RawMessage(card),
			KEL: kel, Keys: keys, Home: home, FedSeq: seq})
	}
	return out, next, rows.Err()
}

// cardStore is satisfied by *sql.DB and *sql.Tx (card.go).

// withdrawA2ACard records that this hub stopped publishing aid's A2A card,
// at the head of the stream. Called only for an agent whose visibility
// federated, so the withdrawal names no AID that was not already
// published; and only when a card row exists, since without one there is
// nothing a peer could hold (a withdrawal already written stays).
func withdrawA2ACard(x cardStore, aid, reason string) error {
	var n int
	if err := x.QueryRow(`SELECT COUNT(1) FROM agent_a2a_card WHERE aid=?`, aid).Scan(&n); err != nil || n == 0 {
		return err
	}
	next, err := nextA2AFedSeq(x)
	if err != nil {
		return err
	}
	_, err = x.Exec(
		`INSERT INTO a2a_card_withdrawal(aid, reason, at, fed_seq) VALUES(?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET reason=excluded.reason, at=excluded.at, fed_seq=excluded.fed_seq`,
		aid, reason, nowStamp(), next)
	return err
}

// clearA2AWithdrawal deletes aid's withdrawal once the card is published
// again after it: listed, from an agent that federates, at a later
// fed_seq. Any other state leaves the withdrawal standing.
func clearA2AWithdrawal(x cardStore, aid string) error {
	_, err := x.Exec(
		`DELETE FROM a2a_card_withdrawal
		  WHERE aid = ?
		    AND fed_seq < (SELECT c.fed_seq FROM agent_a2a_card c JOIN agent a ON a.aid = c.aid
		                    WHERE c.aid = ? AND c.verified_at IS NOT NULL AND a.visibility IN (?, ?))`,
		aid, aid, VisibilityFederated, VisibilityPublic)
	return err
}

// bumpA2ACard moves aid's listed A2A card to the head of the stream, for
// a change the entry carries that is not in the card (the visibility that
// makes it published, the key set), and lifts a withdrawal it supersedes.
func bumpA2ACard(x cardStore, aid string) error {
	var n int
	if err := x.QueryRow(`SELECT COUNT(1) FROM agent_a2a_card WHERE aid=? AND verified_at IS NOT NULL`,
		aid).Scan(&n); err != nil || n == 0 {
		return err
	}
	next, err := nextA2AFedSeq(x)
	if err != nil {
		return err
	}
	if _, err := x.Exec(`UPDATE agent_a2a_card SET fed_seq=? WHERE aid=?`, next, aid); err != nil {
		return err
	}
	return clearA2AWithdrawal(x, aid)
}

// a2aVisibilityChanged moves aid's A2A card on the stream after its
// visibility changed from before to after (SetVisibility).
func a2aVisibilityChanged(x cardStore, aid, before, after string) error {
	switch {
	case federates(before) && !federates(after):
		return withdrawA2ACard(x, aid, withdrawNotFederated)
	case !federates(before) && federates(after):
		return bumpA2ACard(x, aid)
	}
	return nil
}

// agentFederates reports whether aid is registered here with a visibility
// that federates.
func agentFederates(q rowQuerier, aid string) (bool, error) {
	var v string
	err := q.QueryRow(`SELECT visibility FROM agent WHERE aid=?`, aid).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return federates(v), err
}

// ---- receiving ----

// AdmitFedA2ACard admits one A2A card stream entry learned from peerAID,
// dispatching on its format. The sync loop passes only FormatA2ACard and
// FormatWithdrawal; any other is refused here.
//
// A card entry is admitted in this order: the entry's KEL decodes and
// replays; the card verifies against it for the AID it replays to (the
// local admission, verifyA2ACardFor); that agent is not registered here
// (federation.ErrRefusedForNow otherwise); the KEL extends the one held
// for it (§3.8); the card passes the params.seq high-water rule against
// the one held. Its key set is kept only if it verifies (fedKeysToStore).
// Where the agent lives is read from the card's relay interface; the
// entry's home is used when the card names none, and a disagreement is
// logged (§10.6: the card wins).
func (s *Store) AdmitFedA2ACard(peerAID string, e FedA2ACard) error {
	switch e.Format {
	case federation.FormatWithdrawal:
		return s.retireFedA2ACard(peerAID, e.Card)
	case federation.FormatA2ACard:
	default:
		return fmt.Errorf("federated A2A card entry in unknown format %q", e.Format)
	}
	kel, err := identity.UnmarshalKEL(e.KEL)
	if err != nil {
		return fmt.Errorf("federated A2A card refused: kel malformed: %w", err)
	}
	states, err := identity.Replay(kel)
	if err != nil || len(states) == 0 {
		return fmt.Errorf("federated A2A card refused: kel does not replay: %v", err)
	}
	aid := states[len(states)-1].AID
	now := time.Now()
	// Verify is pure, so it runs before the store mutex is taken. The
	// resolver answers only for the AID the entry's KEL replays to, so a
	// card speaking for anyone else fails as BINDING_MISMATCH.
	v, err := verifyA2ACardFor(aid, e.Card, kel, now)
	if err != nil {
		return fmt.Errorf("federated A2A card refused: %w", err)
	}
	home := fedA2AHome(aid, peerAID, e.Card, e.Home)
	caps, err := json.Marshal(skillIDs(v))
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// An agent registered HERE speaks for itself, as for AdmitFedCard;
	// and the refusal is for now, so the sync holds its cursor.
	var local int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, aid).Scan(&local); err != nil {
		return err
	}
	if local > 0 {
		return fmt.Errorf("%w: %s is registered here", federation.ErrRefusedForNow, aid)
	}
	var (
		storedSeq                         uint64
		storedHash, storedKEL, storedKeys []byte
		storedPeer                        string
		storedVerified                    sql.NullString
	)
	err = tx.QueryRow(`SELECT seq, payload_hash, kel, keys, peer_aid, verified_at FROM fed_a2a_card WHERE aid=?`, aid).
		Scan(&storedSeq, &storedHash, &storedKEL, &storedKeys, &storedPeer, &storedVerified)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var mark *a2acard.Mark
	if found {
		old, uerr := identity.UnmarshalKEL(storedKEL)
		if uerr != nil {
			return fmt.Errorf("stored federated kel for %s undecodable: %w", aid, uerr)
		}
		if err := identity.ExtendsKEL(old, kel); err != nil {
			return fmt.Errorf("federated A2A card refused: its key history does not extend the stored one: %w", err)
		}
		if len(storedHash) == 32 {
			mark = &a2acard.Mark{Seq: storedSeq}
			copy(mark.PayloadHash[:], storedHash)
		}
	}
	decision, err := a2acard.CheckHighWater(mark, v.Mark())
	if err != nil {
		return fmt.Errorf("federated A2A card refused: %w", err)
	}
	listed := found && storedVerified.Valid
	if decision == a2acard.Same && listed && peerAID != storedPeer {
		// The card already held, from a peer that did not teach it: the
		// statement is not new, and only the teaching peer updates the
		// row (its KEL and key set) or withdraws it.
		return nil
	}
	// A withdrawn row keeps no key set (retireFedA2ACard cleared it), so
	// a relisted card starts from the one its entry carries. On the same
	// statement in other bytes (re-signed under a rotated key) the new
	// bytes replace the stored ones, which may no longer verify.
	keys := fedKeysToStore(aid, b64(e.Keys), storedKeys, kel)
	card := e.Card
	if _, err := tx.Exec(
		`INSERT INTO fed_a2a_card(aid, seq, payload_hash, card, kel, keys, home, peer_aid, name, caps, search, verified_at, stored_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, payload_hash=excluded.payload_hash, card=excluded.card,
		   kel=excluded.kel, keys=excluded.keys, home=excluded.home, peer_aid=excluded.peer_aid, name=excluded.name,
		   caps=excluded.caps, search=excluded.search, verified_at=excluded.verified_at, stored_at=excluded.stored_at`,
		aid, v.Seq, v.PayloadHash[:], []byte(card), e.KEL, keys, home, peerAID, v.Name, string(caps),
		cardSearchText(card, v), verifiedStamp(now), nowStamp()); err != nil {
		return err
	}
	if err := indexFedA2ACard(tx, aid, v); err != nil {
		return err
	}
	return tx.Commit()
}

// retireFedA2ACard applies a withdrawal from peerAID: the card it taught is
// delisted, its key set and index rows removed, and the high-water mark
// and KEL kept. Scoped to the peer that taught the card, as
// retireFedCard: a hub may retract what it published and nothing else.
func (s *Store) retireFedA2ACard(peerAID string, raw []byte) error {
	var w fedWithdrawal
	if err := json.Unmarshal(raw, &w); err != nil || w.Action != withdrawAction || w.AgentID == "" {
		return fmt.Errorf("federated A2A withdrawal malformed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE fed_a2a_card SET verified_at=NULL, keys=NULL, stored_at=?
	                      WHERE aid=? AND peer_aid=? AND verified_at IS NOT NULL`,
		nowStamp(), w.AgentID, peerAID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	for _, q := range []string{
		`DELETE FROM fed_a2a_skill WHERE aid=?`,
		`DELETE FROM fed_a2a_tag WHERE aid=?`,
	} {
		if _, err := tx.Exec(q, w.AgentID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// indexFedA2ACard rebuilds aid's fed_a2a_skill and fed_a2a_tag rows.
func indexFedA2ACard(tx *sql.Tx, aid string, v *a2acard.Verified) error {
	for _, q := range []string{
		`DELETE FROM fed_a2a_skill WHERE aid=?`,
		`DELETE FROM fed_a2a_tag WHERE aid=?`,
	} {
		if _, err := tx.Exec(q, aid); err != nil {
			return err
		}
	}
	for _, sk := range v.Skills {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO fed_a2a_skill(aid, skill_id) VALUES(?,?)`, aid, sk.ID); err != nil {
			return err
		}
		for _, tag := range sk.Tags {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO fed_a2a_tag(aid, tag) VALUES(?,?)`, aid, tag); err != nil {
				return err
			}
		}
	}
	return nil
}

// fedA2AHome is where a federated agent lives: the hub its card's relay
// interface names (the daemon writes <hub>/relay), or the entry's home when
// the card names no relay interface or one that is not an http(s) URL.
// When the two disagree the card wins (A2A-DESIGN §10.6) and the
// disagreement is logged: it is the agent's signed statement against the
// peer's.
func fedA2AHome(aid, peerAID string, card []byte, entryHome string) string {
	relay := cardRelayHub(card)
	if relay == "" {
		return entryHome
	}
	if hubKey(relay) != hubKey(entryHome) {
		log.Printf("hub: federated A2A card of %s from %s names home %q, its card's relay interface %q; using the card's",
			aid, peerAID, entryHome, relay)
	}
	return relay
}

// cardRelayHub is the hub base URL of a card's first anet relay
// interface: its url without the trailing /relay. Empty when the card has
// none or its url is not an absolute http(s) URL.
//
// Read with encoding/json: Verify has refused cards whose member names
// collide under case folding, so this reads the members Verify checked.
func cardRelayHub(card []byte) string {
	var c struct {
		SupportedInterfaces []struct {
			URL             string `json:"url"`
			ProtocolBinding string `json:"protocolBinding"`
		} `json:"supportedInterfaces"`
	}
	if json.Unmarshal(card, &c) != nil {
		return ""
	}
	for _, it := range c.SupportedInterfaces {
		if it.ProtocolBinding != a2acard.BindingRelayURI {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(it.URL))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return ""
		}
		// Scheme, host and path only: no credentials, query or fragment
		// from the card reach the directory.
		return strings.TrimSuffix(strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), "/relay")
	}
	return ""
}

// hubKey normalises a hub URL for comparison: scheme and host lowercased,
// no trailing slash.
func hubKey(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/")
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// FedA2ACardKeys returns the key set and KEL of a listed A2A card learned
// from a peer, or sql.ErrNoRows.
func (s *Store) FedA2ACardKeys(aid string) (keyset, kel []byte, err error) {
	err = s.db.QueryRow(
		`SELECT keys, kel FROM fed_a2a_card
		  WHERE aid=? AND verified_at IS NOT NULL AND keys IS NOT NULL AND length(keys) > 0`,
		aid).Scan(&keyset, &kel)
	return keyset, kel, err
}

// federatedA2AAgents is the /agents view of the listed A2A cards learned
// from peers: the card's name and skill ids, and its home.
func (s *Store) federatedA2AAgents(capFilter string) ([]AgentView, error) {
	rows, err := s.db.Query(`SELECT aid, name, caps, home FROM fed_a2a_card WHERE verified_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentView
	for rows.Next() {
		var aid, name, capsJSON, home string
		if err := rows.Scan(&aid, &name, &capsJSON, &home); err != nil {
			return nil, err
		}
		var caps []string
		if json.Unmarshal([]byte(capsJSON), &caps) != nil {
			continue
		}
		if capFilter != "" && !capsServe(caps, capFilter) {
			continue
		}
		out = append(out, AgentView{AID: aid, Name: name, Caps: caps, Listed: len(caps) > 0, HomeHub: home})
	}
	return out, rows.Err()
}

// FedDirectory's half of the A2A card stream.

// A2ACardsSince implements federation.Directory.
func (d FedDirectory) A2ACardsSince(cursor int64, limit int, home string) ([]federation.FedA2ACardView, int64, error) {
	cards, next, err := d.S.A2ACardsSince(cursor, limit, home)
	if err != nil {
		return nil, cursor, err
	}
	out := make([]federation.FedA2ACardView, 0, len(cards))
	for _, c := range cards {
		out = append(out, federation.FedA2ACardView{Format: c.Format, Card: []byte(c.Card), KEL: c.KEL,
			Keys: c.Keys, Home: c.Home, FedSeq: c.FedSeq})
	}
	return out, next, nil
}

// AdmitFedA2ACard implements federation.Directory.
func (d FedDirectory) AdmitFedA2ACard(peerAID string, e federation.FedA2ACardView) error {
	return d.S.AdmitFedA2ACard(peerAID, FedA2ACard{Format: e.Format, Card: json.RawMessage(e.Card),
		KEL: e.KEL, Keys: e.Keys, Home: e.Home, FedSeq: e.FedSeq})
}
