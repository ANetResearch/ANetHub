package aghub

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Encryption key sets (A2A-DESIGN §2 X3, §3.1, §3.7).
//
// A sender seals each message to the recipient's current X25519 key, which
// the recipient publishes as a seal.SignedEncKeySet signed by its identity
// key. The hub stores the set and serves it with the KEL it verifies
// against, so a sender can fetch both in one request. The hub is not
// trusted with the result: the sender runs seal.VerifyEncKeySet with the
// recipient AID it intends to reach, so a hub serving another AID's set,
// or a set not signed by the recipient's current key, is detected there.
//
// Publisher rule (§3.1, forward-secrecy FS-H4): a publication names, as
// prev_seq, the seq of the last set its publisher signed before this one,
// and is a compare-and-swap on it: a hub holding a set with a higher seq
// than prev_seq refuses it with 409 keys_rollback and says which seq it
// holds (stored_seq), and stores nothing. So does a set whose seq is not
// strictly greater than the stored one. A set with the stored seq and
// identical set bytes is the same statement and is accepted without change
// (200), whatever its prev_seq, which lets a restarted daemon re-register
// and a daemon that lost an answer publish again without an error.
//
// The request and response bodies are wire 3 (core §2.12.2): binary values
// in base64url (CORE-E5), requests decoded strictly (CORE-E7), every
// refusal a G1 error body.
//
// Mailbox key rule (sealed-sender SSR-W9): a set carries its owner's
// mailbox signing key and its epoch, and the hub admits a delivery
// credential only if the current mailbox key signed it under the current
// epoch (SSR-W11). The epoch is how holders and other hubs tell that the
// key changed, so it only rises, and only with a new key: a new key under
// the same epoch looks unchanged to them, and a lower epoch could bring
// back an old key and every credential it signed, which the owner had
// invalidated by changing keys. A set whose mailbox key changes
// without its epoch rising, whose epoch changes without its key changing,
// whose epoch goes down, or whose epoch is 2^53 or more is refused as
// invalid (keys_status invalid on /register, 400 bad_request naming the rule
// on POST /agents/{aid}/keys), and the stored set stays. There is no
// exception for a daemon that lost its key file and made a new key under
// the old epoch: it is refused like anyone else, and publishes a valid set
// once it raises the epoch.

// ErrKeysInvalid is a key set that does not decode or does not verify
// against the agent's KEL: POST /agents/{aid}/keys answers 400 bad_request
// with the reason in its sentence, /register reports keys_status invalid.
// Every such refusal is a *KeysInvalidError.
var ErrKeysInvalid = errors.New("hub: key set invalid")

// KeysInvalidError is why a key set was refused as invalid: what is wrong
// with it, and what the publisher does about it.
type KeysInvalidError struct {
	Why  string // what is wrong, e.g. "the mailbox key changed but its epoch stayed 3"
	Next string // the next step, e.g. "a new mailbox key needs epoch 4 or more"
}

func (e *KeysInvalidError) Error() string {
	return ErrKeysInvalid.Error() + ": " + e.Why + "; " + e.Next
}

// Is makes errors.Is(err, ErrKeysInvalid) hold.
func (e *KeysInvalidError) Is(target error) bool { return target == ErrKeysInvalid }

// Sentence is the one English sentence a refusal of the set carries.
func (e *KeysInvalidError) Sentence() string {
	return "The key set was not accepted: " + e.Why + "; " + e.Next + "."
}

func keysInvalid(why, next string) error { return &KeysInvalidError{Why: why, Next: next} }

// KeysRollbackError is the refusal of a key set that does not follow the
// one this hub holds (forward-secrecy FS-H4): 409 keys_rollback, with
// stored_seq, on POST /agents/{aid}/keys and on /register.
//
// A publisher names, as prev_seq, the seq of the last set it signed before
// this one. A hub that holds a set with a higher seq than that holds one the
// publisher has not seen: its data was restored from a backup, or another
// copy of the identity is running (FS §4.7). The hub stores nothing and says
// what it holds, and the daemon decides what that means. A set whose own
// seq does not rise above the stored one (the high-water rule) is refused
// the same way: it is not newer than what the hub holds either.
//
// The stored set sent again is not refused: the same seq with the same set
// bytes is unchanged, whatever prev_seq says, so a daemon that lost the
// answer to a publication can send it again.
type KeysRollbackError struct {
	StoredSeq uint64 // the seq of the set this hub holds
	PrevSeq   uint64 // the publisher's prev_seq
	Seq       uint64 // the seq of the set refused
}

func (e *KeysRollbackError) Error() string {
	if e.StoredSeq > e.PrevSeq {
		return fmt.Sprintf("hub: this hub holds key set seq %d, newer than the prev_seq %d of the publication", e.StoredSeq, e.PrevSeq)
	}
	return fmt.Sprintf("hub: key set seq %d is not above the stored seq %d", e.Seq, e.StoredSeq)
}

// Key-set statuses reported by POST /agents/{aid}/keys and /register. A set
// that does not follow the stored one is not a status: it is refused with
// 409 keys_rollback (KeysRollbackError).
const (
	KeysStatusOK        = "ok"        // stored; it replaced an older set or was the first
	KeysStatusUnchanged = "unchanged" // same seq and set bytes as the stored set
	KeysStatusAbsent    = "absent"    // the request carried no key set (/register only)
	KeysStatusInvalid   = "invalid"   // did not decode or did not verify; not stored
)

// KeysView is the GET /agents/{aid}/keys response. Both binary values are
// base64url without padding (core CORE-E5), like the same values in a
// directory entry and the /agents listing.
type KeysView struct {
	AID  string `json:"aid"`
	Keys string `json:"keys"` // the seal.SignedEncKeySet encoding
	KEL  string `json:"kel"`  // identity.MarshalKEL
}

// KeysPublishRequest is the POST /agents/{aid}/keys body (core §2.12.2),
// decoded strictly (CORE-E7). Keys is base64url of the seal.SignedEncKeySet
// encoding. PrevSeq is the seq of the last set the publisher signed before
// this one (0 when it signed none); it is required, so that a publisher that
// forgot it is told so instead of overwriting a newer set (FS-H4).
type KeysPublishRequest struct {
	Keys    string  `json:"keys"`
	PrevSeq *uint64 `json:"prev_seq"`
}

// KeysPublishResponse is the POST /agents/{aid}/keys response.
type KeysPublishResponse struct {
	AID        string `json:"aid"`
	KeysStatus string `json:"keys_status"`
}

// storedKeys reads the key set stored for aid: nil when there is none.
func storedKeys(q rowQuerier, aid string) (*seal.Seen, []byte, error) {
	var raw []byte
	var seq uint64
	err := q.QueryRow(`SELECT seq, keyset FROM agent_keys WHERE aid=?`, aid).Scan(&seq, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	stored, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("hub: stored key set for %s undecodable: %w", aid, err)
	}
	return &seal.Seen{Seq: seq, Set: stored.Set}, raw, nil
}

// followsStored is the publisher rule for signed against what is stored
// (seen, nil for nothing): the prev_seq rule of FS-H4, then the high-water
// rule. It returns the high-water decision (Replace or Same), or a
// *KeysRollbackError, or a *KeysInvalidError when the set bytes do not
// decode.
func followsStored(seen *seal.Seen, signed *seal.SignedEncKeySet, prevSeq uint64) (seal.Decision, error) {
	decision, err := seal.DecideHighWaterSigned(seen, signed)
	if err != nil {
		return 0, keysInvalid("it does not decode as a key set ("+err.Error()+")",
			"publish the set as anet encodes it")
	}
	if seen == nil || decision == seal.Same {
		return decision, nil
	}
	if seen.Seq > prevSeq || decision == seal.Ignore || decision == seal.Fork {
		var es seal.EncKeySet
		_ = coredet.UnmarshalStrict(signed.Set, &es) // DecideHighWaterSigned decoded it
		return 0, &KeysRollbackError{StoredSeq: seen.Seq, PrevSeq: prevSeq, Seq: es.Seq}
	}
	return decision, nil
}

// KeysRollbackOf is the prev_seq rule of PublishKeys, checked without
// writing: the *KeysRollbackError PublishKeys would return for raw and
// prevSeq now, or nil (also for bytes that do not decode, which PublishKeys
// reports). /register checks it before it writes anything (PAY-A1 step 9);
// PublishKeys checks it again where it writes.
func (s *Store) KeysRollbackOf(aid string, raw []byte, prevSeq uint64) error {
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return nil
	}
	seen, _, err := storedKeys(s.db, aid)
	if err != nil {
		return err
	}
	var rb *KeysRollbackError
	if _, err := followsStored(seen, signed, prevSeq); errors.As(err, &rb) {
		return rb
	}
	return nil
}

// PublishKeys applies the publisher rule to a key set and stores it.
// prevSeq is the publisher's prev_seq (FS-H4); kel is the agent's KEL as
// this hub holds it. It returns KeysStatusOK or KeysStatusUnchanged, or a
// *KeysRollbackError (409 keys_rollback) or a *KeysInvalidError
// (ErrKeysInvalid).
//
// The order: the set decodes; under the store's lock, the stored set is
// read and the prev_seq and high-water rules applied (followsStored); the
// set verifies against kel; the mailbox key rule (SSR-W9); the write. The
// stored set is compared and replaced under the one lock, so two
// publications that both follow the same stored set cannot both succeed.
func (s *Store) PublishKeys(aid string, raw []byte, prevSeq uint64, kel []identity.SignedEvent, now time.Time) (string, error) {
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return "", keysInvalid("it does not decode as a signed key set ("+err.Error()+")",
			"publish the set as anet encodes it")
	}
	canon, err := signed.Marshal()
	if err != nil {
		return "", keysInvalid("it does not encode again ("+err.Error()+")", "publish the set as anet encodes it")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen, storedRaw, err := storedKeys(s.db, aid)
	if err != nil {
		return "", err
	}
	decision, err := followsStored(seen, signed, prevSeq)
	if err != nil {
		return "", err
	}
	set, err := seal.VerifyEncKeySet(signed, aid, kel, uint64(now.UnixMilli()))
	if err != nil {
		return "", keysInvalid("it does not verify against this agent's key history ("+err.Error()+")",
			"sign a new key set with the identity's current key and publish it")
	}
	var prev *seal.Mbox
	if seen != nil {
		if prev, err = mboxOf(seen.Set); err != nil {
			return "", fmt.Errorf("hub: stored key set for %s undecodable: %w", aid, err)
		}
	}
	if err := checkMboxEpoch(prev, set.Mbox); err != nil {
		return "", err
	}
	// agent_keys.seq is an SQLite INTEGER, and database/sql refuses a
	// uint64 with the high bit set: such a set verified and then failed to
	// store, and POST /agents/{aid}/keys answered 500 (found by FuzzHubKeys,
	// ANet an internal note). A seq is unix milliseconds or one above the
	// last (seal.NextSeq), nowhere near 2^63; one past it is refused here.
	if set.Seq > math.MaxInt64 {
		return "", keysInvalid(fmt.Sprintf("its seq %d is above %d, the largest this hub stores", set.Seq, int64(math.MaxInt64)),
			"publish a set whose seq is unix milliseconds")
	}
	if decision == seal.Same && bytes.Equal(canon, storedRaw) {
		return KeysStatusUnchanged, nil
	}
	// The stored set and the agent's directory entry, which carries it
	// (sealed-sender SSR-H17), change in one transaction.
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if decision == seal.Same {
		// The same set may arrive with a new signature, for example
		// re-signed after a KEL rotation. The set is unchanged; the
		// signature just verified against the current KEL, so it replaces
		// the stored one, which a consumer may no longer accept.
		if _, err := tx.Exec(`UPDATE agent_keys SET keyset=?, stored_at=? WHERE aid=?`,
			canon, nowStamp(), aid); err != nil {
			return "", err
		}
		if err := s.refreshDirTx(tx, aid); err != nil {
			return "", err
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return KeysStatusUnchanged, nil
	}
	if _, err := tx.Exec(
		`INSERT INTO agent_keys(aid, seq, keyset, stored_at) VALUES(?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, keyset=excluded.keyset, stored_at=excluded.stored_at`,
		aid, set.Seq, canon, nowStamp()); err != nil {
		return "", err
	}
	// A federating agent's card entry carries its key set (§3.9), and the
	// A2A card stream is ordered by fed_seq, so the card is moved to the
	// head of the stream for peers to pick up the new set.
	if fed, err := agentFederates(tx, aid); err != nil {
		return "", err
	} else if fed {
		if err := bumpA2ACard(tx, aid); err != nil {
			return "", err
		}
	}
	if err := s.refreshDirTx(tx, aid); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return KeysStatusOK, nil
}

// MaxMboxEpoch bounds a mailbox key's epoch: every epoch is below it
// (sealed-sender SSR-W9, SSR-W10). 2^53 is the largest integer every JSON
// reader holds exactly; an honest hub never stores more, so a daemon that
// adds one to what a hub reports cannot wrap around to 0.
const MaxMboxEpoch = 1 << 53

// mboxOf reads the mailbox key of stored set bytes. They were verified
// before they were stored, so they decode.
func mboxOf(set []byte) (*seal.Mbox, error) {
	var es seal.EncKeySet
	if err := coredet.UnmarshalStrict(set, &es); err != nil {
		return nil, err
	}
	return &es.Mbox, nil
}

// checkMboxEpoch is the mailbox key rule (SSR-W9) for next against the stored
// prev (nil when there is none). A refusal is a *KeysInvalidError.
func checkMboxEpoch(prev *seal.Mbox, next seal.Mbox) error {
	if next.Epoch >= MaxMboxEpoch {
		return keysInvalid(fmt.Sprintf("the mailbox key's epoch %d is not below 2^53", next.Epoch),
			"no mailbox key has an epoch that large, so publish one below it")
	}
	if prev == nil {
		return nil
	}
	samePub := bytes.Equal(prev.Pub, next.Pub)
	switch {
	case next.Epoch < prev.Epoch:
		return keysInvalid(fmt.Sprintf("the mailbox key's epoch went down from %d to %d", prev.Epoch, next.Epoch),
			fmt.Sprintf("publish epoch %d or a new key under a higher epoch", prev.Epoch))
	case !samePub && next.Epoch == prev.Epoch:
		return keysInvalid(fmt.Sprintf("the mailbox key changed but its epoch stayed %d", prev.Epoch),
			fmt.Sprintf("a new mailbox key needs epoch %d or more", prev.Epoch+1))
	case samePub && next.Epoch != prev.Epoch:
		return keysInvalid(fmt.Sprintf("the mailbox key is unchanged but its epoch moved from %d to %d", prev.Epoch, next.Epoch),
			fmt.Sprintf("keep epoch %d with this key", prev.Epoch))
	}
	return nil
}

// LocalKeys returns the key set and KEL of an agent registered here.
// registered is false for an AID with no registration row; keyset is nil
// for a registered agent that has published no key set.
func (s *Store) LocalKeys(aid string) (keyset, kel []byte, registered bool, err error) {
	err = s.db.QueryRow(
		`SELECT k.keyset, a.kel FROM agent a LEFT JOIN agent_keys k ON k.aid = a.aid WHERE a.aid=?`,
		aid).Scan(&keyset, &kel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	return keyset, kel, true, nil
}

func writeKeys(w http.ResponseWriter, aid string, keyset, kel []byte) {
	writeJSON(w, http.StatusOK, KeysView{AID: aid, Keys: wire3.EncodeB64URL(keyset), KEL: wire3.EncodeB64URL(kel)})
}

// hKeysGet serves GET /agents/{aid}/keys: the key set and KEL of an agent
// registered here. Its refusals are wire-3 error bodies (core G1): 404
// unknown_aid for an AID not registered here, 404 not_found for an agent
// with no key set to serve.
//
// It is a route for people and for an agent's own daemon (sealed-sender
// SSR-W16). A sender does not look up a peer by AID: it reads the peer's
// entry from a directory bucket (directory.go), which does not name the
// peer. So this answers only for agents registered here; it no longer asks
// peer hubs, nor serves key sets learned from them (§2.7).
func (s *Server) hKeysGet(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	keyset, kel, registered, err := s.store.LocalKeys(aid)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if !registered {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnknownAID,
			Error: "No agent with this AID is registered here, and this hub serves the key sets of its own agents only; ask the agent's own hub."})
		return
	}
	if keyset == nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonNotFound,
			Error: "This agent is registered here but has published no encryption key set yet; ask again once its anet daemon is running."})
		return
	}
	// A key history stored before /register capped it is not served: no
	// sender accepts it (seal.ParseKEL) [redteam:F36].
	if _, err := seal.ParseKEL(kel); err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonNotFound,
			Error: "This agent's key history on this hub is longer than any sender accepts, so its key set is not served; the agent needs a new identity."})
		return
	}
	writeKeys(w, aid, keyset, kel)
}

// hKeysPost serves POST /agents/{aid}/keys: the agent publishes a new key
// set, signed with relayauth v2 action "keys". The body is decoded strictly
// (CORE-E7); keys is base64url (CORE-E5) and prev_seq is required (FS-H4).
// A set that does not follow the stored one is 409 keys_rollback with
// stored_seq; one that does not decode or verify, or breaks the mailbox key
// rule (SSR-W9), is 400 bad_request saying why. Every refusal is a wire-3
// error body (core G1).
func (s *Server) hKeysPost(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionKeys, signedBodyLimit)
	if !ok {
		return
	}
	var req KeysPublishRequest
	if err := wire3.DecodeStrict(a.Body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if req.Keys == "" || req.PrevSeq == nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A key set publication carries keys and prev_seq (the seq of the last set signed before it, 0 for none); add them and send again."})
		return
	}
	raw, err := wire3.DecodeB64URL("keys", req.Keys)
	if err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	kel, err := s.agentKELEvents(a.AID)
	if seal.ReasonOf(err) == seal.ReasonKELTooLarge {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid, Error: fmt.Sprintf(
			"The key history this hub holds for this agent is past %d events or %d bytes, which no sender accepts; the agent needs a new identity.",
			seal.MaxKELEvents, seal.MaxKELBytes)})
		return
	}
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	status, err := s.store.PublishKeys(a.AID, raw, *req.PrevSeq, kel, time.Now())
	if err != nil {
		refuseKeys(w, err)
		return
	}
	writeJSON(w, http.StatusOK, KeysPublishResponse{AID: a.AID, KeysStatus: status})
}

// keysFollowSentence is the error of 409 keys_rollback when the hub holds a
// set newer than prev_seq; the code's own sentence says the other case, a
// set whose seq is not above the stored one.
const keysFollowSentence = "This hub holds a newer key set (stored_seq) than the one this publication follows (prev_seq); " +
	"sign the next set after stored_seq and publish it with prev_seq set to stored_seq."

// refuseKeys answers a key set PublishKeys refused: 409 keys_rollback with
// stored_seq, 400 bad_request with the reason, or 500 internal.
func refuseKeys(w http.ResponseWriter, err error) {
	var rb *KeysRollbackError
	var bad *KeysInvalidError
	switch {
	case errors.As(err, &rb):
		rf := wire3.Refusal{Reason: wire3.ReasonKeysRollback, Extra: map[string]any{"stored_seq": rb.StoredSeq}}
		if rb.StoredSeq > rb.PrevSeq {
			rf.Error = keysFollowSentence
		}
		wire3.Write(w, rf)
	case errors.As(err, &bad):
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: bad.Sentence()})
	default:
		wire3.Internal(w, err)
	}
}

// agentKELEvents returns the stored KEL of a registered agent, decoded
// under the caps /register applies (seal.ParseKEL) [redteam:F36]: a key
// history stored before those caps is refused rather than replayed.
func (s *Server) agentKELEvents(aid string) ([]identity.SignedEvent, error) {
	kelBytes, err := s.store.AgentKEL(aid)
	if err != nil {
		return nil, err
	}
	return seal.ParseKEL(kelBytes)
}

// keysStatusOf maps a PublishKeys result other than a *KeysRollbackError
// (which /register answers with 409) onto the per-field status that
// /register reports: ok or unchanged, or invalid with the reason.
func keysStatusOf(status string, err error) (string, string) {
	var bad *KeysInvalidError
	switch {
	case err == nil:
		return status, ""
	case errors.As(err, &bad):
		return KeysStatusInvalid, bad.Sentence()
	default:
		log.Printf("hub: storing a registering agent's key set: %v", err)
		return KeysStatusInvalid, "This hub could not store the key set; publish it again."
	}
}
