package aghub

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
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
// Publisher rule (§3.1): a new set must have a strictly greater seq than
// the stored one. A set with the stored seq and identical set bytes is the
// same statement and is accepted without change (200), which lets a
// restarted daemon re-register without an error. Anything else — a lower
// seq, or the stored seq with different content — is refused with 409.
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
// invalid (keys_status invalid), and the stored set stays. There is no
// exception for a daemon that lost its key file and made a new key under
// the old epoch: it is refused like anyone else, and publishes a valid set
// once it raises the epoch.

// ErrKeysConflict is the publisher high-water refusal (409).
var ErrKeysConflict = errors.New("hub: key set does not advance the stored one")

// ErrKeysInvalid is a key set that does not decode or does not verify
// against the agent's KEL (400).
var ErrKeysInvalid = errors.New("hub: key set invalid")

// Key-set statuses reported by POST /agents/{aid}/keys and /register.
const (
	KeysStatusOK        = "ok"        // stored; it replaced an older set or was the first
	KeysStatusUnchanged = "unchanged" // same seq and set bytes as the stored set
	KeysStatusAbsent    = "absent"    // the request carried no key set (/register only)
	KeysStatusInvalid   = "invalid"   // did not decode or did not verify; not stored
	KeysStatusConflict  = "conflict"  // lower seq, or equal seq with different content; not stored
)

// KeysView is the GET /agents/{aid}/keys response.
type KeysView struct {
	AID    string `json:"aid"`
	KeySet string `json:"keyset"` // base64 (std) of the seal.SignedEncKeySet encoding
	KEL    string `json:"kel"`    // base64 (std) of identity.MarshalKEL
}

// KeysPublishRequest is the POST /agents/{aid}/keys body.
type KeysPublishRequest struct {
	KeySet string `json:"keyset"` // base64 (std) of the seal.SignedEncKeySet encoding
}

// KeysPublishResponse is the POST /agents/{aid}/keys response.
type KeysPublishResponse struct {
	AID        string `json:"aid"`
	KeysStatus string `json:"keys_status"`
}

// PublishKeys applies the publisher rule to a key set and stores it.
// kel is the agent's KEL as this hub holds it. It returns KeysStatusOK or
// KeysStatusUnchanged, or an error wrapping ErrKeysConflict or
// ErrKeysInvalid.
func (s *Store) PublishKeys(aid string, raw []byte, kel []identity.SignedEvent, now time.Time) (string, error) {
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeysInvalid, err)
	}
	canon, err := signed.Marshal()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeysInvalid, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var storedRaw []byte
	var storedSeq uint64
	err = s.db.QueryRow(`SELECT seq, keyset FROM agent_keys WHERE aid=?`, aid).Scan(&storedSeq, &storedRaw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var seen *seal.Seen
	if err == nil {
		stored, uerr := seal.UnmarshalSignedEncKeySet(storedRaw)
		if uerr != nil {
			return "", fmt.Errorf("hub: stored key set for %s undecodable: %w", aid, uerr)
		}
		seen = &seal.Seen{Seq: storedSeq, Set: stored.Set}
	}
	decision, err := seal.DecideHighWaterSigned(seen, signed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeysInvalid, err)
	}
	switch decision {
	case seal.Ignore:
		return "", fmt.Errorf("%w: its seq is below the stored seq %d", ErrKeysConflict, storedSeq)
	case seal.Fork:
		return "", fmt.Errorf("%w: it has the stored seq %d with different content", ErrKeysConflict, storedSeq)
	}
	set, err := seal.VerifyEncKeySet(signed, aid, kel, uint64(now.UnixMilli()))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeysInvalid, err)
	}
	var prev *seal.Mbox
	if seen != nil {
		if prev, err = mboxOf(seen.Set); err != nil {
			return "", fmt.Errorf("hub: stored key set for %s undecodable: %w", aid, err)
		}
	}
	if err := checkMboxEpoch(prev, set.Mbox); err != nil {
		return "", fmt.Errorf("%w: %v", ErrKeysInvalid, err)
	}
	// agent_keys.seq is an SQLite INTEGER, and database/sql refuses a
	// uint64 with the high bit set: such a set verified and then failed to
	// store, and POST /agents/{aid}/keys answered 500 (found by FuzzHubKeys,
	// ANet an internal note). A seq is unix milliseconds or one above the
	// last (seal.NextSeq), nowhere near 2^63; one past it is refused here.
	if set.Seq > math.MaxInt64 {
		return "", fmt.Errorf("%w: seq %d is above %d, the largest this hub stores", ErrKeysInvalid,
			set.Seq, int64(math.MaxInt64))
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
// prev (nil when there is none).
func checkMboxEpoch(prev *seal.Mbox, next seal.Mbox) error {
	if next.Epoch >= MaxMboxEpoch {
		return fmt.Errorf("the mailbox key's epoch %d is not below 2^53; no mailbox key has one that large", next.Epoch)
	}
	if prev == nil {
		return nil
	}
	samePub := bytes.Equal(prev.Pub, next.Pub)
	switch {
	case next.Epoch < prev.Epoch:
		return fmt.Errorf("the mailbox key's epoch went down from %d to %d; publish epoch %d or a new key under a higher epoch",
			prev.Epoch, next.Epoch, prev.Epoch)
	case !samePub && next.Epoch == prev.Epoch:
		return fmt.Errorf("the mailbox key changed but its epoch stayed %d; a new mailbox key needs epoch %d or more",
			prev.Epoch, prev.Epoch+1)
	case samePub && next.Epoch != prev.Epoch:
		return fmt.Errorf("the mailbox key is unchanged but its epoch moved from %d to %d; keep epoch %d with this key",
			prev.Epoch, next.Epoch, prev.Epoch)
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
	writeJSON(w, http.StatusOK, KeysView{
		AID:    aid,
		KeySet: base64.StdEncoding.EncodeToString(keyset),
		KEL:    base64.StdEncoding.EncodeToString(kel),
	})
}

// hKeysGet serves GET /agents/{aid}/keys: the key set and KEL of an agent
// registered here.
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !registered {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": aid + " is not registered here; this hub serves the key sets of its own agents only"})
		return
	}
	if keyset == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": aid + " is registered here and has published no encryption key set"})
		return
	}
	// A key history stored before /register capped it is not served: no
	// sender accepts it (seal.ParseKEL) [redteam:F36].
	if _, err := seal.ParseKEL(kel); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": aid + "'s key history on this hub is not one a sender accepts: " + err.Error()})
		return
	}
	writeKeys(w, aid, keyset, kel)
}

// hKeysPost serves POST /agents/{aid}/keys: the agent publishes a new key
// set, signed with relayauth v2 action "keys".
func (s *Server) hKeysPost(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authSelf(w, r, relayauth.ActionKeys, signedBodyLimit)
	if !ok {
		return
	}
	var req KeysPublishRequest
	if err := json.Unmarshal(a.Body, &req); err != nil || req.KeySet == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "keyset required"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.KeySet)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "keyset not base64"})
		return
	}
	kel, err := s.agentKELEvents(a.AID)
	if seal.ReasonOf(err) == seal.ReasonKELTooLarge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
			"the key history this hub holds for %s is past %d events or %d bytes, which no sender accepts: %v",
			a.AID, seal.MaxKELEvents, seal.MaxKELBytes, err)})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	status, err := s.store.PublishKeys(a.AID, raw, kel, time.Now())
	switch {
	case errors.Is(err, ErrKeysConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, ErrKeysInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, KeysPublishResponse{AID: a.AID, KeysStatus: status})
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

// keysStatusOf maps a PublishKeys result onto the per-field status that
// /register reports.
func keysStatusOf(status string, err error) (string, string) {
	switch {
	case err == nil:
		return status, ""
	case errors.Is(err, ErrKeysConflict):
		return KeysStatusConflict, err.Error()
	case errors.Is(err, ErrKeysInvalid):
		return KeysStatusInvalid, err.Error()
	default:
		return KeysStatusInvalid, err.Error()
	}
}

// StoreKeySource adapts the store to federation.KeySource: it answers
// /fed/v2/keys for any AID registered here, whatever its visibility
// (A2A-DESIGN §3.9, [C32]).
type StoreKeySource struct{ S *Store }

// LocalKeys implements federation.KeySource.
func (k StoreKeySource) LocalKeys(aid string) (keyset, kel []byte, err error) {
	keyset, kel, registered, err := k.S.LocalKeys(aid)
	if err != nil {
		return nil, nil, err
	}
	if !registered || keyset == nil {
		return nil, nil, federation.ErrNoKeys
	}
	return keyset, kel, nil
}
