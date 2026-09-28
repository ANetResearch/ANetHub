package aghub

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/seamerr"
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

// KeysLookupPath is the key-set lookup that names the AID in its body
// rather than in its path (A2A-DESIGN §3.5 step 1, §3.7). A sender looks up
// its recipient's key set before the first message and every ten minutes
// of a conversation, from its own address and without authentication; a
// reverse proxy logging request lines would write the edge
// sender-address -> recipient-AID to the hub host's disk if the AID were
// in the path [redteam:F3]. GET /agents/{aid}/keys answers the same and
// stays for older daemons and for readers.
const KeysLookupPath = "/agents/keys:lookup"

// KeysLookupRequest is the POST /agents/keys:lookup body. The answer is a
// KeysView, as for GET /agents/{aid}/keys.
type KeysLookupRequest struct {
	AID string `json:"aid"`
}

// keysLookupBodyLimit caps a lookup body: one AID in JSON.
const keysLookupBodyLimit = 4 << 10

// KeysPublishRequest is the POST /agents/{aid}/keys body.
type KeysPublishRequest struct {
	KeySet string `json:"keyset"` // base64 (std) of the seal.SignedEncKeySet encoding
}

// KeysPublishResponse is the POST /agents/{aid}/keys response.
type KeysPublishResponse struct {
	AID        string `json:"aid"`
	KeysStatus string `json:"keys_status"`
}

// FederatedKeyLookup asks peer hubs for an AID's key set (/fed/v2/keys).
// accept is called on each answer; an answer it refuses is skipped and the
// next peer is asked. It returns an error wrapping seamerr.ErrNoKeys
// (federation.ErrNoKeys is the same value) when no peer holds the AID.
type FederatedKeyLookup func(ctx context.Context, aid string,
	accept func(keyset, kel []byte) error) (keyset, kel []byte, peerAID string, err error)

// SetFederatedKeyLookup installs the federation hook for key sets of AIDs
// not registered here. Nil in a build without federation.
func (s *Server) SetFederatedKeyLookup(f FederatedKeyLookup) { s.fedKeys = f }

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
	if decision == seal.Same {
		// The same set may arrive with a new signature, for example
		// re-signed after a KEL rotation. The set is unchanged; the
		// signature just verified against the current KEL, so it replaces
		// the stored one, which a consumer may no longer accept.
		if !bytes.Equal(canon, storedRaw) {
			if _, err := s.db.Exec(`UPDATE agent_keys SET keyset=?, stored_at=? WHERE aid=?`,
				canon, nowStamp(), aid); err != nil {
				return "", err
			}
		}
		return KeysStatusUnchanged, nil
	}
	if _, err := s.db.Exec(
		`INSERT INTO agent_keys(aid, seq, keyset, stored_at) VALUES(?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, keyset=excluded.keyset, stored_at=excluded.stored_at`,
		aid, set.Seq, canon, nowStamp()); err != nil {
		return "", err
	}
	// A federating agent's card entry carries its key set (§3.9), and the
	// sync stream is ordered by fed_seq, so the card row is moved to the
	// head of the stream for peers to pick up the new set.
	if err := s.bumpFederatedCard(aid); err != nil {
		return "", err
	}
	// The A2A card stream carries the key set too (/fed/v2/cards).
	if fed, err := agentFederates(s.db, aid); err != nil {
		return "", err
	} else if fed {
		if err := bumpA2ACard(s.db, aid); err != nil {
			return "", err
		}
	}
	return KeysStatusOK, nil
}

// bumpFederatedCard moves a published card to the head of the federation
// stream without changing it. A card that is withdrawn, or an agent that
// does not federate, is left alone.
func (s *Store) bumpFederatedCard(aid string) error {
	var stored []byte
	err := s.db.QueryRow(`SELECT card FROM agent_card WHERE aid=?`, aid).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, withdrawn := parseWithdrawal(stored); withdrawn {
		return nil
	}
	fed, err := s.federatesCard(aid)
	if err != nil || !fed {
		return err
	}
	return bumpCard(s.db, aid, stored)
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

// FedCardKeys returns the key set and KEL a peer's card sync delivered for
// aid, or sql.ErrNoRows when there is none.
func (s *Store) FedCardKeys(aid string) (keyset, kel []byte, err error) {
	err = s.db.QueryRow(`SELECT keys, kel FROM fed_card WHERE aid=? AND keys IS NOT NULL AND length(keys) > 0`,
		aid).Scan(&keyset, &kel)
	return keyset, kel, err
}

// verifyKeysFor checks a key set and KEL for aid as a sender would. The
// hub runs it on key sets it did not receive from their owner (a peer's
// card sync, a federated lookup) before serving them, so that it does not
// relay a set the requester will refuse. The requester verifies again.
func verifyKeysFor(aid string, keyset, kel []byte) error {
	signed, err := seal.UnmarshalSignedEncKeySet(keyset)
	if err != nil {
		return err
	}
	events, err := seal.ParseKEL(kel)
	if err != nil {
		return err
	}
	_, err = seal.VerifyEncKeySet(signed, aid, events, uint64(time.Now().UnixMilli()))
	return err
}

func writeKeys(w http.ResponseWriter, aid string, keyset, kel []byte) {
	writeJSON(w, http.StatusOK, KeysView{
		AID:    aid,
		KeySet: base64.StdEncoding.EncodeToString(keyset),
		KEL:    base64.StdEncoding.EncodeToString(kel),
	})
}

// hKeysGet serves GET /agents/{aid}/keys; POST /agents/keys:lookup
// (hKeysLookup) is the same with the AID in the body.
//
// Sources, in order: an agent registered here; a key set that arrived with
// a peer's card sync (the A2A card stream, then the ADP card stream); a
// /fed/v2/keys lookup at the peer hubs. The last one
// covers agents whose card is not federated (the default hub-local
// visibility), which a cross-hub sender can otherwise never encrypt to
// ([C32]). Its answer is relayed to this caller and not stored: it does
// not enter fed_card, /agents or any index.
func (s *Server) hKeysGet(w http.ResponseWriter, r *http.Request) {
	s.serveKeys(w, r, r.PathValue("aid"))
}

// hKeysLookup serves POST /agents/keys:lookup: GET /agents/{aid}/keys with
// the AID in the body (KeysLookupRequest), so that no request line names it.
func (s *Server) hKeysLookup(w http.ResponseWriter, r *http.Request) {
	body, err := readAllLimited(w, r, keysLookupBodyLimit)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": fmt.Sprintf("a key lookup body is at most %d bytes", keysLookupBodyLimit)})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reading request body: " + err.Error()})
		return
	}
	var req KeysLookupRequest
	if err := json.Unmarshal(body, &req); err != nil || req.AID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": `body must be {"aid": "<AID>"}`})
		return
	}
	s.serveKeys(w, r, req.AID)
}

// serveKeys answers a key-set lookup for aid (hKeysGet, hKeysLookup).
func (s *Server) serveKeys(w http.ResponseWriter, r *http.Request, aid string) {
	keyset, kel, registered, err := s.store.LocalKeys(aid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if registered {
		if keyset == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": aid + " is registered here and has published no encryption key set"})
			return
		}
		// A key history stored before /register capped it is not
		// served: no sender accepts it (seal.ParseKEL) [redteam:F36].
		if _, err := seal.ParseKEL(kel); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": aid + "'s key history on this hub is not one a sender accepts: " + err.Error()})
			return
		}
		writeKeys(w, aid, keyset, kel)
		return
	}
	if ks, kl, err := s.store.FedA2ACardKeys(aid); err == nil && verifyKeysFor(aid, ks, kl) == nil {
		writeKeys(w, aid, ks, kl)
		return
	}
	if ks, kl, err := s.store.FedCardKeys(aid); err == nil && verifyKeysFor(aid, ks, kl) == nil {
		writeKeys(w, aid, ks, kl)
		return
	}
	if s.fedKeys != nil {
		// The federated lookup sends one signed request to each peer
		// hub, on behalf of an unauthenticated caller, so it is bounded
		// per client address (Limits.KeysLookupPerMinute).
		if ok, wait := s.keysLimiter.allow(clientIP(r)); !ok {
			w.Header().Set("Retry-After", retryAfter(wait))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "too many key lookups for agents registered at other hubs from this address; retry later"})
			return
		}
		ks, kl, _, err := s.fedKeys(r.Context(), aid, func(ks, kl []byte) error {
			return verifyKeysFor(aid, ks, kl)
		})
		if err == nil {
			writeKeys(w, aid, ks, kl)
			return
		}
		if !errors.Is(err, seamerr.ErrNoKeys) {
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": "federated key lookup failed: " + err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error": "no encryption key set for " + aid + " here or at any peer hub"})
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
