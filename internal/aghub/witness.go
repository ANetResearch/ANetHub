package aghub

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/ANetResearch/ANetCore/ael"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// Witnessing: holding somebody else's chain head so they cannot deny it
// later.
//
// The issuance chain makes a rewrite detectable by anyone who already
// holds an older copy. It offers nothing to a reader seeing the chain for
// the first time, because a hub that has never been observed can present
// whatever chain it likes.
//
// A witness closes that. It fetches this hub's head periodically and
// signs "at time T, that chain's head was N with id X". The attestation
// lives with the WITNESS, which is what makes it worth anything — a
// statement the subject could delete is not evidence about the subject.
// This hub also accepts and serves attestations made about it, but that
// is a convenience for readers looking for somewhere to start, not a
// source of authority: a hub can withhold an inconvenient attestation.
// It cannot forge one, because the witness's signature is over the head
// the witness saw.
//
// Who witnesses whom:
//
//	peer hubs   default on, configurable off. They already poll each
//	            other for directory and reputation, they have identities
//	            on an allowlist, and they have their own users — which
//	            is what makes their attestation worth something.
//	agents      opt-in, off by default. An agent may be a trimmed build
//	            that serves nothing and only talks to its hub, and such
//	            a node should not be made to do work for the network.
//	            An agent that does witness gains the most: it holds
//	            independent evidence about the ledger its own balance
//	            lives on.

// StoreAttestation records an attestation somebody made about a chain.
//
// Kept whether the subject is this hub or another. Attestations about
// this hub are served to readers; attestations this hub made about a peer
// are the evidence it holds as a witness, and those are the ones that
// matter if that peer ever rewrites.
func (s *Store) StoreAttestation(a *ael.HeadAttestation) error {
	if a == nil || a.Envelope == nil {
		return fmt.Errorf("hub: unsigned attestation")
	}
	raw, err := a.Marshal()
	if err != nil {
		return err
	}
	id, err := a.ID()
	if err != nil {
		return err
	}
	// Keyed on witness AND statement, not the statement alone.
	//
	// The attestation's CID covers {chain, seq, head, observed_at} and
	// not the signer — the envelope carries that. Two witnesses observing
	// the same head at the same moment therefore produce the same CID,
	// which is correct as a content identifier and wrong as a storage
	// key: the second insert was discarded, so a chain watched by six
	// parties reported one witness.
	//
	// That is the number the whole trust argument rests on, and it was
	// silently the wrong one.
	key := a.WitnessAID() + ":" + id
	_, err = s.db.Exec(
		`INSERT INTO head_attestation(id, chain_did, witness_aid, seq, head_id, observed_at, blob)
		 VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`,
		key, a.ChainDID, a.WitnessAID(), int64(a.Seq), a.HeadID, a.ObservedAt, raw)
	return err
}

// AttestationView is one stored attestation as served.
type AttestationView struct {
	WitnessAID string `json:"witness_aid"`
	ChainDID   string `json:"chain_did"`
	Seq        uint64 `json:"seq"`
	HeadID     string `json:"head_id"`
	ObservedAt int64  `json:"observed_at"`
	// Attestation is the signed object, base64 CoreDet-CBOR. A reader
	// checking this must verify the object, not the JSON beside it.
	Attestation string `json:"attestation"`
}

// AttestationsAbout returns what is held about one chain, newest first.
func (s *Store) AttestationsAbout(chainDID string, limit int) ([]AttestationView, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT witness_aid, chain_did, seq, head_id, observed_at, blob
		   FROM head_attestation WHERE chain_did=?
		  ORDER BY seq DESC, observed_at DESC LIMIT ?`, chainDID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AttestationView{}
	for rows.Next() {
		var v AttestationView
		var seq int64
		var raw []byte
		if err := rows.Scan(&v.WitnessAID, &v.ChainDID, &seq, &v.HeadID, &v.ObservedAt, &raw); err != nil {
			return nil, err
		}
		v.Seq = uint64(seq)
		v.Attestation = base64.StdEncoding.EncodeToString(raw)
		out = append(out, v)
	}
	return out, rows.Err()
}

// WitnessPeer fetches a peer's issuance head and signs what it saw.
//
// Returns the attestation so the caller can also send it to the peer;
// storing it here is what matters, because evidence held only by the
// subject is not evidence.
func (s *Store) WitnessPeer(peerAID, headID string, seq uint64) (*ael.HeadAttestation, error) {
	if s.hubKey == nil {
		return nil, fmt.Errorf("hub: no signing key, so this hub cannot witness")
	}
	a := &ael.HeadAttestation{
		ChainDID: peerAID, Seq: seq, HeadID: headID,
		ObservedAt: time.Now().UnixMilli(),
	}
	if err := a.Sign(s.hubKey); err != nil {
		return nil, err
	}
	if err := s.StoreAttestation(a); err != nil {
		return nil, err
	}
	return a, nil
}

// CheckAgainstAttestations reports any stored attestation that the given
// chain records contradict.
//
// This is the payoff. An attestation and a record signed by different
// parties, naming the same position in the same chain with different
// contents, demonstrate a rewrite without either party agreeing to
// anything.
func (s *Store) CheckAgainstAttestations(chainDID string, recs []*ael.EventRecord) ([]AttestationView, error) {
	held, err := s.AttestationsAbout(chainDID, 500)
	if err != nil {
		return nil, err
	}
	bySeq := map[uint64]*ael.EventRecord{}
	for _, r := range recs {
		bySeq[r.Seq] = r
	}
	var bad []AttestationView
	for _, v := range held {
		r := bySeq[v.Seq]
		if r == nil {
			continue // not in the range we were given; not a contradiction
		}
		raw, derr := base64.StdEncoding.DecodeString(v.Attestation)
		if derr != nil {
			continue
		}
		a, aerr := ael.UnmarshalHeadAttestation(raw)
		if aerr != nil {
			continue
		}
		if a.ContradictedBy(r) {
			bad = append(bad, v)
		}
	}
	return bad, nil
}

// FedWitness adapts the store to federation's Witness seam, so the
// federation module never imports the kernel's internals.
type FedWitness struct{ S *Store }

func (w FedWitness) Attest(peerAID, headID string, seq uint64) ([]byte, error) {
	a, err := w.S.WitnessPeer(peerAID, headID, seq)
	if err != nil {
		return nil, err
	}
	return a.Marshal()
}

// WitnessHealth is how much independent observation this chain has.
//
// The trust model is "the hub and its witnesses did not all collude",
// which is only worth something if a reader can see how many witnesses
// there are and how recently they looked. A hub with one witness that
// last looked in March is technically witnessed and practically not, and
// nothing distinguished that from a hub with six witnesses looking
// hourly.
//
// This adds no guarantee. It makes the existing one measurable.
type WitnessHealth struct {
	ChainDID string `json:"chain_did"`
	// Witnesses is how many distinct parties have ever attested.
	//
	// Distinct by AID, which is the only thing this hub can check. Two
	// AIDs run by the same operator count as two here and are worth one;
	// no hub can tell the difference, and a reader deciding whether the
	// count means anything has to look at who the witnesses are. That is
	// why they are listed rather than only counted.
	Witnesses int `json:"witnesses"`
	// Attestations is the total held, across all witnesses.
	Attestations int `json:"attestations"`
	// LatestAt and LatestSeq describe the most recent observation.
	LatestAt  int64  `json:"latest_at,omitempty"`
	LatestSeq uint64 `json:"latest_seq"`
	// StaleFor is how long since anybody looked, in seconds. A chain
	// whose head has moved since the last attestation has records nobody
	// outside has pinned.
	StaleFor int64 `json:"stale_seconds,omitempty"`
	// UnwitnessedRecords is how many records sit above the highest
	// witnessed sequence. These are the ones the hub could still rewrite
	// without contradicting anybody.
	UnwitnessedRecords uint64 `json:"unwitnessed_records"`
	// Who has attested, so a reader can judge whether the count means
	// anything.
	WitnessAIDs []string `json:"witness_aids,omitempty"`
}

// WitnessHealthOf measures the observation on one chain.
func (s *Store) WitnessHealthOf(chainDID string, now time.Time) (WitnessHealth, error) {
	h := WitnessHealth{ChainDID: chainDID, WitnessAIDs: []string{}}
	rows, err := s.db.Query(
		`SELECT witness_aid, COUNT(*), MAX(seq), MAX(observed_at)
		   FROM head_attestation WHERE chain_did=? GROUP BY witness_aid`, chainDID)
	if err != nil {
		return h, err
	}
	defer rows.Close()
	var highest uint64
	for rows.Next() {
		var aid string
		var n int
		var maxSeq int64
		var maxAt int64
		if err := rows.Scan(&aid, &n, &maxSeq, &maxAt); err != nil {
			return h, err
		}
		h.Witnesses++
		h.Attestations += n
		h.WitnessAIDs = append(h.WitnessAIDs, aid)
		if uint64(maxSeq) > highest {
			highest = uint64(maxSeq)
		}
		if maxAt > h.LatestAt {
			h.LatestAt = maxAt
		}
	}
	if err := rows.Err(); err != nil {
		return h, err
	}
	sort.Strings(h.WitnessAIDs)
	h.LatestSeq = highest
	if h.LatestAt > 0 {
		h.StaleFor = now.UnixMilli()/1000 - h.LatestAt/1000
	}
	// How far the chain has run past the last thing anybody pinned.
	_, headSeq, ok := s.IssuanceHead()
	if ok && h.Attestations > 0 && headSeq > highest {
		h.UnwitnessedRecords = headSeq - highest
	} else if ok && h.Attestations == 0 {
		h.UnwitnessedRecords = headSeq + 1 // nothing pinned, including seq 0
	}
	return h, nil
}

// ---- HTTP ----

// hIssuanceHead serves what a witness signs.
func (s *Server) hIssuanceHead(w http.ResponseWriter, _ *http.Request) {
	id, seq, ok := s.store.IssuanceHead()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"chain_did": s.hubAID,
			"note":      "nothing has been issued on this hub yet, so there is no head to pin"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"chain_did": s.hubAID, "seq": seq, "head_id": id,
		"note": "sign {chain_did, seq, head_id, observed_at} and keep it. " +
			"An attestation held only by this hub is not evidence about this hub.",
	})
}

// hIssuance serves the chain.
func (s *Server) hIssuance(w http.ResponseWriter, r *http.Request) {
	// Inclusive: ?from=0 (or absent) starts at the genesis record, which
	// a verifier must have. Continue with head_seq+1.
	var from uint64
	if v := r.URL.Query().Get("from"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &from)
	}
	entries, err := s.store.IssuanceSince(from, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	id, seq, _ := s.store.IssuanceHead()
	writeJSON(w, http.StatusOK, map[string]any{
		"chain_did": s.hubAID, "entries": entries, "head_id": id, "head_seq": seq,
		"note": "verify the record field, not the parsed columns beside it — " +
			"those are rendered by this hub and are not what it signed.",
	})
}

// hWitnessSubmit accepts an attestation somebody made about this hub.
//
// Unauthenticated: the attestation carries its own signature, and the
// worst a stranger can do is store a statement attributed to themselves.
// The witness's key history is not fetched here — a reader deciding
// whether an attestation means anything must resolve the witness and
// check it themselves, which is the only way it could ever be worth
// anything to them.
func (s *Server) hWitnessSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Attestation string `json:"attestation"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Attestation)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "attestation not base64"})
		return
	}
	a, err := ael.UnmarshalHeadAttestation(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.ChainDID != s.hubAID {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "this attestation is about " + a.ChainDID + ", not this hub"})
		return
	}
	if err := s.store.StoreAttestation(a); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "stored", "witness": a.WitnessAID(), "seq": a.Seq,
		"note": "keep your own copy. This hub serving your attestation is a convenience; " +
			"evidence about a party that only that party holds is not evidence."})
}

// hWitnesses serves the attestations held about this hub.
func (s *Server) hWitnesses(w http.ResponseWriter, _ *http.Request) {
	out, err := s.store.AttestationsAbout(s.hubAID, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	health, herr := s.store.WitnessHealthOf(s.hubAID, time.Now())
	if herr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": herr.Error()})
		return
	}
	// Where each witness can be reached, so the instruction below is one
	// a reader can actually follow.
	//
	// The note told readers to resolve each witness and check the
	// signature. Nothing said where a witness lives, and the attestation
	// carries only an AID — so the instruction named a step that could
	// not be taken. This hub knows: a witness is a federation peer and
	// the peer's endpoint is in its own configuration.
	where := map[string]string{}
	for _, aid := range health.WitnessAIDs {
		if ep := s.peerEndpoint(aid); ep != "" {
			where[aid] = ep
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"chain_did": s.hubAID, "attestations": out, "health": health,
		"witness_endpoints": where,
		"verify":            "anet verify --attestation <attestation> --hub <this hub url>",
		"note": "this hub can withhold an attestation but cannot forge one. " +
			"Resolve each witness and verify the signature yourself; then ask that " +
			"witness directly, since what it holds is what it will not have edited. " +
			"witnesses counts distinct AIDs, which is all this hub can check — two " +
			"AIDs run by one operator count as two here and are worth one, so read " +
			"witness_aids rather than the number. unwitnessed_records is how far the " +
			"chain has run past the last thing anybody pinned."})
}

// verifyRecords decodes and verifies a run of chain records.
func verifyRecords(entries []IssuanceEntry, kel []identity.SignedEvent) ([]*ael.EventRecord, error) {
	ledger := ael.NewLedger()
	var out []*ael.EventRecord
	for _, e := range entries {
		raw, err := base64.StdEncoding.DecodeString(e.Record)
		if err != nil {
			return nil, fmt.Errorf("seq %d: %w", e.Seq, err)
		}
		var rec ael.EventRecord
		if err := coredet.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("seq %d: %w", e.Seq, err)
		}
		if err := ledger.Append(&rec, kel); err != nil {
			return nil, fmt.Errorf("seq %d: %w", e.Seq, err)
		}
		out = append(out, &rec)
	}
	return out, nil
}
