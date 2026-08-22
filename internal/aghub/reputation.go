package aghub

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
)

// Reputation that stops at a hub boundary is reputation a hub owns.
//
// An agent's ratings live where its counterparties registered, so an
// agent working across two hubs has two reputations and neither is the
// truth. This file lets a hub pull its peers' ratings — and, more
// importantly, decides what it does with them.
//
// It does NOT merge them into one number. Two reasons, and the second is
// the one that matters:
//
//   - A review cannot be forged in transit. It is the requester's
//     signature interlocked with the provider's receipt, checked here the
//     same way a locally uploaded one is, so a peer relaying reviews can
//     withhold but cannot invent.
//   - A peer CAN mint identities on its own hub and have them review its
//     own agents. Nothing in the evidence model prevents that, because
//     every one of those reviews is genuine — genuinely signed by an
//     account that genuinely exists. The interlock proves a real
//     counterparty of a real interaction, not an independent one.
//
// So the arithmetic is kept per source. A reader sees "4.8 from 40
// reviews, of which 38 came from hub X" and can draw their own
// conclusion; a reader shown "4.8 from 40 reviews" has been told
// something misleading by a system that knew better. The combined figure
// is published too, because people will compute it anyway and a
// deliberately-shaped one is better than everybody's ad-hoc version —
// but it ships next to the breakdown, never instead of it.

// FedReview is one review as it crosses a hub boundary.
//
// The KELs travel with it. A receiving hub has no reason to hold the key
// history of a stranger's counterparties, and without them the interlock
// cannot be checked at all — which would reduce this to trusting the
// peer, the exact thing the evidence model exists to avoid.
type FedReview struct {
	Receipt     string `json:"receipt"`     // base64 evidence.Receipt
	Review      string `json:"review"`      // base64 evidence.Review
	RequestDoc  string `json:"request_doc"` // base64, hashes to receipt.RequestCID
	Deliverable string `json:"deliverable"` // base64, hashes to receipt.ResultCID
	ProviderKEL string `json:"provider_kel"`
	ReviewerKEL string `json:"reviewer_kel"`
	FedSeq      int64  `json:"fed_seq"`
}

// ReviewsSince serves the reputation sync stream: reviews stored HERE,
// for agents who opted into federation, after the caller's cursor.
//
// One hop, like the card stream and for the same reason (K208 §5.2). A
// hub that forwarded reviews it learned from a peer would launder a
// second-hand rating into a first-hand one, and the receiving hub's
// per-source breakdown — the whole defence above — would name the wrong
// source.
func (s *Store) ReviewsSince(cursor int64, limit int) ([]FedReview, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT r.rowid, r.interaction_id, r.subject_aid, r.reviewer_aid,
		        r.rating, r.comment, r.receipt_cid, r.created_at,
		        r.goal, r.deliverable, r.request_cid, r.result_cid, r.completed_at,
		        p.kel, q.kel
		   FROM review r
		   JOIN agent p ON p.aid = r.subject_aid
		   JOIN agent q ON q.aid = r.reviewer_aid
		  WHERE r.rowid > ? AND p.visibility IN (?, ?)
		  ORDER BY r.rowid LIMIT ?`,
		cursor, VisibilityFederated, VisibilityPublic, limit)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	out := []FedReview{}
	next := cursor
	for rows.Next() {
		var (
			rowid                                  int64
			ixID, subject, reviewer, comment, rcid string
			goal, deliverable, reqCID, resCID      string
			rating                                 int
			createdAt, completedAt                 uint64
			provKEL, revKEL                        []byte
		)
		if err := rows.Scan(&rowid, &ixID, &subject, &reviewer, &rating, &comment, &rcid,
			&createdAt, &goal, &deliverable, &reqCID, &resCID, &completedAt,
			&provKEL, &revKEL); err != nil {
			return nil, cursor, err
		}
		next = rowid
		// The stored row is not the signed object; the signatures were
		// checked on the way in and the bytes were not kept. Rebuilding
		// them is the honest gap in this design and it is closed by
		// storing what was verified — see reviewBlob.
		blob, err := s.reviewBlob(ixID)
		if err != nil || blob == nil {
			continue
		}
		blob.ProviderKEL = base64.StdEncoding.EncodeToString(provKEL)
		blob.ReviewerKEL = base64.StdEncoding.EncodeToString(revKEL)
		blob.FedSeq = rowid
		out = append(out, *blob)
	}
	return out, next, rows.Err()
}

// reviewBlob reads back the exact bytes that were verified on upload.
//
// Kept because a rating is only as good as the objects behind it, and a
// hub that stored the conclusion and threw away the evidence could not
// pass the evidence on — it could only pass on its own say-so, which is
// what federating reputation must not be.
func (s *Store) reviewBlob(interactionID string) (*FedReview, error) {
	var receipt, review, doc, deliv []byte
	err := s.db.QueryRow(
		`SELECT receipt_raw, review_raw, request_doc_raw, deliverable_raw
		   FROM review_blob WHERE interaction_id=?`, interactionID).
		Scan(&receipt, &review, &doc, &deliv)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &FedReview{
		Receipt:     base64.StdEncoding.EncodeToString(receipt),
		Review:      base64.StdEncoding.EncodeToString(review),
		RequestDoc:  base64.StdEncoding.EncodeToString(doc),
		Deliverable: base64.StdEncoding.EncodeToString(deliv),
	}, nil
}

// PutReviewBlob keeps the verified bytes alongside the parsed row.
func (s *Store) PutReviewBlob(interactionID string, receipt, review, doc, deliv []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO review_blob(interaction_id, receipt_raw, review_raw, request_doc_raw, deliverable_raw)
		 VALUES(?,?,?,?,?) ON CONFLICT(interaction_id) DO NOTHING`,
		interactionID, receipt, review, doc, deliv)
	return err
}

// AdmitFedReview checks a peer's review the same way a local upload is
// checked, and stores it as that peer's.
//
// "The same way" is load-bearing. A federated review admitted on weaker
// terms than a local one would make federation the way to get a rating in
// without evidence, and every attacker would use exactly that door.
func (s *Store) AdmitFedReview(peerAID string, fr FedReview) error {
	dec := func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
	rcBytes, err := dec(fr.Receipt)
	if err != nil {
		return fmt.Errorf("receipt not base64: %w", err)
	}
	rvBytes, err := dec(fr.Review)
	if err != nil {
		return fmt.Errorf("review not base64: %w", err)
	}
	docBytes, err := dec(fr.RequestDoc)
	if err != nil {
		return fmt.Errorf("request doc not base64: %w", err)
	}
	delivBytes, err := dec(fr.Deliverable)
	if err != nil {
		return fmt.Errorf("deliverable not base64: %w", err)
	}
	provKELBytes, err := dec(fr.ProviderKEL)
	if err != nil {
		return fmt.Errorf("provider kel not base64: %w", err)
	}
	revKELBytes, err := dec(fr.ReviewerKEL)
	if err != nil {
		return fmt.Errorf("reviewer kel not base64: %w", err)
	}
	rc, err := evidence.UnmarshalReceipt(rcBytes)
	if err != nil {
		return fmt.Errorf("receipt undecodable: %w", err)
	}
	rv, err := evidence.UnmarshalReview(rvBytes)
	if err != nil {
		return fmt.Errorf("review undecodable: %w", err)
	}
	provKEL, err := identity.UnmarshalKEL(provKELBytes)
	if err != nil {
		return fmt.Errorf("provider kel malformed: %w", err)
	}
	revKEL, err := identity.UnmarshalKEL(revKELBytes)
	if err != nil {
		return fmt.Errorf("reviewer kel malformed: %w", err)
	}
	// The KELs arrived from the peer, so they have to be checked against
	// the AIDs the objects name rather than taken as given. A peer that
	// supplied its own key history for both parties could otherwise sign
	// a whole interaction into existence.
	if err := kelMatches(provKEL, rc.ProviderAID); err != nil {
		return fmt.Errorf("provider key history: %w", err)
	}
	if err := kelMatches(revKEL, rv.ReviewerAID); err != nil {
		return fmt.Errorf("reviewer key history: %w", err)
	}
	if err := evidence.VerifyInterlock(rc, rv, docBytes, delivBytes, provKEL, revKEL); err != nil {
		return fmt.Errorf("federated review refused: %w", err)
	}
	// An agent registered HERE has its ratings here; a peer's copy must
	// not add to them, or a peer could inflate one of our own agents.
	var local int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM agent WHERE aid=?`, rv.SubjectAID).Scan(&local); err != nil {
		return err
	}
	if local > 0 {
		return fmt.Errorf("federated review for %s, which is registered here", rv.SubjectAID)
	}
	_, err = s.db.Exec(
		`INSERT INTO fed_review(interaction_id, subject_aid, reviewer_aid, rating, comment,
		   receipt_cid, peer_aid, created_at, stored_at)
		 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(interaction_id) DO NOTHING`,
		rv.InteractionID, rv.SubjectAID, rv.ReviewerAID, rv.Rating, rv.Comment,
		rv.ReceiptCID, peerAID, rv.CreatedAt, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// kelMatches checks a key history actually belongs to the AID claimed.
func kelMatches(kel []identity.SignedEvent, aid string) error {
	states, err := identity.Replay(kel)
	if err != nil {
		return fmt.Errorf("does not replay: %w", err)
	}
	if got := states[len(states)-1].AID; got != aid {
		return fmt.Errorf("is %s, not %s", got, aid)
	}
	return nil
}

// Source is one origin's view of an agent.
type Source struct {
	// Hub is the hub those reviews were collected by. Empty means here.
	Hub     string  `json:"hub,omitempty"`
	Reviews int     `json:"reviews"`
	Avg     float64 `json:"avg_rating"`
}

// Reputation is what this hub knows about an agent's standing, kept by
// source rather than flattened.
type Reputation struct {
	AID   string   `json:"aid"`
	Local Source   `json:"local"`
	Peers []Source `json:"peers"`
	// Combined is every source pooled. Published because people will
	// compute it regardless, and next to the breakdown rather than
	// instead of it: one hub can hold most of the mass, and a single
	// number cannot say so.
	Combined Source `json:"combined"`
	// Concentration is the largest single source's share of Combined,
	// 0..1. The one number that makes a pooled average safe to read: 0.95
	// means one hub is effectively deciding this rating.
	Concentration float64 `json:"concentration"`
}

// ReputationOf assembles an agent's standing from every source.
func (s *Store) ReputationOf(aid string) (Reputation, error) {
	out := Reputation{AID: aid, Peers: []Source{}}
	var avg sql.NullFloat64
	if err := s.db.QueryRow(
		`SELECT COUNT(*), AVG(rating) FROM review WHERE subject_aid=?`, aid).
		Scan(&out.Local.Reviews, &avg); err != nil {
		return out, err
	}
	out.Local.Avg = round2(avg.Float64)

	rows, err := s.db.Query(
		`SELECT peer_aid, COUNT(*), AVG(rating) FROM fed_review
		  WHERE subject_aid=? GROUP BY peer_aid ORDER BY COUNT(*) DESC`, aid)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var src Source
		var a sql.NullFloat64
		if err := rows.Scan(&src.Hub, &src.Reviews, &a); err != nil {
			return out, err
		}
		src.Avg = round2(a.Float64)
		out.Peers = append(out.Peers, src)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}

	total, sum, biggest := out.Local.Reviews, out.Local.Avg*float64(out.Local.Reviews), out.Local.Reviews
	for _, p := range out.Peers {
		total += p.Reviews
		sum += p.Avg * float64(p.Reviews)
		if p.Reviews > biggest {
			biggest = p.Reviews
		}
	}
	out.Combined.Reviews = total
	if total > 0 {
		out.Combined.Avg = round2(sum / float64(total))
		out.Concentration = round2(float64(biggest) / float64(total))
	}
	return out, nil
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

// ---- HTTP ----

// hReputation publishes an agent's standing, by source.
func (s *Server) hReputation(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.ReputationOf(r.PathValue("aid"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reputation": rep,
		"note": "kept by source on purpose. a peer hub cannot forge a review — every one is the " +
			"requester's signature interlocked with the provider's receipt, checked here — but it " +
			"can register accounts of its own and have them review its own agents. concentration " +
			"is how much of the combined figure rests on a single hub.",
	})
}

// hFedReviews serves the reputation sync stream to a peer.
func (s *Server) hFedReviews(w http.ResponseWriter, r *http.Request) {
	cursor := int64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		_, _ = fmt.Sscanf(v, "%d", &cursor)
	}
	revs, next, err := s.store.ReviewsSince(cursor, 0)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": revs, "next": next})
}

// FedReviewJSON is the encoding used on the sync wire.
func (fr FedReview) FedReviewJSON() ([]byte, error) { return json.Marshal(fr) }
