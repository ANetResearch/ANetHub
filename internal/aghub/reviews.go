package aghub

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Reviews, version 2 (hub-payment-privacy §2.5, §3.2, §4.2.3; core §2.9,
// L27–L33).
//
// A review still rests on the provider's own signature, so a hub cannot
// invent one: the provider signs a receipt for the task it completed, and the
// requester rates it with a one-time key whose public half the requester put
// in the task and the provider copied into the receipt. Unlike version 1, the
// pair names nobody but the provider. The receipt carries commitments to the
// interaction (ix_commit, L27) and to the requester (requester_commit, L28);
// the review is signed by the one-time key, not by the requester's identity.
//
// The requester uploads the pair signed as itself (relayauth review), with
// the salt of its commitment, so this hub can check that the uploader is the
// requester the receipt committed to (PAY-V1 step 6). What the hub then
// keeps is the review without the reviewer (SI-48): a tag (L31) under a key
// only this hub holds (tagkey.go) lets readers count distinct reviewers per
// subject and nothing more, every stored time is a UTC day, and neither the
// uploader's AID nor its salt is written anywhere or logged. The hub signs an
// attestation of what it stored (L32), which travels with the review to peer
// hubs (/fed/v3/reviews) and back to the uploader.

// FormatReviewV2 is the format of a review stream entry (core §2.12.2).
const FormatReviewV2 = "review/2"

// ReviewStored is the status of an accepted upload.
const ReviewStored = "stored"

// maxReviewUploadBody bounds POST /reviews (hub-payment-privacy §0.4).
const maxReviewUploadBody = 16 << 10

// ReviewWindowDays is how long after its interaction ends a review is
// accepted: its created_day is completed_day up to completed_day + 30
// (PAY-V1 step 7).
const ReviewWindowDays = 30

// reviewSchema is the review tables of hub.db (hub-payment-privacy §3.2).
func reviewSchema() []string {
	return []string{
		// One row per review uploaded here. The key is the interaction's
		// commitment, so an interaction is reviewed once whatever receipts
		// its provider signed for it. There is no reviewer column and no
		// time finer than a UTC day (SI-48): tag counts reviewers under
		// the key tag_key_id names. The rowid orders the review stream
		// (fed_seq); reviews are never deleted, so it never goes back.
		`CREATE TABLE IF NOT EXISTS review (
		   ix_commit     BLOB PRIMARY KEY,
		   subject_aid   TEXT NOT NULL,
		   tag           BLOB NOT NULL,
		   tag_key_id    INTEGER NOT NULL,
		   rating        INTEGER NOT NULL,
		   comment       TEXT NOT NULL DEFAULT '',
		   receipt_cid   TEXT NOT NULL,
		   completed_day INTEGER NOT NULL,
		   created_day   INTEGER NOT NULL,
		   stored_day    INTEGER NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_review_subject ON review(subject_aid)`,
		// The signed objects a review was checked from, and this hub's
		// attestation of it, so that a peer can check them for itself
		// rather than take this hub's word.
		`CREATE TABLE IF NOT EXISTS review_blob (
		   ix_commit       BLOB PRIMARY KEY,
		   receipt_raw     BLOB NOT NULL,
		   review_raw      BLOB NOT NULL,
		   attestation_raw BLOB NOT NULL
		 )`,
		// Reviews learned from a peer hub, apart from local ones so the
		// arithmetic stays per source (reputation): a peer's tags are
		// under its own key and say nothing next to ours.
		`CREATE TABLE IF NOT EXISTS fed_review (
		   ix_commit   BLOB PRIMARY KEY,
		   subject_aid TEXT NOT NULL,
		   tag         BLOB NOT NULL,
		   tag_key_id  INTEGER NOT NULL,
		   peer_aid    TEXT NOT NULL,
		   rating      INTEGER NOT NULL,
		   comment     TEXT NOT NULL DEFAULT '',
		   receipt_cid TEXT NOT NULL,
		   created_day INTEGER NOT NULL,
		   stored_day  INTEGER NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_fed_review_subject ON fed_review(subject_aid)`,
	}
}

// reviewDay is the UTC day number of t (core CORE-E6), the only time a
// review row holds.
func reviewDay(t time.Time) uint64 {
	if d := utcDay(t); d > 0 {
		return uint64(d)
	}
	return 0
}

// ---- POST /reviews ----

// UploadReviewRequest is the body of POST /reviews (core §2.12.2): the
// receipt (evidence.ReceiptWire) and the review (evidence.ReviewWire) as the
// requester holds them, and rsalt, the 32 bytes of its requester_commit, all
// base64url. It is decoded strictly: v0.2's request_doc and deliverable, or
// any other member, are refused.
type UploadReviewRequest struct {
	Receipt string `json:"receipt"`
	Review  string `json:"review"`
	RSalt   string `json:"rsalt"`
}

// UploadReviewResponse is the answer to an accepted upload: status "stored"
// and this hub's attestation (evidence.ReviewAttWire, base64url).
type UploadReviewResponse struct {
	Status      string `json:"status"`
	Attestation string `json:"attestation"`
}

// reviewUpload is an upload after PAY-V1 step 3: both objects decoded.
type reviewUpload struct {
	receiptRaw, reviewRaw []byte
	receipt               *evidence.ReceiptWire
	review                *evidence.ReviewWire
	rc                    *evidence.ReceiptBody
	rv                    *evidence.ReviewBody
	rsalt                 []byte
}

// hUploadReview is POST /reviews, in the order of PAY-V1; each step that
// fails answers with its code, so an upload wrong in several ways gets the
// code of the first:
//
//  1. relayauth review, signed by an agent registered here (401);
//  2. the signer is on probation: 403 probation;
//  3. the body: strict JSON with three base64url members (rsalt 32 bytes),
//     each object well-formed CBOR, the rating 1..5, the comment at most 280
//     characters, the subject without U+0000: 400 bad_request; objects of
//     another type or without their commitments: 400 receipt_not_reviewable;
//  4. the provider's signature on the receipt, under the key history this
//     hub holds for it (registered here, learned from a peer, or departed),
//     judged at the receipt's own day (SI-36): 400 receipt_not_reviewable;
//  5. the review's signature by the receipt's review_key, the review naming
//     this receipt and its provider: 400 receipt_not_reviewable;
//  6. requester_commit is the signer's with this rsalt: 400
//     requester_commit_mismatch;
//  7. created_day within 30 days from completed_day, and not after
//     tomorrow: 400 review_window_closed;
//  8. (merged into 3);
//  9. the interaction has no review here, local or from a peer: 409
//     review_exists.
//
// Then it tags the reviewer (L31), signs the attestation (L32) and stores
// both objects and the attestation; 200 {status: stored, attestation}.
func (s *Server) hUploadReview(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authRegistered(w, r, relayauth.ActionReview, maxReviewUploadBody)
	if !ok {
		return
	}
	if _, on := s.store.ProbationUntil(a.AID); on {
		wire3.Refuse(w, wire3.ReasonProbation)
		return
	}
	up, rf := decodeReviewUpload(a.Body)
	if rf != nil {
		wire3.Write(w, *rf)
		return
	}
	// Step 5's signature first: it is one Ed25519 check against the
	// receipt's review_key, where step 4 replays the provider's key history
	// (kelreplay.go). Both answer receipt_not_reviewable.
	if _, err := up.review.Verify(up.rc.ReviewKey); err != nil {
		wire3.Refuse(w, wire3.ReasonReceiptNotReviewable)
		return
	}
	kel, err := s.store.subjectKEL(up.rc.Provider)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if kel == nil || !receiptPlausible(up.receipt, kel) {
		wire3.Refuse(w, wire3.ReasonReceiptNotReviewable)
		return
	}
	if _, _, err := evidence.CheckV2(up.receipt, up.review, kel); err != nil {
		wire3.Refuse(w, wire3.ReasonReceiptNotReviewable)
		return
	}
	want, err := evidence.RequesterCommit(a.AID, up.rsalt)
	if err != nil || subtle.ConstantTimeCompare(want, up.rc.RequesterCommit) != 1 {
		wire3.Refuse(w, wire3.ReasonRequesterCommitMismatch)
		return
	}
	today := reviewDay(s.store.now())
	if !inReviewWindow(up.rc.CompletedDay, up.rv.CreatedDay, today) {
		wire3.Refuse(w, wire3.ReasonReviewWindowClosed)
		return
	}
	if exists, err := reviewExists(s.store.db, up.rc.IXCommit); err != nil {
		wire3.Internal(w, err)
		return
	} else if exists {
		wire3.Refuse(w, wire3.ReasonReviewExists)
		return
	}
	stored, att, err := s.store.attest(a.AID, up, today)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	switch err := s.store.StoreReview(stored, up.receiptRaw, up.reviewRaw, att); {
	case errors.Is(err, ErrReviewExists):
		wire3.Refuse(w, wire3.ReasonReviewExists)
		return
	case err != nil:
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, UploadReviewResponse{Status: ReviewStored, Attestation: wire3.EncodeB64URL(att)})
}

// decodeReviewUpload is the body's part of PAY-V1 step 3. The refusal is
// bad_request for a request that is not one (JSON, base64url, CBOR, or a
// rating, comment or subject no review may have), and
// receipt_not_reviewable for well-formed objects that are not a 0.3.0
// receipt and review (another type tag, a v0.2 object, a missing
// commitment).
func decodeReviewUpload(body []byte) (*reviewUpload, *wire3.Refusal) {
	var req UploadReviewRequest
	if err := wire3.DecodeStrict(body, &req); err != nil {
		return nil, decodeRefusal(err)
	}
	up := &reviewUpload{}
	var err error
	if up.receiptRaw, err = requiredB64URL("receipt", req.Receipt); err != nil {
		return nil, decodeRefusal(err)
	}
	if up.reviewRaw, err = requiredB64URL("review", req.Review); err != nil {
		return nil, decodeRefusal(err)
	}
	if up.rsalt, err = wire3.DecodeB64URLSize("rsalt", req.RSalt, evidence.RSaltSize); err != nil {
		return nil, decodeRefusal(err)
	}
	for _, m := range []struct {
		name string
		raw  []byte
	}{{"receipt", up.receiptRaw}, {"review", up.reviewRaw}} {
		if !wellFormedCBOR(m.raw) {
			return nil, &wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "The member \"" + m.name + "\" is not CBOR; send the " + m.name + "'s bytes as they were signed, base64url."}
		}
	}
	if up.receipt, err = evidence.UnmarshalReceiptWire(up.receiptRaw); err != nil {
		return nil, objectRefusal(err)
	}
	if up.review, err = evidence.UnmarshalReviewWire(up.reviewRaw); err != nil {
		return nil, objectRefusal(err)
	}
	// Both decoders checked their bodies; these cannot fail now.
	if up.rc, err = up.receipt.Open(); err != nil {
		return nil, objectRefusal(err)
	}
	if up.rv, err = up.review.Open(); err != nil {
		return nil, objectRefusal(err)
	}
	return up, nil
}

// requiredB64URL decodes a member that must be there and not be empty.
func requiredB64URL(member, s string) ([]byte, error) {
	if s == "" {
		return nil, &wire3.DecodeError{Kind: wire3.KindType, Member: member}
	}
	return wire3.DecodeB64URL(member, s)
}

// decodeRefusal is the 400 bad_request of a body that does not decode (as
// wire3.RefuseDecode sends it).
func decodeRefusal(err error) *wire3.Refusal {
	var de *wire3.DecodeError
	if !errors.As(err, &de) {
		de = &wire3.DecodeError{Kind: wire3.KindSyntax, Detail: err.Error()}
	}
	return &wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: de.Sentence()}
}

// objectRefusal maps an evidence decoding error (PAY-V1 step 3): a rating, a
// comment or a subject that no review may carry is the request's fault,
// anything else says the objects are not a 0.3.0 receipt and review.
func objectRefusal(err error) *wire3.Refusal {
	switch {
	case errors.Is(err, evidence.ErrRating):
		return &wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The review's rating is not between 1 and 5; rate the interaction 1 to 5 and sign the review again."}
	case errors.Is(err, evidence.ErrComment):
		return &wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The review's comment is longer than 280 characters; shorten it and sign the review again."}
	case errors.Is(err, evidence.ErrNUL):
		return &wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The review's subject contains U+0000; name the provider's AID as the receipt does and sign the review again."}
	}
	return &wire3.Refusal{Reason: wire3.ReasonReceiptNotReviewable}
}

// wellFormedCBOR reports whether b is one CBOR data item that the CoreDet
// decoder reads: no trailing bytes, no tags, no duplicate map keys, text in
// UTF-8. Whether it is the right object is the evidence decoder's question.
func wellFormedCBOR(b []byte) bool {
	var v any
	return len(b) > 0 && coredet.Unmarshal(b, &v) == nil
}

// receiptPlausible checks the receipt's signature against the key the
// provider's key history names at the receipt's key state, without replaying
// the history (kelreplay.go): a receipt signed with any other key costs one
// verification, not a replay, before it is refused.
func receiptPlausible(rw *evidence.ReceiptWire, kel []identity.SignedEvent) bool {
	return rw.Env != nil && plausibleSignature(kel, rw.Env.KeyStateSeq, rw.Body, rw.Env.Sig) == nil
}

// inReviewWindow is PAY-V1 step 7: created is completed up to completed + 30
// (UTC days), and not after today + 1.
func inReviewWindow(completed, created, today uint64) bool {
	return created >= completed && created-completed <= ReviewWindowDays && created <= today+1
}

// subjectKEL is the key history this hub holds for aid: registered here,
// learned from a peer's card stream, or kept after it left (departed_kel).
// nil when there is none.
func (s *Store) subjectKEL(aid string) ([]identity.SignedEvent, error) {
	raw, err := s.anyKEL(aid)
	if err != nil || raw == nil {
		return nil, err
	}
	kel, err := identity.UnmarshalKEL(raw)
	if err != nil {
		return nil, fmt.Errorf("hub: the key history held for %s does not decode: %w", aid, err)
	}
	return kel, nil
}

// reviewTag is the tag of a review by reviewer of subject under key (L31).
func reviewTag(key []byte, reviewer, subject string) ([]byte, error) {
	return evidence.ReviewTag(key, reviewer, subject)
}

// attest tags the reviewer and signs this hub's attestation of the review
// (PAY-V2): the row to store, and the attestation's bytes.
func (s *Store) attest(reviewer string, up *reviewUpload, today uint64) (StoredReview, []byte, error) {
	if s.hubKey == nil {
		return StoredReview{}, nil, errors.New("hub: this hub holds no signing key to attest reviews with")
	}
	key, keyID, err := s.reviewTagKey()
	if err != nil {
		return StoredReview{}, nil, err
	}
	tag, err := reviewTag(key, reviewer, up.rv.Subject)
	if err != nil {
		return StoredReview{}, nil, err
	}
	receiptCID, err := up.receipt.CID()
	if err != nil {
		return StoredReview{}, nil, err
	}
	reviewCID, err := up.review.CID()
	if err != nil {
		return StoredReview{}, nil, err
	}
	body := &evidence.ReviewAttBody{ReviewCID: reviewCID, ReceiptCID: receiptCID, Subject: up.rv.Subject,
		Tag: tag, TagKeyID: keyID, Day: today}
	wire, err := body.Sign(s.hubKey)
	if err != nil {
		return StoredReview{}, nil, err
	}
	raw, err := wire.Marshal()
	if err != nil {
		return StoredReview{}, nil, err
	}
	return StoredReview{
		IXCommit: up.rc.IXCommit, Subject: up.rv.Subject, Tag: tag, TagKeyID: keyID,
		Rating: up.rv.Rating, Comment: up.rv.Comment, ReceiptCID: receiptCID,
		CompletedDay: up.rc.CompletedDay, CreatedDay: up.rv.CreatedDay, StoredDay: today,
	}, raw, nil
}

// ---- the store ----

// StoredReview is a review row as this hub keeps it (hub-payment-privacy
// §3.2): no reviewer, no interaction id, days only.
type StoredReview struct {
	IXCommit     []byte
	Subject      string
	Tag          []byte
	TagKeyID     uint64
	Rating       uint64
	Comment      string
	ReceiptCID   string
	CompletedDay uint64
	CreatedDay   uint64
	StoredDay    uint64
}

// ErrReviewExists is a review of an interaction this hub holds a review of
// already, uploaded here or learned from a peer (PAY-V1 step 9).
var ErrReviewExists = errors.New("hub: the interaction has a review here already")

// reviewExists reports whether a review of the interaction ixCommit is held,
// local or from a peer.
func reviewExists(q rowQuerier, ixCommit []byte) (bool, error) {
	var one int
	err := q.QueryRow(`SELECT 1 FROM review WHERE ix_commit=?
		UNION ALL SELECT 1 FROM fed_review WHERE ix_commit=? LIMIT 1`, ixCommit, ixCommit).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// StoreReview keeps a review that passed every check of PAY-V1, with the
// receipt, the review and the attestation it was stored under. A review of
// the same interaction already held, here or from a peer, is ErrReviewExists
// and nothing is written.
func (s *Store) StoreReview(r StoredReview, receiptRaw, reviewRaw, attestationRaw []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if exists, err := reviewExists(tx, r.IXCommit); err != nil {
		return err
	} else if exists {
		return ErrReviewExists
	}
	if _, err := tx.Exec(`INSERT INTO review(ix_commit, subject_aid, tag, tag_key_id, rating, comment,
		   receipt_cid, completed_day, created_day, stored_day) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.IXCommit, r.Subject, r.Tag, r.TagKeyID, r.Rating, r.Comment,
		r.ReceiptCID, r.CompletedDay, r.CreatedDay, r.StoredDay); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO review_blob(ix_commit, receipt_raw, review_raw, attestation_raw)
		VALUES(?,?,?,?)`, r.IXCommit, receiptRaw, reviewRaw, attestationRaw); err != nil {
		return err
	}
	return tx.Commit()
}

// reviewsOf is the reviews stored here of aid, newest first.
func (s *Store) reviewsOf(aid string) ([]ReviewView, error) {
	rows, err := s.db.Query(`SELECT subject_aid, rating, comment, receipt_cid, completed_day, created_day
		FROM review WHERE subject_aid=? ORDER BY created_day DESC, rowid DESC`, aid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReviewView{}
	for rows.Next() {
		var v ReviewView
		if err := rows.Scan(&v.SubjectAID, &v.Rating, &v.Comment, &v.ReceiptCID, &v.CompletedDay, &v.CreatedDay); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- the review stream (/fed/v3/reviews) ----

// FedReviewEntry is one entry of the review stream (core §2.12.2): the
// receipt and the review as they were uploaded here, this hub's attestation,
// and the provider's key history, all base64url, and the entry's place in
// the stream. It names no reviewer and no interaction and carries no time
// finer than a day (hub-payment-privacy §2.5): those were never kept.
type FedReviewEntry struct {
	Format      string `json:"format"`
	Receipt     string `json:"receipt"`
	Review      string `json:"review"`
	Attestation string `json:"attestation"`
	ProviderKEL string `json:"provider_kel"`
	FedSeq      uint64 `json:"fed_seq"`
}

// ReviewsSince serves the review stream: reviews uploaded HERE after the
// caller's cursor, of subjects that consented to federation.
//
// One hop. A hub that forwarded what it learned from a peer would launder a
// second-hand rating into a first-hand one, and the per-source arithmetic
// of the receiving hub would name the wrong source; fed_review is never
// served.
//
// Whose consent governs is the subject's, because the reputation at stake
// is the subject's: one registered here by its visibility; one registered
// elsewhere by the A2A card its home hub federates (fed_a2a_card, verified),
// which is how this hub knows it at all.
func (s *Store) ReviewsSince(cursor int64, limit int) ([]FedReviewEntry, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT r.rowid, b.receipt_raw, b.review_raw, b.attestation_raw, COALESCE(p.kel, g.kel)
		   FROM review r
		   JOIN review_blob b ON b.ix_commit = r.ix_commit
		   LEFT JOIN agent p ON p.aid = r.subject_aid
		   LEFT JOIN fed_a2a_card g ON g.aid = r.subject_aid AND g.verified_at IS NOT NULL
		  WHERE r.rowid > ?
		    AND (p.visibility IN (?, ?) OR (p.aid IS NULL AND g.aid IS NOT NULL))
		  ORDER BY r.rowid LIMIT ?`,
		cursor, VisibilityFederated, VisibilityPublic, limit)
	if err != nil {
		return nil, cursor, err
	}
	defer rows.Close()
	out := []FedReviewEntry{}
	next := cursor
	for rows.Next() {
		var (
			seq                  int64
			receipt, review, att []byte
			kel                  []byte
		)
		if err := rows.Scan(&seq, &receipt, &review, &att, &kel); err != nil {
			return nil, cursor, err
		}
		next = seq
		out = append(out, FedReviewEntry{Format: FormatReviewV2,
			Receipt: wire3.EncodeB64URL(receipt), Review: wire3.EncodeB64URL(review),
			Attestation: wire3.EncodeB64URL(att), ProviderKEL: wire3.EncodeB64URL(kel), FedSeq: uint64(seq)})
	}
	return out, next, rows.Err()
}

// ErrFedReviewFormat is a stream entry of another format than review/2.
var ErrFedReviewFormat = errors.New("hub: the review stream entry is not review/2")

// AdmitFedReview checks one entry of a peer's review stream and stores it as
// that peer's (PAY-V3), in this order: the provider's signature on the
// receipt; the review's by the receipt's review_key, naming this receipt and
// its provider; the peer's attestation, signed by peerAID under peerKEL as
// it stood on the attestation's day (CORE-L8); the attestation stating this
// review, receipt and subject; the interaction reviewed nowhere here yet.
//
// "The same way as a local upload" is load-bearing: a federated review
// admitted on weaker terms would be the way to get a rating in without
// evidence. Two checks of an upload cannot be made here, and the
// attestation stands for them: that the uploader was the requester, and the
// review window — the peer checked both, and signed that it stored the
// review.
//
// An attestation signed under a key state beyond peerKEL wraps
// federation.ErrRefusedForNow: the peer rotated and this hub has not caught
// up with its key history yet. The same entry again from the same peer (a
// full resync) is not an error.
func (s *Store) AdmitFedReview(peerAID string, peerKEL []identity.SignedEvent, e FedReviewEntry) error {
	if e.Format != FormatReviewV2 {
		return fmt.Errorf("%w: %q", ErrFedReviewFormat, e.Format)
	}
	dec := func(member, v string) ([]byte, error) {
		b, err := wire3.DecodeB64URL(member, v)
		if err == nil && len(b) == 0 {
			err = fmt.Errorf("%s is empty", member)
		}
		return b, err
	}
	receiptRaw, err := dec("receipt", e.Receipt)
	if err != nil {
		return err
	}
	reviewRaw, err := dec("review", e.Review)
	if err != nil {
		return err
	}
	attRaw, err := dec("attestation", e.Attestation)
	if err != nil {
		return err
	}
	var offered []byte
	if e.ProviderKEL != "" {
		if offered, err = wire3.DecodeB64URL("provider_kel", e.ProviderKEL); err != nil {
			return err
		}
	}
	receipt, err := evidence.UnmarshalReceiptWire(receiptRaw)
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	review, err := evidence.UnmarshalReviewWire(reviewRaw)
	if err != nil {
		return fmt.Errorf("review: %w", err)
	}
	att, err := evidence.UnmarshalReviewAttWire(attRaw)
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}
	rc, err := receipt.Open()
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	provKEL, err := s.providerKELFor(rc.Provider, offered)
	if err != nil {
		return err
	}
	if !receiptPlausible(receipt, provKEL) {
		return errors.New("the provider's signature on the receipt does not verify")
	}
	_, rv, err := evidence.CheckV2(receipt, review, provKEL)
	if err != nil {
		return err
	}
	ab, err := s.checkPeerAttestation(peerAID, peerKEL, att)
	if err != nil {
		return err
	}
	receiptCID, err := receipt.CID()
	if err != nil {
		return err
	}
	reviewCID, err := review.CID()
	if err != nil {
		return err
	}
	if ab.ReviewCID != reviewCID || ab.ReceiptCID != receiptCID || ab.Subject != rv.Subject {
		return errors.New("the attestation is about another review")
	}
	return s.storeFedReview(peerAID, rc.IXCommit, ab, rv, receiptCID)
}

// checkPeerAttestation verifies a peer's attestation (CORE-L8: under the
// peer's key history at the attestation's own day) and returns its body.
//
// A peer that rotated signs under its new key at once. An attestation
// signed under a key state past peerKEL has the peer's key history fetched
// again, once, and at most once a minute per peer (KEL H-34; peerKELFor),
// so it is admitted in the same pass of the review stream instead of after
// the next periodic fetch; when the history still does not reach it, it is
// refused for now.
func (s *Store) checkPeerAttestation(peerAID string, peerKEL []identity.SignedEvent, att *evidence.ReviewAttWire) (*evidence.ReviewAttBody, error) {
	ab, err := att.Open()
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	if ab.Hub != peerAID || att.Env == nil || att.Env.SignerAID != peerAID {
		return nil, fmt.Errorf("the attestation is %s's, not the peer %s's", ab.Hub, peerAID)
	}
	held := func(string) ([]identity.SignedEvent, error) { return peerKEL, nil }
	if peerKEL, err = s.peerKELFor(held, peerAID, att.Env.KeyStateSeq); err != nil || len(peerKEL) == 0 {
		return nil, fmt.Errorf("%w: this hub holds no key history of %s to check its attestation with",
			federation.ErrRefusedForNow, peerAID)
	}
	if verr := plausibleSignature(peerKEL, att.Env.KeyStateSeq, att.Body, att.Env.Sig); verr != nil {
		return nil, attestationRefusal(peerAID, verr)
	}
	at, ok := evidence.DayStart(ab.Day)
	if !ok {
		return nil, fmt.Errorf("the attestation's day %d is not a day", ab.Day)
	}
	if _, err := att.Verify(peerKEL, at); err != nil {
		var verr *identity.VErr
		if errors.As(err, &verr) {
			return nil, attestationRefusal(peerAID, verr)
		}
		return nil, err
	}
	return ab, nil
}

// attestationRefusal says why a peer's attestation was refused: for now
// when it is signed under a key state this hub has not seen yet.
func attestationRefusal(peerAID string, verr *identity.VErr) error {
	if verr.Reason == "KEY_STATE_DOWNGRADE" {
		return fmt.Errorf("%w: %s signed its attestation under a key state this hub does not hold yet",
			federation.ErrRefusedForNow, peerAID)
	}
	return fmt.Errorf("the attestation of %s does not verify: %v", peerAID, verr)
}

// providerKELFor is the key history to check a peer's receipt with: the
// longer of the one this hub holds and the one the peer sent, when one
// extends the other. A peer cannot replace a history this hub knows with a
// shorter one (under which a key the provider retired would look current),
// nor with a fork.
func (s *Store) providerKELFor(aid string, offered []byte) ([]identity.SignedEvent, error) {
	held, err := s.subjectKEL(aid)
	if err != nil {
		return nil, err
	}
	var sent []identity.SignedEvent
	if len(offered) > 0 {
		if sent, err = identity.UnmarshalKEL(offered); err != nil {
			return nil, fmt.Errorf("provider key history: %w", err)
		}
		if err := kelMatches(sent, aid); err != nil {
			return nil, fmt.Errorf("provider key history: %w", err)
		}
	}
	switch {
	case held == nil && sent == nil:
		return nil, fmt.Errorf("no key history of the provider %s", aid)
	case held == nil:
		return sent, nil
	case sent == nil:
		return held, nil
	}
	switch err := identity.ExtendsKEL(held, sent); {
	case err == nil:
		return sent, nil
	case errors.Is(err, identity.ErrKELRollback):
		return held, nil
	default:
		return nil, fmt.Errorf("provider key history: %w", err)
	}
}

// kelMatches checks a key history belongs to the AID claimed.
func kelMatches(kel []identity.SignedEvent, aid string) error {
	states, err := identity.Replay(kel)
	if err != nil {
		return fmt.Errorf("does not replay: %w", err)
	}
	if got := states[len(states)-1].AID; got != aid {
		return fmt.Errorf("is %s's, not %s's", got, aid)
	}
	return nil
}

// storeFedReview keeps a peer's review. The same review again from the same
// peer (a full resync) changes nothing; one of an interaction reviewed here
// or at another peer is ErrReviewExists.
func (s *Store) storeFedReview(peerAID string, ixCommit []byte, ab *evidence.ReviewAttBody,
	rv *evidence.ReviewBody, receiptCID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var peer string
	var tag []byte
	switch err := tx.QueryRow(`SELECT peer_aid, tag FROM fed_review WHERE ix_commit=?`, ixCommit).Scan(&peer, &tag); {
	case err == nil:
		if peer == peerAID && bytes.Equal(tag, ab.Tag) {
			return nil
		}
		return ErrReviewExists
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if exists, err := reviewExists(tx, ixCommit); err != nil {
		return err
	} else if exists {
		return ErrReviewExists
	}
	if _, err := tx.Exec(`INSERT INTO fed_review(ix_commit, subject_aid, tag, tag_key_id, peer_aid, rating,
		   comment, receipt_cid, created_day, stored_day) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		ixCommit, rv.Subject, ab.Tag, ab.TagKeyID, peerAID, rv.Rating,
		rv.Comment, receiptCID, rv.CreatedDay, reviewDay(s.now())); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- reputation ----

// Reputation that stops at a hub boundary is reputation a hub owns: an agent
// working across two hubs is rated at both. This hub pulls its peers'
// reviews — and keeps them apart.
//
// A peer cannot forge a review: each rests on the provider's signature,
// checked here. A peer CAN register accounts of its own and have them review
// its own agents; every one of those reviews is genuine. So the arithmetic is
// kept per source: a reader sees "4.8 from 40 reviews, 38 of them from hub
// X" and draws their own conclusion. The pooled figure is published too,
// beside the breakdown, never instead of it. Reviewers are counted per source
// only: each hub tags under its own key, so tags of two sources cannot be
// compared (PAY-V4).

// Source is one origin's reviews of an agent.
type Source struct {
	// Hub is the peer hub that collected them; absent for this hub's own.
	Hub     string  `json:"hub,omitempty"`
	Reviews int     `json:"reviews"`
	Avg     float64 `json:"avg"`
	// Reviewers is how many distinct (tag_key_id, tag) the reviews carry:
	// the distinct reviewers, as far as the source's key can tell.
	Reviewers int `json:"reviewers"`
}

// Combined is every source pooled.
type Combined struct {
	Reviews int     `json:"reviews"`
	Avg     float64 `json:"avg"`
}

// Reputation is GET /agents/{aid}/reputation (hub-payment-privacy §2.5).
type Reputation struct {
	AID      string   `json:"aid"`
	Local    Source   `json:"local"`
	Peers    []Source `json:"peers"`
	Combined Combined `json:"combined"`
	// Concentration is the largest single source's share of the pooled
	// reviews, 0..1: 0.95 says one source is effectively deciding the
	// rating.
	Concentration float64 `json:"concentration"`
}

// ReputationOf assembles an agent's standing from every source.
func (s *Store) ReputationOf(aid string) (Reputation, error) {
	out := Reputation{AID: aid, Peers: []Source{}}
	var avg sql.NullFloat64
	if err := s.db.QueryRow(
		`SELECT COUNT(*), AVG(rating),
		        (SELECT COUNT(*) FROM (SELECT DISTINCT tag_key_id, tag FROM review WHERE subject_aid=?))
		   FROM review WHERE subject_aid=?`, aid, aid).
		Scan(&out.Local.Reviews, &avg, &out.Local.Reviewers); err != nil {
		return out, err
	}
	out.Local.Avg = round2(avg.Float64)
	rows, err := s.db.Query(
		`SELECT f.peer_aid, COUNT(*), AVG(f.rating),
		        (SELECT COUNT(*) FROM (SELECT DISTINCT tag_key_id, tag FROM fed_review g
		          WHERE g.subject_aid = f.subject_aid AND g.peer_aid = f.peer_aid))
		   FROM fed_review f WHERE f.subject_aid=? GROUP BY f.peer_aid ORDER BY COUNT(*) DESC, f.peer_aid`, aid)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var src Source
		var a sql.NullFloat64
		if err := rows.Scan(&src.Hub, &src.Reviews, &a, &src.Reviewers); err != nil {
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

// hReputation is GET /agents/{aid}/reputation.
func (s *Server) hReputation(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.ReputationOf(r.PathValue("aid"))
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ---- the graph ----

// GraphNode is one node of GET /graph: an agent and how many reviews this
// hub stores of it. There are no edges: an edge was a reviewer, and the hub
// keeps none (hub-payment-privacy PAY-V5).
type GraphNode struct {
	AID         string `json:"aid"`
	Name        string `json:"name"`
	ReviewCount int    `json:"reviewCount"`
}

// GraphNodes is every listed agent, then every other agent reviewed here (one
// that left, or one known from a peer), each with its review count.
func (s *Store) GraphNodes() ([]GraphNode, error) {
	agents, err := s.ListAgents("")
	if err != nil {
		return nil, err
	}
	out := make([]GraphNode, 0, len(agents))
	seen := make(map[string]bool, len(agents))
	for _, a := range agents {
		seen[a.AID] = true
		out = append(out, GraphNode{AID: a.AID, Name: a.Name, ReviewCount: a.ReviewCount})
	}
	rows, err := s.db.Query(`SELECT subject_aid, COUNT(*) FROM review GROUP BY subject_aid ORDER BY subject_aid`)
	if err != nil {
		return nil, err
	}
	var rest []GraphNode
	for rows.Next() {
		var n GraphNode
		if err := rows.Scan(&n.AID, &n.ReviewCount); err != nil {
			rows.Close()
			return nil, err
		}
		if !seen[n.AID] {
			rest = append(rest, n)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, n := range rest {
		n.Name = s.GraphNodeFor(n.AID).Name
		out = append(out, n)
	}
	return out, nil
}

// hGraph is GET /graph: {nodes: [{aid, name, reviewCount}]}.
func (s *Server) hGraph(w http.ResponseWriter, _ *http.Request) {
	nodes, err := s.store.GraphNodes()
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
}
