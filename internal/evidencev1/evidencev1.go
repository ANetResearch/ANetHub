// Package evidencev1 is the 0.2 evidence pair — the provider's Receipt and the requester's Review
// — and their interlock, kept in the hub while its review upload, reputation and storage still
// read them. ANetCore 0.16 replaced them with evidence v2 (receipt and review commitments, the
// hub's attestation); the hub moves to those, and this package goes, with the review v2 work.
//
// v030-todo(PAY-6): the hub stores and serves evidence v2 (ANetCore evidence) and this package is
// deleted.
package evidencev1

import (
	"errors"
	"fmt"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// RatingMin/RatingMax bound a review score (inclusive).
const (
	RatingMin = 1
	RatingMax = 5
)

// Receipt is the provider-signed completion proof for one delegated interaction.
type Receipt struct {
	InteractionID string `cbor:"1,keyasint"`
	RequesterAID  string `cbor:"2,keyasint"`
	ProviderAID   string `cbor:"3,keyasint"`
	RequestCID    string `cbor:"4,keyasint"`
	ResultCID     string `cbor:"5,keyasint"`
	CompletedAt   uint64 `cbor:"6,keyasint"` // unix millis
	// Envelope is the detached provider signature. cbor:"-" keeps it out of the signed preimage; it
	// rides beside the object (like tsir.TaskDoc.Envelope).
	Envelope *aobj.Envelope `cbor:"-"`
}

type receiptPreimage struct {
	InteractionID string `cbor:"1,keyasint"`
	RequesterAID  string `cbor:"2,keyasint"`
	ProviderAID   string `cbor:"3,keyasint"`
	RequestCID    string `cbor:"4,keyasint"`
	ResultCID     string `cbor:"5,keyasint"`
	CompletedAt   uint64 `cbor:"6,keyasint"`
}

// CanonicalPreimage returns the CoreDet-CBOR signing/CID preimage (envelope excluded).
func (r *Receipt) CanonicalPreimage() ([]byte, error) {
	return coredet.Marshal(receiptPreimage{
		InteractionID: r.InteractionID, RequesterAID: r.RequesterAID, ProviderAID: r.ProviderAID,
		RequestCID: r.RequestCID, ResultCID: r.ResultCID, CompletedAt: r.CompletedAt,
	})
}

// CID is the content identifier over the canonical preimage (what a Review's ReceiptCID references).
func (r *Receipt) CID() (string, error) {
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return "", err
	}
	return anetcid.Sum(pre)
}

// Sign attaches the provider's detached signature. The signer MUST be the ProviderAID.
func (r *Receipt) Sign(c *identity.Controller) error {
	if r.ProviderAID == "" {
		r.ProviderAID = c.AID()
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	r.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the provider signature against the provider's KEL. It also binds the envelope signer to
// ProviderAID so a receipt cannot be attributed to a provider that did not sign it.
func (r *Receipt) Verify(kel []identity.SignedEvent, msgTime uint64) error {
	if r.Envelope == nil {
		return errors.New("evidence: unsigned receipt")
	}
	if err := r.Envelope.Validate(); err != nil {
		return err
	}
	if r.Envelope.SignerAID != r.ProviderAID {
		return errors.New("evidence: receipt signer is not the provider")
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, r.Envelope.SignerAID, r.Envelope.KeyStateSeq, msgTime, pre, r.Envelope.Sig)
}

// Marshal/Unmarshal serialize a receipt WITH its detached envelope for transport/storage (the deliverable
// carrier). The envelope is CBOR key 7 in the transport wrapper, kept out of the signed preimage.
type receiptWire struct {
	Body     receiptPreimage `cbor:"1,keyasint"`
	Envelope *aobj.Envelope  `cbor:"2,keyasint"`
}

// Marshal encodes the receipt + envelope for the wire.
func (r *Receipt) Marshal() ([]byte, error) {
	return coredet.Marshal(receiptWire{
		Body: receiptPreimage{
			InteractionID: r.InteractionID, RequesterAID: r.RequesterAID, ProviderAID: r.ProviderAID,
			RequestCID: r.RequestCID, ResultCID: r.ResultCID, CompletedAt: r.CompletedAt,
		},
		Envelope: r.Envelope,
	})
}

// UnmarshalReceipt decodes a wire receipt (body + detached envelope).
func UnmarshalReceipt(b []byte) (*Receipt, error) {
	var w receiptWire
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &Receipt{
		InteractionID: w.Body.InteractionID, RequesterAID: w.Body.RequesterAID, ProviderAID: w.Body.ProviderAID,
		RequestCID: w.Body.RequestCID, ResultCID: w.Body.ResultCID, CompletedAt: w.Body.CompletedAt,
		Envelope: w.Envelope,
	}, nil
}

// Review is the requester-signed rating of a provider for one interaction.
type Review struct {
	InteractionID string         `cbor:"1,keyasint"`
	SubjectAID    string         `cbor:"2,keyasint"` // the provider being rated
	ReviewerAID   string         `cbor:"3,keyasint"` // the requester
	Rating        int            `cbor:"4,keyasint"` // RatingMin..RatingMax
	Comment       string         `cbor:"5,keyasint,omitempty"`
	ReceiptCID    string         `cbor:"6,keyasint"` // CID of the receipt this review is anchored to
	CreatedAt     uint64         `cbor:"7,keyasint"` // unix millis
	Envelope      *aobj.Envelope `cbor:"-"`
}

type reviewPreimage struct {
	InteractionID string `cbor:"1,keyasint"`
	SubjectAID    string `cbor:"2,keyasint"`
	ReviewerAID   string `cbor:"3,keyasint"`
	Rating        int    `cbor:"4,keyasint"`
	Comment       string `cbor:"5,keyasint,omitempty"`
	ReceiptCID    string `cbor:"6,keyasint"`
	CreatedAt     uint64 `cbor:"7,keyasint"`
}

func (r *Review) canonicalStruct() reviewPreimage {
	return reviewPreimage{
		InteractionID: r.InteractionID, SubjectAID: r.SubjectAID, ReviewerAID: r.ReviewerAID,
		Rating: r.Rating, Comment: r.Comment, ReceiptCID: r.ReceiptCID, CreatedAt: r.CreatedAt,
	}
}

// CanonicalPreimage returns the CoreDet-CBOR signing preimage (envelope excluded).
func (r *Review) CanonicalPreimage() ([]byte, error) { return coredet.Marshal(r.canonicalStruct()) }

// ValidRating reports whether Rating is in [RatingMin, RatingMax].
func (r *Review) ValidRating() bool { return r.Rating >= RatingMin && r.Rating <= RatingMax }

// Sign attaches the requester's detached signature. The signer MUST be the ReviewerAID.
func (r *Review) Sign(c *identity.Controller) error {
	if r.ReviewerAID == "" {
		r.ReviewerAID = c.AID()
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	sig, seq := c.Sign(pre)
	r.Envelope = &aobj.Envelope{SignerAID: c.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}
	return nil
}

// Verify checks the requester signature against the reviewer's KEL and binds the signer to ReviewerAID.
func (r *Review) Verify(kel []identity.SignedEvent, msgTime uint64) error {
	if r.Envelope == nil {
		return errors.New("evidence: unsigned review")
	}
	if err := r.Envelope.Validate(); err != nil {
		return err
	}
	if r.Envelope.SignerAID != r.ReviewerAID {
		return errors.New("evidence: review signer is not the reviewer")
	}
	pre, err := r.CanonicalPreimage()
	if err != nil {
		return err
	}
	return identity.VerifyObject(kel, r.Envelope.SignerAID, r.Envelope.KeyStateSeq, msgTime, pre, r.Envelope.Sig)
}

type reviewWire struct {
	Body     reviewPreimage `cbor:"1,keyasint"`
	Envelope *aobj.Envelope `cbor:"2,keyasint"`
}

// Marshal encodes the review + envelope for the wire.
func (r *Review) Marshal() ([]byte, error) {
	return coredet.Marshal(reviewWire{Body: r.canonicalStruct(), Envelope: r.Envelope})
}

// UnmarshalReview decodes a wire review (body + detached envelope).
func UnmarshalReview(b []byte) (*Review, error) {
	var w reviewWire
	if err := coredet.Unmarshal(b, &w); err != nil {
		return nil, err
	}
	return &Review{
		InteractionID: w.Body.InteractionID, SubjectAID: w.Body.SubjectAID, ReviewerAID: w.Body.ReviewerAID,
		Rating: w.Body.Rating, Comment: w.Body.Comment, ReceiptCID: w.Body.ReceiptCID, CreatedAt: w.Body.CreatedAt,
		Envelope: w.Envelope,
	}, nil
}

// VerifyInterlock checks that a receipt and a review are two halves of one
// real interaction.
//
// This is the arithmetic behind "the Hub is a relay — it cannot fake a
// single rating", and it lived inside the Hub, in a package Go forbids
// anyone else from importing. So the claim was true of the Hub's own code
// and unavailable to the people it is addressed to: a rating is worth
// something precisely because a stranger can check it, and no stranger
// could.
//
// Ten checks, and every one of them is a way to manufacture a rating that
// would otherwise pass:
//
//	rating in range                 — a 9-star review
//	same interaction id             — a review of a different job
//	reviewer is the requester       — rating work you did not commission
//	subject is the provider         — praising someone who was not there
//	review anchored to this receipt — a real receipt paired with a review
//	                                  that names a different one
//	request bytes hash to RequestCID  — rating a job that was not asked
//	deliverable hashes to ResultCID   — rating work that was not delivered
//	receipt signed by the provider    — a receipt the provider never issued
//	review signed by the reviewer     — a review the requester never wrote
//	both signatures under a live key   — a key retired before it signed
//
// What it deliberately does NOT check is anything requiring state: that
// the parties are registered somewhere, or that this interaction has not
// already been rated. Those are policy a particular Hub enforces against
// its own store, not facts about the objects. Keeping them out is what
// lets an auditor with nothing but files reach the same verdict.
//
// requestDoc and deliverable are the interaction's actual bytes. Pass nil
// for either to skip that content binding — an auditor who was given only
// the signed objects can still confirm everything else, and saying so is
// better than pretending the content was checked.
func VerifyInterlock(rc *Receipt, rv *Review, requestDoc, deliverable []byte,
	providerKEL, reviewerKEL []identity.SignedEvent) error {
	if rc == nil || rv == nil {
		return errors.New("evidence: interlock needs both a receipt and a review")
	}
	if !rv.ValidRating() {
		return fmt.Errorf("evidence: rating %d out of range %d..%d", rv.Rating, RatingMin, RatingMax)
	}

	// The two objects must describe the same interaction and agree on who
	// was involved.
	if rc.InteractionID != rv.InteractionID {
		return fmt.Errorf("evidence: receipt is for interaction %s, review for %s",
			rc.InteractionID, rv.InteractionID)
	}
	if rv.ReviewerAID != rc.RequesterAID {
		return errors.New("evidence: the reviewer is not the interaction's requester")
	}
	if rv.SubjectAID != rc.ProviderAID {
		return errors.New("evidence: the review rates someone other than the provider")
	}

	// And the review must be anchored to THIS receipt, not merely to one.
	receiptCID, err := rc.CID()
	if err != nil {
		return err
	}
	if rv.ReceiptCID != receiptCID {
		return fmt.Errorf("evidence: review references receipt %s, not %s", rv.ReceiptCID, receiptCID)
	}

	// Content binding: what is shown must be what was signed for.
	if requestDoc != nil {
		cid, err := anetcid.Sum(requestDoc)
		if err != nil {
			return err
		}
		if cid != rc.RequestCID {
			return fmt.Errorf("evidence: request bytes hash to %s, receipt says %s", cid, rc.RequestCID)
		}
	}
	if deliverable != nil {
		cid, err := anetcid.Sum(deliverable)
		if err != nil {
			return err
		}
		if cid != rc.ResultCID {
			return fmt.Errorf("evidence: deliverable hashes to %s, receipt says %s", cid, rc.ResultCID)
		}
	}

	// Signatures last: they are the expensive part, and an object that
	// fails the cheap structural checks is not worth a curve operation.
	if err := rc.Verify(providerKEL, rc.CompletedAt); err != nil {
		return fmt.Errorf("evidence: receipt signature invalid: %w", err)
	}
	if err := rv.Verify(reviewerKEL, rv.CreatedAt); err != nil {
		return fmt.Errorf("evidence: review signature invalid: %w", err)
	}
	return nil
}
