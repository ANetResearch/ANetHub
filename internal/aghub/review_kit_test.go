package aghub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// ReviewKit is one task's evidence v2 as its requester holds it once the
// task is done (core §2.9): the provider's receipt and the requester's review
// of it, before they are signed, with the requester's secrets for the task
// (the interaction id and nonce behind ix_commit, the salt behind
// requester_commit, the one-time review key). A test changes the bodies,
// then signs them with Wires or builds the upload with Body.
type ReviewKit struct {
	Provider, Requester *identity.Controller
	IX, Nonce           string
	RSalt               []byte
	ReviewKey           ed25519.PrivateKey
	Receipt             evidence.ReceiptBody
	Review              evidence.ReviewBody
	// ReviewSignedBy, when set, signs the review instead of ReviewKey.
	ReviewSignedBy ed25519.PrivateKey
	// Unchecked encodes and signs the review body as it is, without the
	// checks evidence.ReviewBody.Marshal makes (a rating of 6, a comment of
	// 281 characters): what a broken or hostile client could send.
	Unchecked bool
	// RawReceipt, RawReview and RawProviderKEL, when set, are the bytes
	// Wires and FedEntryForTest use as they are (KitFromEntryForTest).
	RawReceipt, RawReview, RawProviderKEL []byte
}

// KitFromEntryForTest is a kit of the receipt and the review a stream entry
// carries, as they are, for attesting them again.
func KitFromEntryForTest(t testing.TB, e FedReviewEntry) *ReviewKit {
	t.Helper()
	dec := func(m, s string) []byte {
		b, err := wire3.DecodeB64URL(m, s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return &ReviewKit{RawReceipt: dec("receipt", e.Receipt), RawReview: dec("review", e.Review),
		RawProviderKEL: dec("provider_kel", e.ProviderKEL)}
}

// TodayForTest is today's UTC day number.
func TodayForTest() uint64 { return reviewDay(time.Now()) }

// NewReviewKitForTest is a review by req, rating rating, of a task prov
// completed today, written today.
func NewReviewKitForTest(t testing.TB, prov, req *identity.Controller, ix string, rating uint64) *ReviewKit {
	t.Helper()
	k := &ReviewKit{Provider: prov, Requester: req, IX: ix, Nonce: "nonce-" + ix, RSalt: make([]byte, evidence.RSaltSize)}
	if _, err := rand.Read(k.RSalt); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k.ReviewKey = priv
	ixCommit, err := evidence.IXCommit(k.IX, k.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	reqCommit, err := evidence.RequesterCommit(req.AID(), k.RSalt)
	if err != nil {
		t.Fatal(err)
	}
	reqCID, _ := anetcid.Sum([]byte("the request of " + ix))
	resCID, _ := anetcid.Sum([]byte("the result of " + ix))
	today := TodayForTest()
	k.Receipt = evidence.ReceiptBody{IXCommit: ixCommit, RequesterCommit: reqCommit, ReviewKey: pub,
		Provider: prov.AID(), RequestCID: reqCID, ResultCID: resCID, CompletedDay: today}
	k.Review = evidence.ReviewBody{Subject: prov.AID(), Rating: rating, CreatedDay: today}
	return k
}

// Wires signs the receipt (as the provider) and the review (with the review
// key; ReceiptCID, when empty, is the receipt's) and returns their bytes.
func (k *ReviewKit) Wires(t testing.TB) (receipt, review []byte) {
	t.Helper()
	if k.RawReceipt != nil {
		return k.RawReceipt, k.RawReview
	}
	rw, err := k.Receipt.Sign(k.Provider)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err = rw.Marshal(); err != nil {
		t.Fatal(err)
	}
	body := k.Review
	if body.ReceiptCID == "" {
		if body.ReceiptCID, err = rw.CID(); err != nil {
			t.Fatal(err)
		}
	}
	key := k.ReviewKey
	if k.ReviewSignedBy != nil {
		key = k.ReviewSignedBy
	}
	if k.Unchecked {
		body.Type = evidence.ReviewType
		raw, err := coredet.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		w := evidence.ReviewWire{Body: raw, Pub: key.Public().(ed25519.PublicKey), Sig: ed25519.Sign(key, raw)}
		if review, err = coredet.Marshal(w); err != nil {
			t.Fatal(err)
		}
		return receipt, review
	}
	vw, err := body.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if review, err = vw.Marshal(); err != nil {
		t.Fatal(err)
	}
	return receipt, review
}

// FedEntryForTest is k's review as the hub peer streams it
// (/fed/v3/reviews): the two objects, the provider's key history and peer's
// attestation of the review, signed by peer, with a tag under a key of its
// own (tagKeyID 1) and stored on day.
func FedEntryForTest(t testing.TB, peer identity.Signer, k *ReviewKit, day, fedSeq uint64) FedReviewEntry {
	t.Helper()
	receipt, review := k.Wires(t)
	reviewer := "a-reviewer-the-peer-knows"
	if k.Requester != nil {
		reviewer = k.Requester.AID()
	}
	kel := k.RawProviderKEL
	if kel == nil {
		var err error
		if kel, err = identity.MarshalKEL(k.Provider.KEL()); err != nil {
			t.Fatal(err)
		}
	}
	e, err := FedEntryOfForTest(peer, receipt, review, kel, reviewer, day, fedSeq)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// FedEntryOfForTest is FedEntryForTest of the bytes as they are: peer
// attests whatever it was given, as a peer that lies would. It fails only
// when the bytes do not decode far enough to name a review.
func FedEntryOfForTest(peer identity.Signer, receipt, review, providerKEL []byte, reviewer string, day, fedSeq uint64) (FedReviewEntry, error) {
	// Read without the decoders' checks: an Unchecked kit's review is
	// attested as a hostile peer would attest it.
	var rw evidence.ReceiptWire
	var vw evidence.ReviewWire
	var vb evidence.ReviewBody
	if err := coredet.Unmarshal(receipt, &rw); err != nil {
		return FedReviewEntry{}, err
	}
	if err := coredet.Unmarshal(review, &vw); err != nil {
		return FedReviewEntry{}, err
	}
	if err := coredet.Unmarshal(vw.Body, &vb); err != nil {
		return FedReviewEntry{}, err
	}
	receiptCID, err := anetcid.Sum(rw.Body)
	if err != nil {
		return FedReviewEntry{}, err
	}
	reviewCID, err := anetcid.Sum(vw.Body)
	if err != nil {
		return FedReviewEntry{}, err
	}
	tag, err := reviewTag(bytes.Repeat([]byte{0x7a}, evidence.TagKeySize), reviewer, vb.Subject)
	if err != nil {
		return FedReviewEntry{}, err
	}
	att, err := (&evidence.ReviewAttBody{ReviewCID: reviewCID, ReceiptCID: receiptCID, Subject: vb.Subject,
		Tag: tag, TagKeyID: 1, Day: day}).Sign(peer)
	if err != nil {
		return FedReviewEntry{}, err
	}
	attRaw, err := att.Marshal()
	if err != nil {
		return FedReviewEntry{}, err
	}
	return FedReviewEntry{Format: FormatReviewV2, Receipt: wire3.EncodeB64URL(receipt),
		Review: wire3.EncodeB64URL(review), Attestation: wire3.EncodeB64URL(attRaw),
		ProviderKEL: wire3.EncodeB64URL(providerKEL), FedSeq: fedSeq}, nil
}

// Body is the POST /reviews body of the kit.
func (k *ReviewKit) Body(t testing.TB) map[string]string {
	t.Helper()
	receipt, review := k.Wires(t)
	return map[string]string{
		"receipt": wire3.EncodeB64URL(receipt),
		"review":  wire3.EncodeB64URL(review),
		"rsalt":   wire3.EncodeB64URL(k.RSalt),
	}
}

// IXCommit is the interaction's commitment, the review's key in the store.
func (k *ReviewKit) IXCommit() []byte { return k.Receipt.IXCommit }

// ReviewTagForTest is the hub's review tag (L31) under key.
func ReviewTagForTest(key []byte, reviewer, subject string) ([]byte, error) {
	return reviewTag(key, reviewer, subject)
}

// ReviewTagKeyForTest is the store's review tag key and its id.
func (s *Store) ReviewTagKeyForTest() ([]byte, uint64, error) { return s.reviewTagKey() }

// RegenerateReviewTagKeyForTest is the emergency rotation's step for the
// key, on an open store.
func (s *Store) RegenerateReviewTagKeyForTest() (uint64, error) { return s.regenerateTagKey() }
