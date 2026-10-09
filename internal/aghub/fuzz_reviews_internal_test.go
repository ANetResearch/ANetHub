package aghub

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The decoders of reviews v2 at the hub: the POST /reviews body (PAY-V1
// step 3) and an entry of a peer's review stream (PAY-V3).

// FuzzReviewUpload decodes fuzzed POST /reviews bodies. Properties: no
// panic; a refusal is bad_request or receipt_not_reviewable, with a
// sentence; a body that decodes holds a receipt and a review in their one
// encoding (each re-encodes to the bytes sent), a 32-byte rsalt, a rating
// 1..5, a comment of at most 280 characters and a subject without U+0000.
func FuzzReviewUpload(f *testing.F) {
	prov, err := NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	req, err := NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	add := func(k *ReviewKit) {
		b, err := json.Marshal(k.Body(f))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	add(NewReviewKitForTest(f, prov, req, "ix-fuzz-1", 5))
	k := NewReviewKitForTest(f, prov, req, "ix-fuzz-2", 6)
	k.Unchecked = true
	add(k)
	k = NewReviewKitForTest(f, prov, req, "ix-fuzz-3", 3)
	k.Review.Comment = "评"
	add(k)
	f.Add([]byte(`{"receipt":"AAAA","review":"AAAA","rsalt":"AAAA"}`))
	f.Add([]byte(`{"receipt":"oQE","review":"","rsalt":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > maxReviewUploadBody {
			body = body[:maxReviewUploadBody]
		}
		up, rf := decodeReviewUpload(body)
		if rf != nil {
			if rf.Reason != wire3.ReasonBadRequest && rf.Reason != wire3.ReasonReceiptNotReviewable {
				t.Fatalf("refused with %s", rf.Reason)
			}
			if rf.Reason == wire3.ReasonBadRequest && rf.Error == "" {
				t.Fatal("a bad_request without a sentence")
			}
			return
		}
		rc, err := up.receipt.Marshal()
		if err != nil || !bytes.Equal(rc, up.receiptRaw) {
			t.Fatalf("an accepted receipt is not in its one encoding (%v)", err)
		}
		rv, err := up.review.Marshal()
		if err != nil || !bytes.Equal(rv, up.reviewRaw) {
			t.Fatalf("an accepted review is not in its one encoding (%v)", err)
		}
		if len(up.rsalt) != evidence.RSaltSize || len(up.rc.IXCommit) != evidence.CommitSize ||
			len(up.rc.ReviewKey) != evidence.ReviewKeySize {
			t.Fatalf("sizes: rsalt %d, ix_commit %d, review_key %d", len(up.rsalt), len(up.rc.IXCommit), len(up.rc.ReviewKey))
		}
		if up.rv.Rating < 1 || up.rv.Rating > 5 || utf8.RuneCountInString(up.rv.Comment) > evidence.MaxCommentChars ||
			bytes.IndexByte([]byte(up.rv.Subject), 0) >= 0 || up.rv.Subject == "" {
			t.Fatalf("accepted %+v", up.rv)
		}
	})
}

// FuzzAdmitFedReview admits fuzzed review stream entries, starting from
// genuine ones, from a peer whose key history this hub holds. Properties:
// no panic; an entry admitted is one whose receipt the provider signed,
// whose review the receipt's review key signed about that receipt and its
// provider, and whose attestation the peer signed about exactly that review;
// the row stored says what the objects say; an interaction is held once.
func FuzzAdmitFedReview(f *testing.F) {
	store, err := Open(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { store.Close() })
	peer, err := hubid.LoadOrIncept(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	prov, err := NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	req, err := NewAgentForTest()
	if err != nil {
		f.Fatal(err)
	}
	today := TodayForTest()
	for i, ix := range []string{"ix-fed-fuzz-1", "ix-fed-fuzz-2"} {
		e := FedEntryForTest(f, peer.Ctrl, NewReviewKitForTest(f, prov, req, ix, uint64(3+i)), today, uint64(i+1))
		b, err := json.Marshal(e)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"format":"review/2","receipt":"AAAA","review":"AAAA","attestation":"AAAA","provider_kel":"AAAA","fed_seq":1}`))
	f.Add([]byte(`{"format":"review/1"}`))
	d := FedDirectory{S: store, PeerKEL: func(string) ([]identity.SignedEvent, error) { return peer.Ctrl.KEL(), nil }}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			raw = raw[:64<<10]
		}
		if err := d.AdmitFedReview(peer.AID, raw); err != nil {
			return
		}
		var e FedReviewEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("an entry that is not JSON was admitted: %v", err)
		}
		dec := func(s string) []byte {
			b, err := wire3.DecodeB64URL("", s)
			if err != nil {
				t.Fatalf("an entry with a value that is not base64url was admitted: %v", err)
			}
			return b
		}
		rw, err := evidence.UnmarshalReceiptWire(dec(e.Receipt))
		if err != nil {
			t.Fatal(err)
		}
		vw, err := evidence.UnmarshalReviewWire(dec(e.Review))
		if err != nil {
			t.Fatal(err)
		}
		aw, err := evidence.UnmarshalReviewAttWire(dec(e.Attestation))
		if err != nil {
			t.Fatal(err)
		}
		rc, rv, err := evidence.CheckV2(rw, vw, prov.KEL())
		if err != nil {
			t.Fatalf("an entry that does not interlock under the provider's history was admitted: %v", err)
		}
		ab, err := aw.Open()
		if err != nil {
			t.Fatal(err)
		}
		at, _ := evidence.DayStart(ab.Day)
		if _, err := aw.Verify(peer.Ctrl.KEL(), at); err != nil || ab.Hub != peer.AID {
			t.Fatalf("an entry whose attestation is not the peer's was admitted: %v", err)
		}
		reviewCID, _ := vw.CID()
		receiptCID, _ := rw.CID()
		if ab.ReviewCID != reviewCID || ab.ReceiptCID != receiptCID || ab.Subject != rv.Subject {
			t.Fatal("an attestation of another review was admitted")
		}
		var (
			n               int
			subject, peerAt string
			rating          uint64
			tag             []byte
		)
		if err := store.db.QueryRow(`SELECT COUNT(*), subject_aid, peer_aid, rating, tag FROM fed_review WHERE ix_commit=?`,
			rc.IXCommit).Scan(&n, &subject, &peerAt, &rating, &tag); err != nil || n != 1 {
			t.Fatalf("the admitted review is held %d times (%v)", n, err)
		}
		if subject != rv.Subject || peerAt != peer.AID || rating != rv.Rating || !bytes.Equal(tag, ab.Tag) {
			t.Fatalf("stored %s %s %d, the objects say %s %s %d", subject, peerAt, rating, rv.Subject, peer.AID, rv.Rating)
		}
	})
}
