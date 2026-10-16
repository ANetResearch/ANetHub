package aghub_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// Reviews v2 at the hub (hub-payment-privacy §2.5, §4.2.3; core §2.9,
// L27–L33).

// reviewHub is a hub with a provider, a requester, a registered agent that
// is nobody's requester (carol) and one on probation (probie), and an agent
// registered nowhere (stranger).
type reviewHub struct {
	srv                      *httptest.Server
	store                    *aghub.Store
	prov, req, carol, probie *identity.Controller
	stranger                 *identity.Controller
}

// newReviewHub is a reviewHub and its upload: k's body (or body) signed as
// as (or k's requester).
func newReviewHub(t *testing.T) (*reviewHub, func(k *aghub.ReviewKit, as *identity.Controller, body map[string]string) (int, []byte)) {
	t.Helper()
	srv, store := newHubWithStore(t)
	h := &reviewHub{srv: srv, store: store}
	h.prov, h.req = twoAgents(t)
	h.carol, h.probie = twoAgents(t)
	h.stranger, _ = aghub.NewAgentForTest()
	register(t, srv, h.prov, "Provider", []string{"work.do"})
	register(t, srv, h.req, "Requester", nil)
	register(t, srv, h.carol, "Carol", nil)
	register(t, srv, h.probie, "Probie", nil)
	if _, err := store.DBForTest().Exec(`UPDATE agent SET admitted_via='open', probation_until=?, trial='pending' WHERE aid=?`,
		time.Now().Add(time.Hour).UnixMilli(), h.probie.AID()); err != nil {
		t.Fatal(err)
	}
	upload := func(k *aghub.ReviewKit, as *identity.Controller, body map[string]string) (int, []byte) {
		t.Helper()
		if as == nil {
			as = k.Requester
		}
		if body == nil {
			body = k.Body(t)
		}
		return signedDo(t, srv, as, relayauth.ActionReview, http.MethodPost, "/reviews", body)
	}
	return h, upload
}

// rewire re-encodes a wire object with change applied to its decoded form,
// without signing anything again: tampering, as a relay or a client could.
func rewire[W any](t *testing.T, raw []byte, change func(w *W)) []byte {
	t.Helper()
	var w W
	if err := coredet.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	change(&w)
	out, err := coredet.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// receiptWith signs a receipt body as it is, without the checks
// ReceiptBody.Sign makes (another type tag, a missing commitment).
func receiptWith(t *testing.T, prov *identity.Controller, body evidence.ReceiptBody) []byte {
	t.Helper()
	raw, err := coredet.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sig, seq := prov.Sign(raw)
	out, err := coredet.Marshal(evidence.ReceiptWire{Body: raw,
		Env: &aobj.Envelope{SignerAID: prov.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestReviewUploadFollowsPAYV1: each step of PAY-V1 refuses with its code,
// nothing refused is stored, and an upload wrong in several ways gets the
// code of the first step it fails (2026-10-04: decoding comes before the
// signatures; steps 4 and 5 are both receipt_not_reviewable).
func TestReviewUploadFollowsPAYV1(t *testing.T) {
	h, upload := newReviewHub(t)
	today := aghub.TodayForTest()
	kit := func(name string, rating uint64) *aghub.ReviewKit {
		return aghub.NewReviewKitForTest(t, h.prov, h.req, "ix-v1-"+name, rating)
	}
	type tc struct {
		name   string
		kit    *aghub.ReviewKit
		as     *identity.Controller
		body   map[string]string
		status int
		reason string
	}
	var cases []tc
	add := func(c tc) { cases = append(cases, c) }

	// step 1
	k := kit("unregistered", 5)
	add(tc{"signed by an agent not registered here", k, h.stranger, nil, 401, "unauthorized"})
	// step 2
	add(tc{"on probation", aghub.NewReviewKitForTest(t, h.prov, h.probie, "ix-v1-probie", 5), h.probie, nil, 403, "probation"})
	add(tc{"on probation, with a body that is no review", aghub.NewReviewKitForTest(t, h.prov, h.probie, "ix-v1-probie2", 5),
		h.probie, map[string]string{"receipt": "AAAA"}, 403, "probation"})
	// step 3, bad_request
	k = kit("member", 5)
	body := k.Body(t)
	body["request_doc"] = "AAAA"
	add(tc{"an unknown member", k, nil, body, 400, "bad_request"})
	k = kit("no-rsalt", 5)
	body = k.Body(t)
	delete(body, "rsalt")
	add(tc{"no rsalt", k, nil, body, 400, "bad_request"})
	k = kit("short-rsalt", 5)
	body = k.Body(t)
	body["rsalt"] = b64u(k.RSalt[:31])
	add(tc{"an rsalt of 31 bytes", k, nil, body, 400, "bad_request"})
	k = kit("std-b64", 5)
	body = k.Body(t)
	rcB, _ := k.Wires(t)
	body["receipt"] = base64.StdEncoding.EncodeToString(rcB) + "=="
	add(tc{"the receipt in standard base64", k, nil, body, 400, "bad_request"})
	k = kit("empty", 5)
	body = k.Body(t)
	body["review"] = ""
	add(tc{"an empty review", k, nil, body, 400, "bad_request"})
	k = kit("not-cbor", 5)
	body = k.Body(t)
	body["receipt"] = b64u([]byte{0xa2, 0x01})
	add(tc{"a receipt that is not CBOR", k, nil, body, 400, "bad_request"})
	k = kit("trailing", 5)
	body = k.Body(t)
	rcB, _ = k.Wires(t)
	body["receipt"] = b64u(append(append([]byte(nil), rcB...), 0x00))
	add(tc{"a receipt with a byte after it", k, nil, body, 400, "bad_request"})
	k = kit("rating6", 6)
	k.Unchecked = true
	add(tc{"a rating of 6", k, nil, nil, 400, "bad_request"})
	k = kit("rating0", 0)
	k.Unchecked = true
	add(tc{"a rating of 0", k, nil, nil, 400, "bad_request"})
	k = kit("comment281", 5)
	k.Review.Comment, k.Unchecked = strings.Repeat("评", evidence.MaxCommentChars+1), true
	add(tc{"a comment of 281 characters", k, nil, nil, 400, "bad_request"})
	k = kit("subject-nul", 5)
	k.Review.Subject, k.Unchecked = h.prov.AID()+"\x00", true
	add(tc{"a subject holding U+0000", k, nil, nil, 400, "bad_request"})
	// step 3, receipt_not_reviewable
	k = kit("receipt-type", 5)
	body = k.Body(t)
	rb := k.Receipt
	rb.Type = "anet.receipt/1"
	body["receipt"] = b64u(receiptWith(t, h.prov, rb))
	add(tc{"a receipt of another type", k, nil, body, 400, "receipt_not_reviewable"})
	k = kit("no-review-key", 5)
	body = k.Body(t)
	rb = k.Receipt
	rb.Type, rb.ReviewKey = evidence.ReceiptType, nil
	body["receipt"] = b64u(receiptWith(t, h.prov, rb))
	add(tc{"a receipt without its review key", k, nil, body, 400, "receipt_not_reviewable"})
	k = kit("v02", 5)
	body = k.Body(t)
	v02, _ := coredet.Marshal(map[int]any{1: map[int]any{1: "ix", 2: h.req.AID(), 3: h.prov.AID()}, 2: map[int]any{1: h.prov.AID()}})
	body["receipt"] = b64u(v02)
	add(tc{"a v0.2 receipt", k, nil, body, 400, "receipt_not_reviewable"})
	k = kit("review-as-receipt", 5)
	body = k.Body(t)
	body["receipt"] = body["review"]
	add(tc{"the review sent as the receipt", k, nil, body, 400, "receipt_not_reviewable"})
	// step 4
	add(tc{"a provider this hub knows nothing of", aghub.NewReviewKitForTest(t, h.stranger, h.req, "ix-v1-unknown-prov", 5), nil, nil, 400, "receipt_not_reviewable"})
	k = kit("receipt-sig", 5)
	body = k.Body(t)
	rcB, _ = k.Wires(t)
	body["receipt"] = b64u(rewire(t, rcB, func(w *evidence.ReceiptWire) { w.Env.Sig[0] ^= 1 }))
	add(tc{"the provider's signature broken", k, nil, body, 400, "receipt_not_reviewable"})
	k = kit("receipt-signer", 5)
	body = k.Body(t)
	rcB, _ = k.Wires(t)
	body["receipt"] = b64u(rewire(t, rcB, func(w *evidence.ReceiptWire) { w.Env.SignerAID = h.carol.AID() }))
	add(tc{"the receipt's envelope naming another signer", k, nil, body, 400, "receipt_not_reviewable"})
	// step 5
	k = kit("review-key", 5)
	_, k.ReviewSignedBy, _ = ed25519.GenerateKey(nil)
	add(tc{"a review signed by another key", k, nil, nil, 400, "receipt_not_reviewable"})
	k = kit("review-sig", 5)
	body = k.Body(t)
	_, rvB := k.Wires(t)
	body["review"] = b64u(rewire(t, rvB, func(w *evidence.ReviewWire) { w.Sig[5] ^= 1 }))
	add(tc{"the review's signature broken", k, nil, body, 400, "receipt_not_reviewable"})
	k = kit("other-receipt", 5)
	k.Review.ReceiptCID, _ = anetcid.Sum([]byte("another receipt"))
	add(tc{"a review naming another receipt", k, nil, nil, 400, "receipt_not_reviewable"})
	k = kit("subject", 5)
	k.Review.Subject = h.carol.AID()
	add(tc{"a review rating somebody other than the provider", k, nil, nil, 400, "receipt_not_reviewable"})
	// step 6
	add(tc{"uploaded by somebody other than the requester", kit("carol", 5), h.carol, nil, 400, "requester_commit_mismatch"})
	k = kit("rsalt", 5)
	body = k.Body(t)
	body["rsalt"] = b64u(bytes.Repeat([]byte{9}, 32))
	add(tc{"another rsalt", k, nil, body, 400, "requester_commit_mismatch"})
	// step 7
	k = kit("before", 5)
	k.Review.CreatedDay = k.Receipt.CompletedDay - 1
	add(tc{"created the day before the task ended", k, nil, nil, 400, "review_window_closed"})
	k = kit("day31", 5)
	k.Receipt.CompletedDay = today - aghub.ReviewWindowDays - 1
	add(tc{"created 31 days after the task", k, nil, nil, 400, "review_window_closed"})
	k = kit("future", 5)
	k.Receipt.CompletedDay, k.Review.CreatedDay = today+2, today+2
	add(tc{"created the day after tomorrow", k, nil, nil, 400, "review_window_closed"})
	// the first failing step answers
	k = aghub.NewReviewKitForTest(t, h.prov, h.probie, "ix-v1-probie3", 6)
	k.Unchecked = true
	add(tc{"probation before everything else", k, h.probie, nil, 403, "probation"})
	k = kit("rating-carol", 6)
	k.Unchecked = true
	add(tc{"a rating of 6, uploaded by somebody else (3 before 6)", k, h.carol, nil, 400, "bad_request"})
	add(tc{"an unknown provider, uploaded by somebody else (4 before 6)",
		aghub.NewReviewKitForTest(t, h.stranger, h.req, "ix-v1-unknown-carol", 5), h.carol, nil, 400, "receipt_not_reviewable"})
	k = kit("carol-late", 5)
	k.Receipt.CompletedDay = today - 40
	add(tc{"uploaded by somebody else, out of the window (6 before 7)", k, h.carol, nil, 400, "requester_commit_mismatch"})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, b := upload(c.kit, c.as, c.body)
			if code != c.status || !strings.Contains(string(b), `"reason":"`+c.reason+`"`) {
				t.Fatalf("%d %s, want %d %s", code, b, c.status, c.reason)
			}
			if reviewStored(t, h.store, c.kit) {
				t.Fatal("the refused review was stored")
			}
		})
	}

	t.Run("the window's edges are open", func(t *testing.T) {
		k := kit("edge30", 5)
		k.Receipt.CompletedDay = today - aghub.ReviewWindowDays
		if code, b := upload(k, nil, nil); code != 200 {
			t.Fatalf("created 30 days after the task: %d %s", code, b)
		}
		k = kit("edge-tomorrow", 5)
		k.Review.CreatedDay = today + 1
		if code, b := upload(k, nil, nil); code != 200 {
			t.Fatalf("created tomorrow (a requester ahead of UTC): %d %s", code, b)
		}
	})

	t.Run("an interaction is reviewed once (9)", func(t *testing.T) {
		k := kit("once", 4)
		if code, b := upload(k, nil, nil); code != 200 {
			t.Fatalf("first: %d %s", code, b)
		}
		if code, b := upload(k, nil, nil); code != 409 || !strings.Contains(string(b), `"review_exists"`) {
			t.Fatalf("again: %d %s", code, b)
		}
		// M-PAY-11: a second receipt the provider signed for the same
		// interaction (another result) is the same interaction.
		k2 := kit("once", 2)
		k2.IX, k2.Nonce, k2.RSalt, k2.Receipt.RequesterCommit = k.IX, k.Nonce, k.RSalt, k.Receipt.RequesterCommit
		k2.Receipt.IXCommit = k.Receipt.IXCommit
		k2.Receipt.ResultCID, _ = anetcid.Sum([]byte("a second result"))
		if code, b := upload(k2, nil, nil); code != 409 || !strings.Contains(string(b), `"review_exists"`) {
			t.Fatalf("a second receipt of the same interaction: %d %s", code, b)
		}
		// Out of the window and reviewed already: 7 before 9.
		k3 := kit("once", 4)
		k3.IX, k3.Nonce, k3.RSalt, k3.Receipt.RequesterCommit = k.IX, k.Nonce, k.RSalt, k.Receipt.RequesterCommit
		k3.Receipt.IXCommit = k.Receipt.IXCommit
		k3.Receipt.CompletedDay = today - 45
		if code, b := upload(k3, nil, nil); code != 400 || !strings.Contains(string(b), `"review_window_closed"`) {
			t.Fatalf("reviewed already and out of the window: %d %s", code, b)
		}
	})
}

// The upload body is at most 16 KiB (hub-payment-privacy §0.4, §2.5): one
// byte over is 413 too_large before anything in it is read; at the limit
// the body is read (and this one, carrying a member no upload has, is
// refused for that).
func TestAReviewUploadIsAtMost16KiB(t *testing.T) {
	h, _ := newReviewHub(t)
	srv := h.srv
	k := aghub.NewReviewKitForTest(t, h.prov, h.req, "ix-size", 5)
	sized := func(n int) []byte {
		t.Helper()
		body := k.Body(t)
		body["pad"] = ""
		base, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		body["pad"] = strings.Repeat("A", n-len(base))
		raw, _ := json.Marshal(body)
		if len(raw) != n {
			t.Fatalf("built %d bytes, want %d", len(raw), n)
		}
		return raw
	}
	const limit = 16 << 10
	code, b := signedDo(t, srv, h.req, relayauth.ActionReview, http.MethodPost, "/reviews", sized(limit+1))
	if code != http.StatusRequestEntityTooLarge || !strings.Contains(string(b), `"too_large"`) {
		t.Fatalf("%d bytes: %d %s, want 413 too_large", limit+1, code, b)
	}
	code, b = signedDo(t, srv, h.req, relayauth.ActionReview, http.MethodPost, "/reviews", sized(limit))
	if code != http.StatusBadRequest || !strings.Contains(string(b), `"bad_request"`) || !strings.Contains(string(b), "pad") {
		t.Fatalf("%d bytes: %d %s, want 400 bad_request naming the member", limit, code, b)
	}
	if reviewStored(t, h.store, k) {
		t.Fatal("stored")
	}
}

// PAY-V1 step 4 takes the provider's key history from its account here, a
// peer's card or departed_kel: a provider that left after the task can
// still be reviewed for it.
func TestAProviderThatLeftCanStillBeReviewed(t *testing.T) {
	srv, store := newHubWithStore(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	k := makeEvidence(t, prov, req, "ix-departed", 4, "")
	if _, err := store.Deregister(prov.AID(), aghub.DeregSelf); err != nil {
		t.Fatal(err)
	}
	if code, b := uploadReview(t, srv, k); code != http.StatusOK {
		t.Fatalf("a review of a provider that left: %d %s", code, b)
	}
	if !reviewStored(t, store, k) {
		t.Fatal("not stored")
	}
}

// A receipt is judged by the provider's key history at the start of its own
// day (SI-36): a key the provider retired before then signs nothing for it.
func TestAReceiptSignedWithARetiredKeyIsNotReviewable(t *testing.T) {
	srv, _ := newHubWithStore(t)
	prov, req := twoAgents(t)
	snap, err := prov.Export()
	if err != nil {
		t.Fatal(err)
	}
	if err := identitytest.Rotate(prov, uint64(time.Now().UnixMilli())+5); err != nil {
		t.Fatal(err)
	}
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	old, err := identity.Restore(snap)
	if err != nil {
		t.Fatal(err)
	}
	// Dated tomorrow, after the rotation: the old key was retired before
	// the receipt's day began.
	k := aghub.NewReviewKitForTest(t, old, req, "ix-retired", 5)
	k.Receipt.CompletedDay++
	k.Review.CreatedDay++
	if code, b := uploadReview(t, srv, k); code != 400 || !strings.Contains(string(b), `"receipt_not_reviewable"`) {
		t.Fatalf("a receipt signed with a retired key: %d %s", code, b)
	}
	// Dated today, the day the key was retired: it still signed for today.
	k = aghub.NewReviewKitForTest(t, old, req, "ix-retired-today", 5)
	if code, b := uploadReview(t, srv, k); code != 200 {
		t.Fatalf("a receipt of the day its key was retired: %d %s", code, b)
	}
}

// The attestation is the hub's signed word on what it stored (PAY-V2, L32):
// this review, this receipt, this subject, the reviewer's tag under the
// current key and today; checkable by anyone with the hub's key history.
// The task ended three days ago and the review was written yesterday, so
// the attestation's day and the row's three days cannot stand in for one
// another.
func TestTheAttestationIsTheHubsWordOnWhatItStored(t *testing.T) {
	srv, store := newHubWithStore(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	k := makeEvidence(t, prov, req, "ix-attested", 5, "")
	today := aghub.TodayForTest()
	k.Receipt.CompletedDay, k.Review.CreatedDay = today-3, today-1
	code, b := uploadReview(t, srv, k)
	if code != 200 {
		t.Fatalf("upload: %d %s", code, b)
	}
	var out aghub.UploadReviewResponse
	if err := json.Unmarshal(b, &out); err != nil || out.Status != aghub.ReviewStored {
		t.Fatalf("answer %s (%v)", b, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(out.Attestation)
	if err != nil {
		t.Fatal(err)
	}
	att, err := evidence.UnmarshalReviewAttWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	hub := aghub.HubIdentityForTest(t)
	at, _ := evidence.DayStart(aghub.TodayForTest())
	body, err := att.Verify(hub.Ctrl.KEL(), at)
	if err != nil {
		t.Fatalf("the attestation does not verify under the hub's key history: %v", err)
	}
	rcB, rvB := k.Wires(t)
	rcw, _ := evidence.UnmarshalReceiptWire(rcB)
	rvw, _ := evidence.UnmarshalReviewWire(rvB)
	receiptCID, _ := rcw.CID()
	reviewCID, _ := rvw.CID()
	key, keyID, err := store.ReviewTagKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := aghub.ReviewTagForTest(key, req.AID(), prov.AID())
	if body.ReviewCID != reviewCID || body.ReceiptCID != receiptCID || body.Subject != prov.AID() ||
		!bytes.Equal(body.Tag, tag) || body.TagKeyID != keyID || body.Day != today || body.Hub != hub.AID {
		t.Fatalf("attestation %+v", body)
	}
	// The row says the same, with the receipt's and the review's own days.
	var (
		rowTag                       []byte
		rowKeyID, completed, created uint64
		stored                       uint64
	)
	if err := store.DBForTest().QueryRow(`SELECT tag, tag_key_id, completed_day, created_day, stored_day
		FROM review WHERE ix_commit=?`, k.IXCommit()).Scan(&rowTag, &rowKeyID, &completed, &created, &stored); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rowTag, tag) || rowKeyID != keyID || completed != today-3 || created != today-1 || stored != today {
		t.Fatalf("stored row: tag %x key %d completed %d created %d stored %d (today %d)",
			rowTag, rowKeyID, completed, created, stored, today)
	}
}

// SI-48 at the hub (M-PAY-13, M-PAY-14, M-PAY-40): after a review is stored
// and one learned from a peer, the review tables hold neither reviewer's
// AID, in no form, and no time finer than a day; and no public answer nor
// the review stream names a reviewer or states a millisecond time.
func TestAStoredReviewKeepsNoReviewer(t *testing.T) {
	dir := t.TempDir()
	srv, store, _ := newHubAt(t, dir)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	setVisibility(t, srv, prov, aghub.VisibilityFederated)
	start := time.Now().UnixMilli()
	if code, b := uploadReview(t, srv, makeEvidenceWithComment(t, prov, req, "ix-si48", 5, "", "solid work")); code != 200 {
		t.Fatalf("upload: %d %s", code, b)
	}
	peer := otherHub(t)
	fedReq, _ := aghub.NewAgentForTest()
	fed := aghub.FedEntryForTest(t, peer.Ctrl, makeEvidence(t, prov, fedReq, "ix-si48-peer", 3, ""), aghub.TodayForTest(), 9)
	if err := store.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), fed); err != nil {
		t.Fatal(err)
	}
	end := time.Now().UnixMilli()
	reviewers := []string{req.AID(), fedReq.AID()}

	// Row by row, every value of the review tables.
	timeOfDay := regexp.MustCompile(`\d\d:\d\d(:\d\d)?`)
	for _, tb := range []string{"review", "review_blob", "fed_review"} {
		rows, err := store.DBForTest().Query(`SELECT * FROM ` + tb)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		n := 0
		for rows.Next() {
			n++
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			for i, v := range vals {
				var b []byte
				switch x := v.(type) {
				case int64:
					if x >= 1e12 {
						t.Errorf("%s.%s holds %d, a millisecond time", tb, cols[i], x)
					}
					b = []byte(strconv.FormatInt(x, 10))
				case string:
					b = []byte(x)
				case []byte:
					b = x
				}
				for _, aid := range reviewers {
					if bytes.Contains(b, []byte(aid)) {
						t.Errorf("%s.%s names the reviewer", tb, cols[i])
					}
				}
				if timeOfDay.Match(b) && cols[i] != "comment" && !strings.HasSuffix(cols[i], "_raw") {
					t.Errorf("%s.%s holds a time of day: %q", tb, cols[i], b)
				}
			}
		}
		rows.Close()
		if n == 0 {
			t.Fatalf("%s is empty: nothing was checked", tb)
		}
	}
	// The raw bytes of the review tables and their indexes: a copy of
	// hub.db with every other table emptied and vacuumed holds neither AID.
	others := map[string]bool{}
	rows, err := store.DBForTest().Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		if n != "review" && n != "review_blob" && n != "fed_review" {
			others[n] = true
		}
	}
	rows.Close()
	for _, aid := range reviewers {
		if n := rawScanWithout(t, store.DBForTest(), dir, others, aid); n != 0 {
			t.Errorf("the review tables' bytes hold a reviewer's AID %d time(s)", n)
		}
	}

	// What anyone can read, and what peers read.
	ms := regexp.MustCompile(`\b1\d{12}\b`)
	for _, path := range []string{"/agents/" + prov.AID(), "/agents/" + prov.AID() + "/reputation", "/graph", "/stats",
		"/agents", "/a2a/v1/agents"} {
		code, b := getJSON(t, srv.URL+path)
		if code != 200 {
			t.Fatalf("GET %s: %d", path, code)
		}
		check(t, path, b, reviewers, ms, start, end)
	}
	revs, _, err := store.ReviewsSince(0, 0)
	if err != nil || len(revs) != 1 {
		t.Fatalf("stream: %d %v", len(revs), err)
	}
	stream, _ := json.Marshal(revs)
	check(t, "the review stream", stream, reviewers, ms, start, end)
	for _, e := range revs {
		for _, v := range []string{e.Receipt, e.Review, e.Attestation} {
			raw, _ := base64.RawURLEncoding.DecodeString(v)
			check(t, "an object of the review stream", raw, reviewers, ms, start, end)
		}
	}
}

// check fails t when b names one of aids, or holds a decimal millisecond
// time between start and end.
func check(t *testing.T, what string, b []byte, aids []string, ms *regexp.Regexp, start, end int64) {
	t.Helper()
	for _, aid := range aids {
		if bytes.Contains(b, []byte(aid)) {
			t.Errorf("%s names a reviewer", what)
		}
	}
	for _, m := range ms.FindAll(b, -1) {
		if v, err := strconv.ParseInt(string(m), 10, 64); err == nil && v >= start-1000 && v <= end+1000 {
			t.Errorf("%s states the millisecond time %s", what, m)
		}
	}
}

// Reviewers are counted per source by (tag_key_id, tag) (PAY-V4): one
// reviewer of one subject is one reviewer however many tasks it rates; a new
// tag key starts the count over (hub-payment-privacy §3.3).
func TestReviewersAreCountedByTag(t *testing.T) {
	srv, store := newHubWithStore(t)
	prov, req := twoAgents(t)
	other, _ := aghub.NewAgentForTest()
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	register(t, srv, other, "Other", nil)
	up := func(c *identity.Controller, ix string, rating int) {
		t.Helper()
		if code, b := uploadReview(t, srv, makeEvidence(t, prov, c, ix, rating, "")); code != 200 {
			t.Fatalf("upload %s: %d %s", ix, code, b)
		}
	}
	local := func() aghub.Source {
		t.Helper()
		rep, err := store.ReputationOf(prov.AID())
		if err != nil {
			t.Fatal(err)
		}
		return rep.Local
	}
	up(req, "ix-count-1", 5)
	up(req, "ix-count-2", 3)
	if l := local(); l.Reviews != 2 || l.Reviewers != 1 || l.Avg != 4 {
		t.Fatalf("one reviewer, two tasks: %+v", l)
	}
	up(other, "ix-count-3", 4)
	if l := local(); l.Reviews != 3 || l.Reviewers != 2 {
		t.Fatalf("two reviewers: %+v", l)
	}
	if _, err := store.RegenerateReviewTagKeyForTest(); err != nil {
		t.Fatal(err)
	}
	up(req, "ix-count-4", 4)
	if l := local(); l.Reviews != 4 || l.Reviewers != 3 {
		t.Fatalf("after a new tag key the same reviewer counts again: %+v", l)
	}
}

// PAY-V3: a peer's review is admitted only on the checks a local upload
// makes that can be made of it — the provider's signature, the review key's,
// the peer's attestation under the peer's key history as it stood on the
// attestation's day, the attestation naming this review — and an
// interaction is reviewed once, wherever.
func TestAPeerReviewIsCheckedLikeALocalOne(t *testing.T) {
	_, store := newHubWithStore(t)
	peer := otherHub(t)
	prov, req := twoAgents(t)
	today := aghub.TodayForTest()
	entry := func(ix string) (aghub.FedReviewEntry, *aghub.ReviewKit) {
		k := makeEvidence(t, prov, req, ix, 4, "")
		return aghub.FedEntryForTest(t, peer.Ctrl, k, today, 1), k
	}
	admit := func(e aghub.FedReviewEntry) error { return store.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), e) }
	dec := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

	good, _ := entry("ix-fed-good")
	if err := admit(good); err != nil {
		t.Fatalf("a genuine entry: %v", err)
	}
	for _, c := range []struct {
		name   string
		change func(e *aghub.FedReviewEntry)
	}{
		{"another format", func(e *aghub.FedReviewEntry) { e.Format = "review/1" }},
		{"the receipt in standard base64", func(e *aghub.FedReviewEntry) { e.Receipt += "=" }},
		{"the provider's signature broken", func(e *aghub.FedReviewEntry) {
			e.Receipt = b64u(rewire(t, dec(e.Receipt), func(w *evidence.ReceiptWire) { w.Env.Sig[0] ^= 1 }))
		}},
		{"the review's signature broken", func(e *aghub.FedReviewEntry) {
			e.Review = b64u(rewire(t, dec(e.Review), func(w *evidence.ReviewWire) { w.Sig[0] ^= 1 }))
		}},
		{"the attestation's signature broken", func(e *aghub.FedReviewEntry) {
			e.Attestation = b64u(rewire(t, dec(e.Attestation), func(w *evidence.ReviewAttWire) { w.Env.Sig[0] ^= 1 }))
		}},
		{"an attestation of another review", func(e *aghub.FedReviewEntry) {
			other, _ := entry("ix-fed-other")
			e.Attestation = other.Attestation
		}},
		{"an attestation by another hub", func(e *aghub.FedReviewEntry) {
			k := aghub.KitFromEntryForTest(t, *e)
			*e = aghub.FedEntryForTest(t, otherHub(t).Ctrl, k, today, 1)
		}},
		{"an attestation of another subject", func(e *aghub.FedReviewEntry) {
			ab := attBody(t, e.Attestation)
			ab.Subject = req.AID()
			e.Attestation = signAtt(t, peer, ab)
		}},
		{"an attestation of another receipt", func(e *aghub.FedReviewEntry) {
			ab := attBody(t, e.Attestation)
			ab.ReceiptCID, _ = anetcid.Sum([]byte("x"))
			e.Attestation = signAtt(t, peer, ab)
		}},
		{"somebody else's key history for the provider", func(e *aghub.FedReviewEntry) {
			e.ProviderKEL = kelB64(t, req)
		}},
		{"no key history for a provider this hub does not know", func(e *aghub.FedReviewEntry) {
			e.ProviderKEL = ""
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, k := entry("ix-fed-" + strings.ReplaceAll(c.name, " ", "-"))
			c.change(&e)
			if err := admit(e); err == nil {
				t.Fatal("admitted")
			}
			if fedStored(t, store, k) {
				t.Fatal("stored")
			}
		})
	}

	t.Run("refused for now: the peer's newer key", func(t *testing.T) {
		// The peer rotated and signs under its new key; this hub still
		// holds its history from before. The entry waits (the stream holds
		// its cursor), and is admitted once the history is caught up.
		p := otherHub(t)
		before := p.Ctrl.KEL()
		if err := identitytest.Rotate(p.Ctrl, uint64(time.Now().UnixMilli())+5); err != nil {
			t.Fatal(err)
		}
		k := makeEvidence(t, prov, req, "ix-fed-newer-key", 5, "")
		e := aghub.FedEntryForTest(t, p.Ctrl, k, today, 1)
		if err := store.AdmitFedReview(p.AID, before, e); !errors.Is(err, federation.ErrRefusedForNow) {
			t.Fatalf("under a key state beyond the held history: %v, want refused for now", err)
		}
		if err := store.AdmitFedReview(p.AID, p.Ctrl.KEL(), e); err != nil {
			t.Fatalf("once the history is caught up: %v", err)
		}
	})

	t.Run("refused for now: no key history of the peer yet", func(t *testing.T) {
		// Until this hub holds the peer's key history it cannot check the
		// attestation; the entry waits rather than being passed for good.
		e, k := entry("ix-fed-no-peer-kel")
		if err := store.AdmitFedReview(peer.AID, nil, e); !errors.Is(err, federation.ErrRefusedForNow) {
			t.Fatalf("no key history of the peer: %v, want refused for now", err)
		}
		raw, _ := json.Marshal(e)
		failing := aghub.FedDirectory{S: store, PeerKEL: func(string) ([]identity.SignedEvent, error) {
			return nil, errors.New("not pinned yet")
		}}
		if err := failing.AdmitFedReview(peer.AID, raw); !errors.Is(err, federation.ErrRefusedForNow) {
			t.Fatalf("the peer's key history not to be had: %v, want refused for now", err)
		}
		if err := (aghub.FedDirectory{S: store}).AdmitFedReview(peer.AID, raw); !errors.Is(err, federation.ErrRefusedForNow) {
			t.Fatalf("no resolver of peer key histories: %v, want refused for now", err)
		}
		if fedStored(t, store, k) {
			t.Fatal("stored")
		}
	})

	t.Run("an attestation is judged at its own day", func(t *testing.T) {
		// CORE-L8: the peer's attestation is checked against the peer's key
		// history as it stood on the attestation's day. The peer signed
		// today under the key it then retired today: that key still spoke
		// for today, not for tomorrow.
		//
		// The rotation is dated the last millisecond of today, so the clock
		// stays before it for the whole subtest: a check made at the
		// arrival time instead of at the attestation's day admits
		// tomorrow's attestation on every run, not only when the clock does
		// not cross the rotation between the two admissions.
		dayEnd, _ := evidence.DayStart(today + 1)
		p := otherHub(t)
		snap, err := p.Ctrl.Export()
		if err != nil {
			t.Fatal(err)
		}
		if err := identitytest.Rotate(p.Ctrl, dayEnd-1); err != nil {
			t.Fatal(err)
		}
		old, err := identity.Restore(snap)
		if err != nil {
			t.Fatal(err)
		}
		k := makeEvidence(t, prov, req, "ix-fed-old-key-today", 5, "")
		if err := store.AdmitFedReview(p.AID, p.Ctrl.KEL(), aghub.FedEntryForTest(t, old, k, today, 1)); err != nil {
			t.Fatalf("attested today under the key retired later today: %v", err)
		}
		k = makeEvidence(t, prov, req, "ix-fed-old-key-tomorrow", 5, "")
		err = store.AdmitFedReview(p.AID, p.Ctrl.KEL(), aghub.FedEntryForTest(t, old, k, today+1, 2))
		if err == nil || errors.Is(err, federation.ErrRefusedForNow) {
			t.Fatalf("attested tomorrow under the key retired today: %v, want refused for good", err)
		}
		if fedStored(t, store, k) {
			t.Fatal("stored")
		}
	})

	t.Run("a provider history the peer cut short", func(t *testing.T) {
		// This hub knows the provider rotated; a peer sends the history
		// from before, under which the retired key looks current. The
		// longer history decides, and the receipt the retired key signed
		// for tomorrow is refused.
		p2, r2 := twoAgents(t)
		snap, _ := p2.Export()
		short, _ := identity.MarshalKEL(p2.KEL())
		if err := identitytest.Rotate(p2, uint64(time.Now().UnixMilli())+5); err != nil {
			t.Fatal(err)
		}
		kel, _ := identity.MarshalKEL(p2.KEL())
		if err := store.PutAgent(p2.AID(), "rotated", nil, kel); err != nil {
			t.Fatal(err)
		}
		old, _ := identity.Restore(snap)
		k := aghub.NewReviewKitForTest(t, old, r2, "ix-fed-short", 5)
		k.Receipt.CompletedDay++
		k.Review.CreatedDay++
		e := aghub.FedEntryForTest(t, peer.Ctrl, k, today, 1)
		e.ProviderKEL = b64u(short)
		if err := admit(e); err == nil {
			t.Fatal("a receipt signed with a retired key was admitted under a history cut short")
		}
	})

	t.Run("an interaction reviewed already", func(t *testing.T) {
		srv, store := newHubWithStore(t)
		register(t, srv, prov, "Provider", []string{"work.do"})
		register(t, srv, req, "Requester", nil)
		k := makeEvidence(t, prov, req, "ix-fed-local", 5, "")
		if code, b := uploadReview(t, srv, k); code != 200 {
			t.Fatalf("upload: %d %s", code, b)
		}
		if err := store.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, k, today, 1)); !errors.Is(err, aghub.ErrReviewExists) {
			t.Fatalf("a peer's review of an interaction reviewed here: %v", err)
		}
		// And the other way round: reviewed at a peer first, the upload
		// here is review_exists (PAY-V1 step 9 reads fed_review too).
		k2 := makeEvidence(t, prov, req, "ix-fed-first", 4, "")
		if err := store.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, k2, today, 2)); err != nil {
			t.Fatalf("the peer's review: %v", err)
		}
		if code, b := uploadReview(t, srv, k2); code != http.StatusConflict || !strings.Contains(string(b), `"review_exists"`) {
			t.Fatalf("an upload of an interaction a peer reviewed: %d %s, want 409 review_exists", code, b)
		}
		if reviewStored(t, store, k2) {
			t.Fatal("stored as a local review as well")
		}
	})
}

func attBody(t *testing.T, b64 string) evidence.ReviewAttBody {
	t.Helper()
	raw, _ := base64.RawURLEncoding.DecodeString(b64)
	w, err := evidence.UnmarshalReviewAttWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.Open()
	if err != nil {
		t.Fatal(err)
	}
	return *b
}

func signAtt(t *testing.T, hub *hubid.Identity, b evidence.ReviewAttBody) string {
	t.Helper()
	w, err := b.Sign(hub.Ctrl)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b64u(raw)
}

// fedStored reports whether a peer's review of k's interaction is held.
func fedStored(t *testing.T, store *aghub.Store, k *aghub.ReviewKit) bool {
	t.Helper()
	var n int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM fed_review WHERE ix_commit=?`, k.IXCommit()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// P-PAY-8, the hub's part: a receipt or a review changed anywhere after it
// was signed — any byte, any field — is refused by the upload and by a peer's
// admission alike; the same objects unchanged are accepted.
func TestPropTamperedEvidenceIsRefused(t *testing.T) {
	srv, store := newHubWithStore(t)
	prov, req := twoAgents(t)
	register(t, srv, prov, "Provider", []string{"work.do"})
	register(t, srv, req, "Requester", nil)
	peer := otherHub(t)
	_, peerSide := newHubWithStore(t)
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	t.Logf("seed %d", seed)
	fields := []func(rc *evidence.ReceiptBody, rv *evidence.ReviewBody){
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.IXCommit[rng.IntN(32)] ^= 1 },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.RequesterCommit[rng.IntN(32)] ^= 1 },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.ReviewKey[rng.IntN(32)] ^= 1 },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.RequestCID += "x" },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.ResultCID += "x" },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.CompletedDay-- },
		func(rc *evidence.ReceiptBody, _ *evidence.ReviewBody) { rc.Provider = req.AID() },
		func(_ *evidence.ReceiptBody, rv *evidence.ReviewBody) { rv.Rating = rv.Rating%5 + 1 },
		func(_ *evidence.ReceiptBody, rv *evidence.ReviewBody) { rv.Comment += "!" },
		func(_ *evidence.ReceiptBody, rv *evidence.ReviewBody) { rv.CreatedDay-- },
		func(_ *evidence.ReceiptBody, rv *evidence.ReviewBody) { rv.Subject = req.AID() },
		func(_ *evidence.ReceiptBody, rv *evidence.ReviewBody) { rv.ReceiptCID += "x" },
	}
	const trials = 120
	for i := 0; i < trials; i++ {
		k := makeEvidenceWithComment(t, prov, req, fmt.Sprintf("ix-prop-%d-%d", seed, i), 3, "", "ok")
		rcB, rvB := k.Wires(t)
		var what string
		switch rng.IntN(3) {
		case 0: // a byte of either object
			b := rcB
			what = "receipt byte"
			if rng.IntN(2) == 1 {
				b, what = rvB, "review byte"
			}
			pos := rng.IntN(len(b))
			b[pos] ^= byte(1 << rng.IntN(8))
			what += " " + strconv.Itoa(pos)
		default: // a field of a body, the signature left as it was
			f := rng.IntN(len(fields))
			what = "field " + strconv.Itoa(f)
			var rw evidence.ReceiptWire
			var vw evidence.ReviewWire
			var rc evidence.ReceiptBody
			var rv evidence.ReviewBody
			_ = coredet.Unmarshal(rcB, &rw)
			_ = coredet.Unmarshal(rvB, &vw)
			_ = coredet.Unmarshal(rw.Body, &rc)
			_ = coredet.Unmarshal(vw.Body, &rv)
			fields[f](&rc, &rv)
			rw.Body, _ = coredet.Marshal(rc)
			vw.Body, _ = coredet.Marshal(rv)
			rcB, _ = coredet.Marshal(rw)
			rvB, _ = coredet.Marshal(vw)
		}
		body := map[string]string{"receipt": b64u(rcB), "review": b64u(rvB), "rsalt": b64u(k.RSalt)}
		if code, b := signedDo(t, srv, req, relayauth.ActionReview, http.MethodPost, "/reviews", body); code == 200 {
			t.Fatalf("trial %d (%s): a tampered upload was stored: %s", i, what, b)
		}
		// The peer attests what it sends, tampered or not (a lying peer);
		// bytes too broken to name a review travel under the attestation
		// of the objects before they were changed.
		kel, _ := identity.MarshalKEL(prov.KEL())
		e, err := aghub.FedEntryOfForTest(peer.Ctrl, rcB, rvB, kel, req.AID(), aghub.TodayForTest(), uint64(i+1))
		if err != nil {
			k.RawReceipt, k.RawReview = nil, nil
			e = aghub.FedEntryForTest(t, peer.Ctrl, k, aghub.TodayForTest(), uint64(i+1))
			e.Receipt, e.Review = b64u(rcB), b64u(rvB)
		}
		if err := peerSide.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), e); err == nil {
			t.Fatalf("trial %d (%s): a peer's tampered review was admitted", i, what)
		}
	}
	// Untampered, both paths accept.
	k := makeEvidence(t, prov, req, fmt.Sprintf("ix-prop-%d-clean", seed), 4, "")
	if code, b := uploadReview(t, srv, k); code != 200 {
		t.Fatalf("the untampered upload: %d %s", code, b)
	}
	k2 := makeEvidence(t, prov, req, fmt.Sprintf("ix-prop-%d-clean-peer", seed), 4, "")
	if err := peerSide.AdmitFedReview(peer.AID, peer.Ctrl.KEL(), aghub.FedEntryForTest(t, peer.Ctrl, k2, aghub.TodayForTest(), 1)); err != nil {
		t.Fatalf("the untampered peer review: %v", err)
	}
	var n int
	if err := store.DBForTest().QueryRow(`SELECT COUNT(*) FROM review`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the hub stored %d reviews (%v), want only the untampered one", n, err)
	}
}

// The review tag key (hub-payment-privacy §3.3): 32 bytes in
// <data>/keys/review_tag.key, 0600 in a 0700 directory, made at the first
// start under tag_key_id 1, the same after a restart, a new one under the
// next id when the file is gone or an emergency rotation regenerates it
// (KEL H-33, listed in hubid.EmergencySecrets), and a file that is not a key
// stops the hub.
func TestTheReviewTagKey(t *testing.T) {
	dir := t.TempDir()
	open := func() *aghub.Store {
		t.Helper()
		s, err := aghub.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	id, err := s.LoadReviewTagKey()
	if err != nil || id != 1 {
		t.Fatalf("first start: id %d, %v", id, err)
	}
	k1, _, _ := s.ReviewTagKeyForTest()
	s.Close()
	path := aghub.TagKeyPath(dir)
	if path != filepath.Join(dir, "keys", "review_tag.key") {
		t.Fatalf("the key is at %s", path)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != 32 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if dst, err := os.Stat(filepath.Dir(path)); err != nil || dst.Mode().Perm() != 0o700 {
		t.Fatalf("keys directory: %v %v", dst, err)
	}
	onDisk, _ := os.ReadFile(path)
	if !bytes.Equal(onDisk, k1) {
		t.Fatal("the key in use is not the key on disk")
	}

	s = open()
	if k, id, err := s.ReviewTagKeyForTest(); err != nil || id != 1 || !bytes.Equal(k, k1) {
		t.Fatalf("after a restart: id %d, same key %v, %v", id, bytes.Equal(k, k1), err)
	}
	s.Close()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s = open()
	k2, id, err := s.ReviewTagKeyForTest()
	if err != nil || id != 2 || bytes.Equal(k2, k1) {
		t.Fatalf("after the file was lost: id %d, %v", id, err)
	}
	s.Close()

	var entry *hubid.EmergencySecret
	for _, e := range hubid.EmergencySecrets() {
		if e.Name == aghub.ReviewTagKeyName {
			e := e
			entry = &e
		}
	}
	if entry == nil || entry.Name != "hub_tag_key" {
		t.Fatalf("hub_tag_key is not among the emergency secrets: %+v", hubid.EmergencySecrets())
	}
	if err := entry.Regenerate(dir); err != nil {
		t.Fatal(err)
	}
	s = open()
	k3, id, err := s.ReviewTagKeyForTest()
	if err != nil || id != 3 || bytes.Equal(k3, k2) || bytes.Equal(k3, k1) {
		t.Fatalf("after an emergency rotation: id %d, %v", id, err)
	}
	s.Close()
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("the keys directory holds %d files, want the key alone", len(entries))
	}

	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = open()
	defer s.Close()
	if _, err := s.LoadReviewTagKey(); !errors.Is(err, aghub.ErrTagKeyFile) {
		t.Fatalf("a key file that is not a key: %v, want ErrTagKeyFile", err)
	}
	var v string
	if err := s.DBForTest().QueryRow(`SELECT value FROM hub_meta WHERE key='tag_key_id'`).Scan(&v); err != nil || v != "3" {
		t.Fatalf("tag_key_id %q (%v), want 3", v, err)
	}
}

// A key file beside a database that never named one (hub.db made anew next
// to an existing keys directory) is that database's first key: tag_key_id 1,
// never 0, so its tags are counted under an id like any other's.
func TestATagKeyBesideANewDatabaseIsItsFirst(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x5c}, evidence.TagKeySize)
	path := aghub.TagKeyPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, id, err := s.ReviewTagKeyForTest()
	if err != nil || id != 1 || !bytes.Equal(got, key) {
		t.Fatalf("id %d, the file's key %v, %v; want id 1 and the file's key", id, bytes.Equal(got, key), err)
	}
	var v string
	if err := s.DBForTest().QueryRow(`SELECT value FROM hub_meta WHERE key='tag_key_id'`).Scan(&v); err != nil || v != "1" {
		t.Fatalf("tag_key_id %q (%v), want 1", v, err)
	}
}
