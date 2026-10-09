package aghub

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// The two halves of a cross-hub send (sealed-sender §4.2.6, §4.2.7, SSR-H13).
//
// The origin (the hub the sender sends at) checks the credential as far as
// it can, takes the sender's own bucket and hands the envelope to the one
// hub that is the recipient's home (forwardSend), and answers the sender
// with what that hub answered (forwardAnswer). The destination (the home)
// checks it again in full, takes its own buckets and queues it
// (ServeForward). Neither stores anything of the sender; the origin stores
// nothing at all.

// FedForwardResponse is the /fed/v3/forward answer (core §2.12.2): the
// /relay/send answer of the home hub, which is always the hub that queued
// the envelope.
type FedForwardResponse struct {
	Status         string `json:"status"`
	RID            string `json:"rid"`
	RecipientQuiet bool   `json:"recipient_quiet"`
}

// FedBucketResponse is the /fed/v3/directory:bucket answer: the
// /directory:bucket answer without partial, since a hub answers a peer for
// its own entries only (SSR-W20).
type FedBucketResponse struct {
	MaxBits uint             `json:"max_bits"`
	Entries []DirBucketEntry `json:"entries"`
	Next    string           `json:"next,omitempty"`
}

// ---- the origin ----

// forwardTake is the sender's bucket a forward takes a token from at the
// origin: a first contact's session send bucket, or a credential's bucket.
type forwardTake = bucketTake

// passedThrough are the refusals of a home that the origin answers the
// sender with, the same status and reason (SSR-H13). The origin writes its
// own body: the code's sentence, never the home's text, and for
// access_invalid the one body of SSR-H3.
var passedThrough = map[wire3.Reason]bool{
	wire3.ReasonAccessInvalid: true, wire3.ReasonKidStale: true,
	wire3.ReasonBadEnvelope: true, wire3.ReasonExpired: true, wire3.ReasonBadExp: true, wire3.ReasonBadRequest: true,
	wire3.ReasonTooLarge: true, wire3.ReasonTooLargeForStranger: true,
	wire3.ReasonRateLimited: true, wire3.ReasonStrangersBusy: true, wire3.ReasonRedeliveryLimited: true,
	wire3.ReasonMailboxFull: true,
}

// homeUnreachableWait is the Retry-After of home_unreachable when the home
// gave none (SSR-H13).
const homeUnreachableWait = 60 * time.Second

// fwdSend is one send the origin hands on to a home.
type fwdSend struct {
	home     string
	to       string
	envelope []byte
	access   []byte
	take     forwardTake
	addr     string
	capBody  *seal.CapBody // nil for a first contact
}

// forwardSend is step 6 of /relay/send for a recipient registered at the
// peer hub f.home (SSR-H13): it takes the sender's own bucket (and no
// other), hands the envelope to that one hub, and answers the sender by
// forwardAnswer. Nothing is stored here.
func (s *Server) forwardSend(w http.ResponseWriter, r *http.Request, f fwdSend) {
	if ok, wait := f.take.set.take(f.take.key, f.take.rate); !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait})
		return
	}
	resp, err := s.fed.Forward(r.Context(), f.home, f.envelope, wire3.EncodeB64URL(f.access))
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonHomeUnreachable, RetryAfter: homeUnreachableWait})
		return
	}
	defer resp.Body.Close()
	s.forwardAnswer(w, resp, f)
}

// forwardAnswer answers the sender with what the home answered, by the
// table of SSR-H13:
//
//   - 200 queued or duplicate: 200, with the home's rid, via_hub the home
//     and recipient_quiet;
//   - 404 unknown_destination: 404 recipient_unknown, and no other hub is
//     tried (SI-17); the recipient's home is resolved afresh at its next
//     use (resolveRecipient);
//   - a refusal of passedThrough: the same status and reason, with the
//     home's Retry-After; for 403 access_invalid (to a send under a
//     credential: a first contact has none to refuse) the credential is kept
//     as refused (SSR-H14a), the owner's resolution is made again at its
//     next use, and the client address's bucket of refusals loses a token
//     (SSR-H3b);
//   - anything else (not_peer, another 401, source_rate, a 5xx, an answer
//     that is not the contract's): 502 home_unreachable, with the home's
//     Retry-After or 60 seconds.
func (s *Server) forwardAnswer(w http.ResponseWriter, resp *http.Response, f fwdSend) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	wait := retryAfterOf(resp)
	unreachable := func() {
		if wait <= 0 {
			wait = homeUnreachableWait
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonHomeUnreachable, RetryAfter: wait})
	}
	if err != nil {
		unreachable()
		return
	}
	if resp.StatusCode == http.StatusOK {
		var ans FedForwardResponse
		if wire3.DecodeStrict(raw, &ans) != nil || ans.Status != RelayQueued && ans.Status != RelayDuplicate {
			unreachable()
			return
		}
		if _, err := wire3.DecodeB64URLSize("rid", ans.RID, RIDLen); err != nil {
			unreachable()
			return
		}
		writeJSON(w, http.StatusOK, RelaySendResponse{Status: ans.Status, RID: ans.RID, ViaHub: f.home,
			RecipientQuiet: ans.RecipientQuiet})
		return
	}
	var ref struct {
		Reason string `json:"reason"`
	}
	reason := wire3.Reason("")
	if json.Unmarshal(raw, &ref) == nil {
		reason = wire3.Reason(ref.Reason)
	}
	switch {
	case reason == wire3.ReasonUnknownDestination && resp.StatusCode == http.StatusNotFound:
		s.fedState.markStale(f.to, s.store.now())
		wire3.Refuse(w, wire3.ReasonRecipientUnknown)
	case reason == wire3.ReasonAccessInvalid && resp.StatusCode == http.StatusForbidden && f.capBody != nil:
		s.fedState.putNegative(negKey{f.home, f.capBody.Owner, string(f.capBody.CapID)}, f.capBody.CapExp)
		s.fedState.markStale(f.capBody.Owner, s.store.now())
		s.refuseAccess(w, f.addr)
	case passedThrough[reason] && reason != wire3.ReasonAccessInvalid && resp.StatusCode == wire3.Status(reason):
		wire3.Write(w, wire3.Refusal{Reason: reason, RetryAfter: wait})
	default:
		unreachable()
	}
}

// retryAfterOf is a response's Retry-After in delta-seconds, 0 when it has
// none that reads.
func retryAfterOf(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Second
}

// capPrecheckRemote is step 2 of a kind-1 send whose owner is not
// registered here (§4.2.6, SSR-H14): the owner's home and mailbox key are
// resolved (resolveOwner), the credential is not one its home refused
// (SSR-H14a), and it was signed under the owner's current epoch, by that
// key, and has not expired. A signature that does not verify under the key
// held has the owner's resolution made again at its next use (§2.12). The
// revocations of a remote owner are its home's to check. Every refusal is the one answer of SSR-H3 and costs one
// verification (SSR-H3a), as for an owner registered here.
func (s *Server) capPrecheckRemote(w http.ResponseWriter, r *http.Request, a *seal.Access, body *seal.CapBody, addr, hint string, now time.Time) (seal.Mbox, string, bool) {
	c := a.Cap
	refuse := func(equal bool) (seal.Mbox, string, bool) {
		if equal {
			_ = verifyEd25519(equalVerifyKey, c.Body, c.Sig)
		}
		s.refuseAccess(w, addr)
		return seal.Mbox{}, "", false
	}
	home, mbox, ok := s.resolveOwner(r.Context(), body.Owner, hint, body.Epoch)
	if !ok {
		return refuse(true)
	}
	nowMS := uint64(now.UnixMilli())
	if s.fedState.negative(negKey{home, body.Owner, string(body.CapID)}, nowMS) {
		return refuse(true)
	}
	if body.Epoch != mbox.Epoch || len(mbox.Pub) != ed25519.PublicKeySize {
		return refuse(true)
	}
	if !verifyEd25519(mbox.Pub, c.Body, c.Sig) {
		s.fedState.markStale(body.Owner, now)
		return refuse(false)
	}
	if !capExpOK(body.CapExp, nowMS) {
		return refuse(false)
	}
	return mbox, home, true
}

// ---- the destination (federation.Kernel) ----

// PeerRC1 is RC1 for a verified signature of the peer hub aid at ts, with K
// = 4096 (core G17; federation authPeer). On a refusal it writes the same
// body an agent gets.
func (s *Server) PeerRC1(w http.ResponseWriter, aid string, ts uint64) bool {
	now := time.Now().UnixMilli()
	var f *authFailure
	switch v, floor := s.replay.accept(aid, ts, rc1KPeerHub, now); v {
	case rc1Stale:
		f = &authFailure{code: http.StatusUnauthorized, reason: wire3.ReasonTSStale, floor: floor}
	case rc1Replayed:
		f = &authFailure{code: http.StatusUnauthorized, reason: wire3.ReasonReplayed}
	case rc1Outside:
		f = &authFailure{code: http.StatusUnauthorized, err: errOutsideWindow}
	}
	if f != nil {
		writeAuthFailure(w, f)
		return false
	}
	return true
}

// PeerFloor is RC1's floor for the peer hub aid now (federation authPeer):
// a signing time at or below it is refused whatever its signature, so
// /fed/v3 refuses it before it reads the body (sealed-sender SSR-H16). It
// takes nothing and adds no state.
func (s *Server) PeerFloor(aid string) uint64 { return s.replay.floorOf(aid) }

// floorOf is aid's floor now: its own, or for a signer without state the
// floor of its part (PAY-R6a).
func (r *rc1State) floorOf(aid string) uint64 {
	sh := r.shard(aid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if st := sh.signers[aid]; st != nil {
		return st.floor
	}
	return sh.gone
}

// ForwardSourceEmpty is step 2 of /fed/v3/forward: whether the peer aid's
// source bucket holds less than a token, without taking one.
func (s *Server) ForwardSourceEmpty(aid string) (bool, time.Duration) {
	return s.relay.fedSource.peek(aid, rateFedSource)
}

// MaxEnvelope is the largest envelope this hub carries (/fed/v3/forward
// step 3).
func (s *Server) MaxEnvelope() int64 { return s.limits.MaxEnvelope }

// ServeForward is /fed/v3/forward from step 5 on (sealed-sender §4.2.7,
// SSR-H15), for a request the peer hub peer signed (federation authPeer has
// done steps 1 to 4), whose body is body:
//
//	5  the headers: Content-Type; X-ANet-Access as for /relay/send; no
//	   session headers
//	6  kind 1: the owner is registered here; the credential's body, type,
//	   epoch, signature, cap_exp and revocation
//	7  the envelope: seal.ParseOuter, outer key 7 the same bytes as the
//	   header, the recipient AID
//	8  kind 1: seal.VerifyAccess, owner == to and the holder's proof
//	9  the recipient is registered here
//	10 the same envelope already waiting: duplicate; non-contact mail no
//	   larger than the recipient's share
//	11 the buckets, all or none: the source hub's; a first contact's
//	   recipient's first-contact bucket, or the credential's
//	12 Store.RelayEnqueue: the redelivery count, the kid (409 kid_stale,
//	   FS-H3) and the mailbox
//	13 queued, with the rid
//
// A first contact was authenticated by the source hub, which also took the
// sender's session bucket. Only what the source hub should have found
// itself costs its bucket FedSourcePenalty tokens (SSR-H15a): a credential
// that does not decode or is not a credential, a signature that does not
// verify under the epoch the source hub saw too, an owner that is not the
// recipient, a proof for another envelope. An owner registered elsewhere,
// another epoch, an expiry and a revocation do not: the source hub could not
// know them.
func (s *Server) ServeForward(w http.ResponseWriter, r *http.Request, peer string, body []byte) {
	now := s.store.now()
	penalize := func() { s.relay.fedSource.debit(peer, rateFedSource, FedSourcePenalty) }
	// 5. The headers.
	if !envelopeContentType(r) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A forward carries the envelope itself as " + EnvelopeContentType + "; send it with that Content-Type."})
		return
	}
	accessRaw, access, why := accessHeader(r)
	if why != "" {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadEnvelope, Error: why})
		return
	}
	for _, h := range []string{relayauth.HeaderSession, relayauth.HeaderMAC} {
		if len(r.Header.Values(h)) > 0 {
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
				Error: "A forward carries no session; the source hub checked it. Send it without " +
					relayauth.HeaderSession + " and " + relayauth.HeaderMAC + "."})
			return
		}
	}
	// 6. The credential.
	var capBody *seal.CapBody
	var mbox seal.Mbox
	if access.Kind == seal.AccessKindCap {
		cb, err := seal.UnmarshalCapBody(access.Cap.Body)
		if err != nil || cb.Class != seal.CapClassContact && cb.Class != seal.CapClassStranger || cb.Type != seal.CapType {
			penalize()
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
		m, found, registered, err := s.store.ownerMboxOf(cb.Owner)
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		if !registered || !found || cb.Epoch != m.Epoch || len(m.Pub) != ed25519.PublicKeySize {
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
		if !verifyEd25519(m.Pub, access.Cap.Body, access.Cap.Sig) {
			penalize()
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
		if !capExpOK(cb.CapExp, uint64(now.UnixMilli())) {
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
		revoked, err := s.store.CapRevoked(cb.Owner, cb.CapID)
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		if revoked {
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
		capBody, mbox = cb, m
	}
	// 7. The envelope.
	outer, err := seal.ParseOuter(body)
	if err != nil {
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
		return
	}
	if !sameOuterAccess(body, accessRaw) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadEnvelope,
			Error: "Outer key 7 of the envelope is not the access in " + HeaderAccess + "; send the same bytes in both."})
		return
	}
	if err := wire3.CheckText("to", outer.To); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	// v030-todo(UX-7): outer key 8 (CUX-H1, core G23): 400 expired and
	// bad_exp, here, as at the origin.
	digest, err := seal.EnvDigest(body)
	if err != nil {
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
		return
	}
	// 8. The credential, completed.
	if capBody != nil {
		if err := seal.VerifyAccess(access, digest, mbox, outer.To, uint64(now.UnixMilli())); err != nil {
			penalize()
			wire3.Refuse(w, wire3.ReasonAccessInvalid)
			return
		}
	}
	// 9. The recipient.
	registered, err := s.store.agentRegistered(outer.To)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if !registered {
		wire3.Refuse(w, wire3.ReasonUnknownDestination)
		return
	}
	// 10. The same envelope already waiting; mail from a non-contact no
	// larger than its share.
	if rid, ok, err := s.store.RelayQueued(outer.To, digest); err != nil {
		wire3.Internal(w, err)
		return
	} else if ok {
		s.answerForward(w, RelayDuplicate, rid, outer.To)
		return
	}
	class, capID := seal.CapClassStranger, []byte(nil)
	if capBody != nil {
		class, capID = capBody.Class, capBody.CapID
	}
	q := s.store.QuotaFor(outer.To)
	if class == seal.CapClassStranger && int64(len(body)) > q.NonContactBytes {
		wire3.Refuse(w, wire3.ReasonTooLargeForStranger)
		return
	}
	// 11. The buckets, all or none.
	takes := []bucketTake{{s.relay.fedSource, peer, rateFedSource}}
	refusals := []wire3.Reason{wire3.ReasonSourceRate}
	if capBody != nil {
		takes = append(takes, bucketTake{s.relay.caps, capKey(capBody), capRate(capBody)})
		refusals = append(refusals, wire3.ReasonRateLimited)
	} else {
		takes = append(takes, bucketTake{s.relay.firstContact, outer.To, firstContactRate(q)})
		refusals = append(refusals, wire3.ReasonStrangersBusy)
	}
	if failed, wait := takeAll(takes); failed >= 0 {
		if rid, ok, err := s.store.RelayQueued(outer.To, digest); err == nil && ok {
			s.answerForward(w, RelayDuplicate, rid, outer.To)
			return
		}
		wire3.Write(w, wire3.Refusal{Reason: refusals[failed], RetryAfter: wait})
		return
	}
	// 12. The redelivery count, the kid and the mailbox, in the transaction
	// that writes the row (§4.2.1 steps 9, 10). A refusal gives the tokens
	// back.
	queued, err := s.store.RelayEnqueue(RelayItem{To: outer.To, Envelope: body, Digest: digest,
		Class: class, CapID: capID, Exp: outer.Exp, KID: outer.KID})
	if err != nil || queued.Duplicate {
		refundAll(takes)
	}
	var limited *RedeliveryLimitedError
	switch {
	case err == nil && queued.Duplicate:
		s.answerForward(w, RelayDuplicate, queued.RID, outer.To)
	case err == nil:
		// 13.
		s.answerForward(w, RelayQueued, queued.RID, outer.To)
	case errors.As(err, &limited):
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRedeliveryLimited, RetryAfter: limited.Wait})
	case errors.Is(err, ErrKidStale):
		// The home checks the kid (FS-H3); the origin answers the sender
		// with this status and body as they are (passedThrough).
		wire3.Refuse(w, wire3.ReasonKidStale)
	case errors.Is(err, ErrMailboxFull):
		wire3.Refuse(w, wire3.ReasonMailboxFull)
	case errors.Is(err, ErrStrangersBusy):
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonStrangersBusy, RetryAfter: StrangersBusyRetry})
	case errors.Is(err, ErrBadEnvelope):
		wire3.Refuse(w, wire3.ReasonBadEnvelope)
	default:
		wire3.Internal(w, err)
	}
}

// answerForward is the 200 of a forward: the /relay/send answer of this hub
// as the home.
func (s *Server) answerForward(w http.ResponseWriter, status string, rid []byte, to string) {
	live, _ := s.store.LivenessOf(to)
	writeJSON(w, http.StatusOK, FedForwardResponse{Status: status, RID: wire3.EncodeB64URL(rid), RecipientQuiet: live.Quiet})
}

// ServeBucket is /fed/v3/directory:bucket for a request a peer hub signed
// (federation authPeer), whose body is body: the request and the checks of
// /directory:bucket (decodeBucketQuery), and a page of this hub's own
// entries, without partial (SSR-W20). A peer is not limited per address: it
// is a hub of the peer table, and its requests are signed.
func (s *Server) ServeBucket(w http.ResponseWriter, body []byte) {
	q, ok := s.decodeBucketQuery(w, body)
	if !ok {
		return
	}
	entries, next, err := s.store.DirBucket(q.prefix, q.bits, q.after)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := FedBucketResponse{MaxBits: uint(q.maxBits), Entries: entries}
	if next != nil {
		out.Next = wire3.EncodeB64URL(next)
	}
	writeJSON(w, http.StatusOK, out)
}

// fedCardRoute is the home (a hub URL) of the listed A2A card of aid that a
// peer taught this hub, and the key set the card arrived with; "" when
// there is no such card.
func (s *Store) fedCardRoute(aid string) (home string, keys []byte, err error) {
	err = s.db.QueryRow(`SELECT home, keys FROM fed_a2a_card WHERE aid=? AND verified_at IS NOT NULL`, aid).Scan(&home, &keys)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil
	}
	return home, keys, err
}
