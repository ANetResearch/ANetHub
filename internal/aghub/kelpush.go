package aghub

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// POST /agents/kel:push (KEL §2.7, H-4; core §2.12.2): a key history this
// hub knows, extended.
//
// An agent registers only at the hub its KEL names as its witness. When it
// moves to another hub, or deactivates, the hub it leaves behind still holds
// its old key history, and with it would go on signing notices for the old
// tip and taking requests signed by the retired key. So the agent's daemon
// pushes its whole KEL to every hub that was ever its witness, until each
// has confirmed the new tip (KEL D-33); this is the route it pushes to.
//
// The route is not authenticated: a key history proves itself. Every event
// is signed by a key the event before committed to, so only whoever holds
// the identity's keys can extend it, and this hub takes a push only when it
// replays to the AID and extends the history held here (the registration or
// the tombstone in departed_kel), or is the same. It is limited per client
// address instead (KELPushPerMinute, KELPushBurst; the keys of limits.go
// clientIP: an IPv4 address, an IPv6 /64), before the body is read. In
// order:
//
//  1. the client address's bucket: 429 rate_limited with Retry-After;
//  2. the body, at most kelPushBodyLimit, decoded strictly, with aid and
//     kel: 413 too_large, 400 bad_request;
//  3. aid is an AID: 400 bad_request;
//  4. this hub holds a key history for aid: 404 unknown_aid (before the
//     pushed one is decoded, so a push for an AID nobody registered here
//     costs no replay);
//  5. kel is base64url, decodes within the caps every sender applies, and
//     replays to aid: 400 kel_invalid;
//  6. kel extends the history held, or is the same: 409 kel_fork,
//     kel_rollback;
//  7. the new events' times (R-9, R-10, as /register): 400
//     kel_ts_out_of_window;
//  8. the same history: 200 with unchanged true, nothing written (a push
//     repeated is idempotent);
//  9. one transaction: the registration's history replaced, with what it
//     ends (H-2: a key set not signed under the new tip, the cached
//     notice) and the directory entry; a history ending in a dip
//     deregisters the agent through DeregisterTx (H-4); for an agent that
//     already left, the tombstone extended;
//  10. 200 {aid, seq, head, unchanged}: the tip now held.
//
// A history whose tip names another hub as the witness stays registered
// here, with its mailbox, until the agent leaves (hub-leave); this hub stops
// signing notices for it (notice.go, H-10 3).

// KELPushPath is the route.
const KELPushPath = "/agents/kel:push"

// The KELPushRate of KEL §2.12, per client address key: code constants.
const (
	KELPushPerMinute = 60
	KELPushBurst     = 20
)

// kelPushBodyLimit bounds a push: a KEL at seal.MaxKELBytes in base64url
// (4/3 of it) and an AID, with room for the JSON around them.
const kelPushBodyLimit = 128 << 10

// KELPushRequest is the POST /agents/kel:push body (core §2.12.2), decoded
// strictly (CORE-E7). KEL is base64url of identity.MarshalKEL.
type KELPushRequest struct {
	AID string `json:"aid"`
	KEL string `json:"kel"`
}

// KELPushResponse is the answer: the tip of the key history this hub now
// holds for aid (its seq and event id), and whether the push changed
// nothing.
type KELPushResponse struct {
	AID       string `json:"aid"`
	Seq       uint64 `json:"seq"`
	Head      string `json:"head"`
	Unchanged bool   `json:"unchanged"`
}

// hKELPush serves POST /agents/kel:push.
func (s *Server) hKELPush(w http.ResponseWriter, r *http.Request) {
	// 1. Per client address, before the body is read.
	if ok, wait := s.kelPushLimiter.allow(clientIP(r)); !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
			Error: "Too many key history pushes from this address; push again after the seconds in Retry-After."})
		return
	}
	// 2, 3. The body.
	body, ok := wire3.ReadBody(w, r, kelPushBodyLimit)
	if !ok {
		return
	}
	var req KELPushRequest
	if err := wire3.DecodeStrict(body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	if req.AID == "" || req.KEL == "" {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "A push carries aid and kel; add them and send again."})
		return
	}
	if !ValidAID(req.AID) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"aid\" is not a complete AID; send the agent's own AID as anet prints it."})
		return
	}
	// 4. An AID this hub holds a key history for.
	if known, err := s.store.holdsKEL(req.AID); err != nil {
		wire3.Internal(w, err)
		return
	} else if !known {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnknownAID,
			Error: "This hub holds no key history for this AID; push it to the hubs that witnessed it."})
		return
	}
	// 5. The pushed key history.
	raw, err := wire3.DecodeB64URL("kel", req.KEL)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The member \"kel\" is not base64url; encode the key history without padding and send again."})
		return
	}
	kel, err := seal.ParseKEL(raw)
	if err != nil {
		msg := "The key history does not decode; send the identity's own key history."
		if seal.ReasonOf(err) == seal.ReasonKELTooLarge {
			msg = fmt.Sprintf("The key history is too long: this hub, like every sender, accepts at most %d events and %d bytes.",
				seal.MaxKELEvents, seal.MaxKELBytes)
		}
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid, Error: msg})
		return
	}
	if states, err := identity.Replay(kel); err != nil || states[len(states)-1].AID != req.AID {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELInvalid,
			Error: "The key history does not replay to the aid it is pushed for; send that identity's own key history."})
		return
	}
	// 6 to 9.
	res, err := s.store.PushKEL(req.AID, kel)
	switch {
	case errors.Is(err, ErrKELNotExtended):
		refuseKELExtension(w, err)
		return
	case errors.Is(err, identity.ErrEventFromFuture), errors.Is(err, identity.ErrEventTooOld):
		refuseEventTime(w, err)
		return
	case errors.Is(err, errNoKEL):
		// Deregistered and its tombstone gone meanwhile: not possible
		// today (a tombstone is never deleted), said as step 4 says it.
		wire3.Refuse(w, wire3.ReasonUnknownAID)
		return
	case err != nil:
		wire3.Internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, KELPushResponse{AID: req.AID, Seq: res.Seq, Head: res.Head, Unchanged: res.Unchanged})
}

// refuseEventTime answers a key history with a new event outside this hub's
// clock window (KEL R-9, R-10): 400 kel_ts_out_of_window, saying which way.
func refuseEventTime(w http.ResponseWriter, err error) {
	msg := "A new key event is dated more than 5 minutes before this hub's clock; correct the system clock and sign the event again."
	if errors.Is(err, identity.ErrEventFromFuture) {
		msg = "A new key event is dated more than 5 minutes after this hub's clock; correct the system clock and sign the event again."
	}
	wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonKELTSOutOfWindow, Error: msg})
}

// checkNewEvents applies KEL R-9 and R-10 to the events kel adds to held
// (nil: this hub holds none), at now: the acceptance rule every party
// applies, with this hub as the witness it is for the events that name it.
func (s *Server) checkNewEvents(held, kel []identity.SignedEvent, now time.Time) error {
	return identity.CheckNewEvents(held, kel, uint64(now.UnixMilli()), firstWitness(kel, s.hubAID))
}

// firstWitness says, for an event of kel, whether hubAID is the hub that
// first accepts it as its witness (KEL R-10): for a rot, the hub its key 9
// names; for a dip, the hub the state before it names. Every other party
// (an old witness taking a push, another hub) checks R-9 alone.
func firstWitness(kel []identity.SignedEvent, hubAID string) func(identity.KeyEvent) bool {
	return func(e identity.KeyEvent) bool {
		if hubAID == "" {
			return false
		}
		switch e.Type {
		case identity.Rotation:
			return len(e.Witnesses) > 0 && e.Witnesses[0] == hubAID
		case identity.Deactivation:
			return witnessBefore(kel, e.Seq) == hubAID
		}
		return false
	}
}

// witnessBefore is the witness named by the last rot of kel before seq, ""
// for none (an icp never names one).
func witnessBefore(kel []identity.SignedEvent, seq uint64) string {
	w := ""
	for _, se := range kel {
		if se.Event.Seq >= seq {
			break
		}
		if se.Event.Type == identity.Rotation && len(se.Event.Witnesses) > 0 {
			w = se.Event.Witnesses[0]
		}
	}
	return w
}

// noticeAnswer is what an answer to aid says about its witness notice: the
// notice (base64url), or why there is none (KEL H-5, H-13). When the store
// fails the answer says nothing either way, and the failure is logged: the
// request it answers took effect.
func (s *Server) noticeAnswer(aid string) (notice, why string) {
	n, why, err := s.store.NoticeFor(aid)
	if err != nil {
		log.Printf("hub: the witness notice of %s: %v", aid, err)
		return "", ""
	}
	if n != nil {
		return wire3.EncodeB64URL(n), ""
	}
	return "", why
}

// KELPushResult is what PushKEL did: the tip of the key history held now,
// and whether anything changed.
type KELPushResult struct {
	Seq       uint64
	Head      string
	Unchanged bool
	// Deregistered: the history ends in a dip and the agent, registered
	// until now, was deregistered (DeregDip).
	Deregistered bool
}

// errNoKEL is PushKEL's answer for an AID it holds no key history for.
var errNoKEL = errors.New("hub: this hub holds no key history for that AID")

// registrationKEL is the key history this hub holds for aid from a
// registration, as stored: the agent row (registered), else the tombstone in
// departed_kel; nil when there is neither.
func (s *Store) registrationKEL(aid string) (kel []byte, registered bool, err error) {
	err = s.db.QueryRow(`SELECT kel FROM agent WHERE aid=?`, aid).Scan(&kel)
	if err == nil {
		return kel, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	err = s.db.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, aid).Scan(&kel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return kel, false, err
}

// holdsKEL reports whether this hub holds a key history for aid: a
// registration, or the tombstone of one.
func (s *Store) holdsKEL(aid string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM agent WHERE aid = ? UNION ALL SELECT 1 FROM departed_kel WHERE aid = ? LIMIT 1`,
		aid, aid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// PushKEL takes kel for aid, which it replays to: when it extends the key
// history held here, it replaces it in one transaction (see the route's step
// 9), in its CoreDet encoding. It returns errNoKEL for an AID with no history here,
// an error wrapping ErrKELNotExtended (with identity.ErrKELFork or
// ErrKELRollback) for one that does not extend it, and one wrapping
// identity.ErrEventFromFuture or ErrEventTooOld for a new event outside the
// clock window (R-9, R-10, with this hub as the witness of the events that
// name it).
func (s *Store) PushKEL(aid string, kel []identity.SignedEvent) (KELPushResult, error) {
	now := s.now()
	s.mu.Lock()
	res, registered, err := s.pushKELLocked(aid, kel, now)
	s.mu.Unlock()
	if err != nil || res.Unchanged {
		return res, err
	}
	switch {
	case res.Deregistered:
		s.afterDereg(aid)
	case registered:
		s.runKELHooks(aid)
		// A card signed by the key this history retired is delisted
		// (KEL H-2), as on a registration.
		if err := s.recheckA2ACard(aid, kel, now); err != nil {
			log.Printf("hub: re-verifying the A2A card of %s after a pushed key history: %v", aid, err)
		}
	}
	return res, nil
}

func (s *Store) pushKELLocked(aid string, kel []identity.SignedEvent, now time.Time) (res KELPushResult, registered bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return res, false, err
	}
	defer tx.Rollback()
	var heldRaw []byte
	switch err := tx.QueryRow(`SELECT kel FROM agent WHERE aid=?`, aid).Scan(&heldRaw); {
	case err == nil:
		registered = true
	case errors.Is(err, sql.ErrNoRows):
		if err := tx.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, aid).Scan(&heldRaw); errors.Is(err, sql.ErrNoRows) {
			return res, false, errNoKEL
		} else if err != nil {
			return res, false, err
		}
	default:
		return res, false, err
	}
	held, err := identity.UnmarshalKEL(heldRaw)
	if err != nil {
		return res, registered, fmt.Errorf("hub: the key history held for %s does not decode: %w", aid, err)
	}
	if err := identity.ExtendsKEL(held, kel); err != nil {
		return res, registered, fmt.Errorf("%w: %w", ErrKELNotExtended, err)
	}
	last := kel[len(kel)-1]
	res.Seq, res.Head = last.Event.Seq, last.EventID
	if len(kel) == len(held) {
		res.Unchanged = true
		return res, registered, nil
	}
	if err := identity.CheckNewEvents(held, kel, uint64(now.UnixMilli()), firstWitness(kel, s.hubAID)); err != nil {
		return res, registered, err
	}
	// Stored in its CoreDet encoding (each event's own bytes are checked
	// to be CoreDet when it is decoded; the array around them is written
	// again here).
	raw, err := identity.MarshalKEL(kel)
	if err != nil {
		return res, registered, err
	}
	if registered {
		tipSeq, tipHead := storedTip(raw)
		if _, err := tx.Exec(`UPDATE agent SET kel=?, tip_seq=?, tip_head=? WHERE aid=?`, raw, tipSeq, tipHead, aid); err != nil {
			return res, registered, err
		}
		if err := countKELChangeTx(tx); err != nil {
			return res, registered, err
		}
		if last.Event.Type == identity.Deactivation {
			// DeregisterTx keeps the history it finds in the row, the one
			// just written, as the tombstone, and with the rest of the
			// agent's rows deletes its notice (deregSteps).
			if _, err := DeregisterTx(tx, aid, DeregDip); err != nil {
				return res, registered, err
			}
			res.Deregistered = true
		} else {
			if err := kelChangedTx(tx, aid, raw); err != nil {
				return res, registered, err
			}
			// A longer key history than the one held: a restore
			// quarantine ends for this AID (KEL H-20 a).
			if err := releaseTx(tx, aid, releasedLongerKEL, now); err != nil {
				return res, registered, err
			}
			if err := s.refreshDirTx(tx, aid); err != nil {
				return res, registered, err
			}
		}
	} else if err := writeTombstone(tx, aid, raw, now); err != nil {
		return res, registered, err
	}
	if err := tx.Commit(); err != nil {
		return res, registered, err
	}
	s.syncKELHighWater()
	return res, registered, nil
}
