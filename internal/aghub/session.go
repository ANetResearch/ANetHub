package aghub

import (
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// First-contact sessions (sealed-sender §2.6, §4.2.3; core L7, L8).
//
// A first contact (outer access kind 0) is the one send in which this hub
// learns who is sending: the sender opens a session with its signature
// (relayauth action "session"), and each send of the session carries a MAC
// under a key only the sender and this hub hold. The MAC authenticates the
// sender to this hub and to nobody else: the hub can compute it as well, so
// it is no evidence a third party would accept. Later messages travel under
// a delivery credential the recipient issued, and name no sender at all.
//
// A session lives an hour, in this process's memory only. Neither it nor
// the AID it belongs to is written to the database, a log, a metric label or
// the admin console (SSR-H7): a restart ends every session. An AID holds at
// most MaxSessionsPerAID at once (a new one ends the oldest) and opens at
// most MaxSessionOpensPerHour in any hour. A rotation of its key, the end of
// its key history, its deregistration and the revocation of its admission
// end its sessions and empty its send bucket at once (SSR-H9).

// Session constants (sealed-sender §2.12, SSR-W13). Code constants, not
// configuration.
const (
	// SessionLifetime is how long a session is valid after it was opened.
	SessionLifetime = time.Hour
	// MaxSessionsPerAID is how many sessions one AID holds at once.
	MaxSessionsPerAID = 4
	// MaxSessionOpensPerHour is how many sessions one AID may open in any
	// hour.
	MaxSessionOpensPerHour = 30
	// SessionSkew bounds how far X-ANet-TS of a session send may be from
	// this hub's clock (SSR-W14).
	SessionSkew = 5 * time.Minute
	// sessionBodyLimit caps a POST /relay/session body: one key in JSON.
	sessionBodyLimit = 4 << 10
)

// SessionRequest is the POST /relay/session body (core §2.12.2): the
// sender's one-time X25519 public key, base64url.
type SessionRequest struct {
	EPK string `json:"epk"`
}

// SessionResponse is the POST /relay/session answer: the session id, when it
// ends (unix ms), and the session key sealed to epk (core L7), all binary
// values base64url.
type SessionResponse struct {
	SID string `json:"sid"`
	Exp uint64 `json:"exp"`
	Enc string `json:"enc"`
	CT  string `json:"ct"`
}

// hubSession is one open session.
type hubSession struct {
	sid [relayauth.SessionIDLen]byte
	aid string
	key []byte
	exp time.Time
}

// sessionTable is every open session of this hub process, and when each AID
// opened its sessions of the last hour.
type sessionTable struct {
	mu    sync.Mutex
	bySID map[[relayauth.SessionIDLen]byte]*hubSession
	// byAID holds each AID's sessions, oldest first.
	byAID map[string][]*hubSession
	// opens holds when each AID opened a session, within the last hour,
	// oldest first.
	opens map[string][]time.Time
	swept time.Time
}

func newSessionTable() *sessionTable {
	return &sessionTable{
		bySID: map[[relayauth.SessionIDLen]byte]*hubSession{},
		byAID: map[string][]*hubSession{},
		opens: map[string][]time.Time{},
	}
}

// sweepLocked drops the sessions that ended and the opens older than an
// hour, at most once a minute.
func (t *sessionTable) sweepLocked(now time.Time) {
	if now.Sub(t.swept) < time.Minute {
		return
	}
	t.swept = now
	for aid := range t.byAID {
		t.pruneLocked(aid, now)
	}
	for aid := range t.opens {
		t.recentOpensLocked(aid, now)
	}
}

// pruneLocked drops aid's sessions that ended by now.
func (t *sessionTable) pruneLocked(aid string, now time.Time) {
	live := t.byAID[aid][:0]
	for _, s := range t.byAID[aid] {
		if now.Before(s.exp) {
			live = append(live, s)
		} else {
			delete(t.bySID, s.sid)
		}
	}
	if len(live) == 0 {
		delete(t.byAID, aid)
		return
	}
	t.byAID[aid] = live
}

// recentOpensLocked is aid's opens of the hour before now.
func (t *sessionTable) recentOpensLocked(aid string, now time.Time) []time.Time {
	all := t.opens[aid]
	i := 0
	for i < len(all) && !now.Before(all[i].Add(time.Hour)) {
		i++
	}
	if i == len(all) {
		delete(t.opens, aid)
		return nil
	}
	if i > 0 {
		all = append(all[:0], all[i:]...)
		t.opens[aid] = all
	}
	return all
}

// openWait is how long aid must wait before it may open a session: 0 when
// it may now.
func (t *sessionTable) openWait(aid string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.openWaitLocked(aid, now)
}

func (t *sessionTable) openWaitLocked(aid string, now time.Time) time.Duration {
	recent := t.recentOpensLocked(aid, now)
	if len(recent) < MaxSessionOpensPerHour {
		return 0
	}
	return recent[len(recent)-MaxSessionOpensPerHour].Add(time.Hour).Sub(now)
}

// open records a new session of aid with id sid and key, ending the oldest
// when aid already holds MaxSessionsPerAID. It refuses (returning the wait)
// when aid opened MaxSessionOpensPerHour sessions in the last hour.
func (t *sessionTable) open(aid string, sid [relayauth.SessionIDLen]byte, key []byte, now time.Time) (*hubSession, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	if wait := t.openWaitLocked(aid, now); wait > 0 {
		return nil, wait
	}
	t.pruneLocked(aid, now)
	held := t.byAID[aid]
	for len(held) >= MaxSessionsPerAID {
		delete(t.bySID, held[0].sid)
		held = held[1:]
	}
	s := &hubSession{sid: sid, aid: aid, key: key, exp: now.Add(SessionLifetime)}
	t.bySID[sid] = s
	t.byAID[aid] = append(append([]*hubSession(nil), held...), s)
	t.opens[aid] = append(t.opens[aid], now)
	return s, 0
}

// get is the session sid names, if it is open at now.
func (t *sessionTable) get(sid []byte, now time.Time) (*hubSession, bool) {
	if len(sid) != relayauth.SessionIDLen {
		return nil, false
	}
	var k [relayauth.SessionIDLen]byte
	copy(k[:], sid)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
	s, ok := t.bySID[k]
	if !ok || !now.Before(s.exp) {
		return nil, false
	}
	return s, true
}

// drop ends every session of aid. It keeps aid's opens: ending a session
// does not give back the opening.
func (t *sessionTable) drop(aid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.byAID[aid] {
		delete(t.bySID, s.sid)
	}
	delete(t.byAID, aid)
}

// count is how many sessions aid holds at now. Tests read it.
func (t *sessionTable) count(aid string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(aid, now)
	return len(t.byAID[aid])
}

// dropSessions ends aid's sessions and empties its session send bucket: the
// next send of aid opens a new session and starts with a full bucket
// (SSR-H9). Registered with the store for deregistrations and key events.
func (s *Server) dropSessions(aid string) {
	s.relay.sessions.drop(aid)
	s.relay.sessionSend.forget(aid)
}

// hRelaySession is POST /relay/session (SSR-H6), in this order:
//
//	0 X-ANet-Wire (wire3.Contract, before this handler)
//	1 the relayauth headers; a signer not registered here is not admitted:
//	  403 admission_required
//	2 relayauth "session": the signature and RC1 (401)
//	3 fewer than MaxSessionOpensPerHour opens in the last hour, or 429
//	  rate_limited with Retry-After
//	4 the body: {epk}, decoded strictly, a 32-byte base64url X25519 key
//	5 a new random sid and session key; the key sealed to epk (core L7)
//
// Nothing is written to disk, and the answer is the same whether or not
// the AID already holds sessions.
func (s *Server) hRelaySession(w http.ResponseWriter, r *http.Request) {
	a, err := parseV2Headers(r)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: sentence(err)})
		return
	}
	// An AID is admitted here exactly while it is registered here (an
	// admission revoked is a deregistration, hub-payment-privacy PAY-O1).
	// The signature cannot be checked without the registration's key
	// history, and whether an AID is registered is public (GET /agents).
	if !ValidAID(a.AID) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: relayauth.HeaderAID + " is not an AID; sign as the agent that opens the session."})
		return
	}
	registered, err := s.store.agentRegistered(a.AID)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	if !registered {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonAdmissionRequired, Extra: map[string]any{"aid": a.AID}})
		return
	}
	au, ok := s.authRegistered(w, r, relayauth.ActionSession, sessionBodyLimit)
	if !ok {
		return
	}
	now := s.store.now()
	if wait := s.relay.sessions.openWait(au.AID, now); wait > 0 {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
			Error: "This agent opened too many first-contact sessions in the last hour; retry after Retry-After."})
		return
	}
	var req SessionRequest
	if err := wire3.DecodeStrict(au.Body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	epk, err := wire3.DecodeB64URLSize("epk", req.EPK, relayauth.SessionPublicKeyLen)
	if err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	var sid [relayauth.SessionIDLen]byte
	key := make([]byte, relayauth.SessionKeyLen)
	if _, err := rand.Read(sid[:]); err != nil {
		wire3.Internal(w, err)
		return
	}
	if _, err := rand.Read(key); err != nil {
		wire3.Internal(w, err)
		return
	}
	enc, ct, err := relayauth.SealSessionKey(epk, s.hubAID, sid[:], key)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest,
			Error: "The member \"epk\" is not a usable X25519 public key; send a newly generated one."})
		return
	}
	sess, wait := s.relay.sessions.open(au.AID, sid, key, now)
	if sess == nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait,
			Error: "This agent opened too many first-contact sessions in the last hour; retry after Retry-After."})
		return
	}
	writeJSON(w, http.StatusOK, SessionResponse{
		SID: wire3.EncodeB64URL(sid[:]), Exp: uint64(sess.exp.UnixMilli()),
		Enc: wire3.EncodeB64URL(enc), CT: wire3.EncodeB64URL(ct)})
}
