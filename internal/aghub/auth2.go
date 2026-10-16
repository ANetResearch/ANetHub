package aghub

import (
	"cmp"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// relayauth v2 (A2A-DESIGN §3.7, [C31]).
//
// Every signed endpoint carries its authentication in four headers,
// X-ANet-AID, X-ANet-TS, X-ANet-Seq and X-ANet-Sig, and the signature
// covers relayauth.PreimageV2: the action, the signer, this hub's AID, the
// time, and a hash of the method, the request target and the raw body.
// The hub reads the body under the endpoint's size cap before decoding
// it, hashes exactly those bytes, and only then decodes. Compared with the
// wire-1 challenge (action, AID and time in the JSON body) this binds a
// signature to one request on one hub: it cannot be replayed against
// another hub, used for another action, or attached to a different body,
// path or query.
//
// A signed request is additionally accepted once, by its signer's time
// (RC1, below): each signer's X-ANet-TS values are taken at most once each,
// and never at or below the floor this hub keeps for the signer. A client
// that retries a request signs it again, at a later time; a client hands
// out its times per hub from relayauth.MonoClock, so two of its requests
// never share one.

// errNoAuthHeaders is the refusal for a request without v2 headers, which
// is what a wire-1 daemon sends.
var errNoAuthHeaders = errors.New("relay v2 authentication headers " +
	relayauth.HeaderAID + ", " + relayauth.HeaderTS + ", " + relayauth.HeaderSeq + ", " +
	relayauth.HeaderSig + " are required; this hub speaks wire " + strconv.Itoa(wireVersion) +
	" and needs anet >= " + RequiredAnet)

// v2Auth is the parsed header tuple of one request.
type v2Auth struct {
	AID string
	TS  uint64
	Seq uint64
	Sig []byte
}

// singleHeader returns the one value of a header, or false when it is
// absent or repeated. A repeated header would leave it open which value
// was signed.
func singleHeader(r *http.Request, name string) (string, bool) {
	vs := r.Header.Values(name)
	if len(vs) != 1 || vs[0] == "" {
		return "", false
	}
	return vs[0], true
}

// errSignerNotAnAID is the refusal of an X-ANet-AID that is not an AID.
var errSignerNotAnAID = errors.New(relayauth.HeaderAID +
	" is not an AID; sign the request as the agent's own AID, the one anet prints")

// parseV2Headers reads and syntax-checks the authentication headers. The
// numbers must be in canonical decimal form so that each request has one
// accepted spelling.
//
// The signer must be an AID in its one spelling (ValidAID, the test every
// party applies, KEL R-3). A header that is not one is refused here, as 401
// unauthorized (hub-payment-privacy PAY-R3), before this hub looks the
// signer up, reads the body, checks a signature or asks RC1: a string that
// names nobody gets no state in this hub and costs it nothing.
func parseV2Headers(r *http.Request) (v2Auth, error) {
	aid, ok1 := singleHeader(r, relayauth.HeaderAID)
	ts, ok2 := singleHeader(r, relayauth.HeaderTS)
	seq, ok3 := singleHeader(r, relayauth.HeaderSeq)
	sig, ok4 := singleHeader(r, relayauth.HeaderSig)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return v2Auth{}, errNoAuthHeaders
	}
	if !ValidAID(aid) {
		return v2Auth{}, errSignerNotAnAID
	}
	var a v2Auth
	a.AID = aid
	var err error
	if a.TS, err = strconv.ParseUint(ts, 10, 64); err != nil || strconv.FormatUint(a.TS, 10) != ts {
		return v2Auth{}, fmt.Errorf("%s is not a canonical decimal unix-millisecond time", relayauth.HeaderTS)
	}
	if a.Seq, err = strconv.ParseUint(seq, 10, 64); err != nil || strconv.FormatUint(a.Seq, 10) != seq {
		return v2Auth{}, fmt.Errorf("%s is not a canonical decimal key_state_seq", relayauth.HeaderSeq)
	}
	if a.Sig, err = relayauth.DecodeSig(sig); err != nil {
		return v2Auth{}, err
	}
	return a, nil
}

// ---- RC1 (hub-payment-privacy §4.2.5, PAY-R2 to PAY-R8; core G17) ----
//
// For each signer this hub keeps a floor, the times it accepted above the
// floor (recent, at most K of them) and the largest time it accepted
// (maxSeen). A request whose signature verified is accepted when its time
// is within MaxSkew of this hub's clock, above the floor and not in recent
// (PAY-R2). Accepting it, under the signer's lock and in the same step as
// the check (PAY-R5): insert the time; raise the floor to maxSeen − W, so
// requests may arrive out of order by up to W; and when recent then holds
// more than K times, raise the floor to the smallest and drop it.
//
// No signer's state depends on any other's: there is no pool shared by the
// signers and no share of one. The per-signature cache this replaces had
// one, and a signer refused at its even share of a full cache was refused
// for what others had signed [redteam:F4]. K bounds one signer's state; a
// signer that signs faster only raises its own floor. The whole is bounded
// by a valve that makes the longest-idle signers strictly monotonic rather
// than refusing anybody (PAY-R7): replay state never makes this hub answer
// 503 or 429.
//
// A signer's state is dropped once everything it ever had accepted is
// older than MaxSkew (PAY-R6), when the time window alone refuses all of
// it, and never by when the signer was last active: a time signed up to
// MaxSkew ahead stays inside the window for up to twice MaxSkew. What is
// dropped leaves its top behind as the floor of every signer without state
// in its part (gone), which is also where a part starts: just before the
// time this state was made. A hub clock that steps back therefore does not
// reopen the window for a request accepted before, and after a restart a
// request signed before the hub started is not accepted again. The state
// is only in memory (hub-payment-privacy §3.3), so a restart does forget
// the times it accepted after the start: a request signed ahead of the
// hub's clock and accepted before a restart can be accepted once more
// after it, until its time leaves the window.

// RC1 constants (hub-payment-privacy §0.4; core G17). Code constants, not
// configuration.
const (
	// rc1W is the out-of-order window W, in ms: a signer's floor follows
	// its largest accepted time at this distance.
	rc1W = 30_000
	// rc1KNew is K for a signer not registered here (a newcomer's
	// /register) and for an account on probation.
	rc1KNew = 16
	// rc1KAgent is K for a registered agent past its probation.
	rc1KAgent = 64
	// rc1KPeerHub is K for a peer hub signing a /fed/v3 request.
	rc1KPeerHub = 4096
	// rc1MemHigh and rc1MemLow are the valve: past High the oldest signers
	// lose their recent times until the state is below Low.
	rc1MemHigh = 256 << 20
	rc1MemLow  = 224 << 20
	// rc1Shards is the number of independently locked parts of the state.
	rc1Shards = 64
	// rc1SweepEvery is how often (ms) a part is swept for signers to drop.
	rc1SweepEvery = 10_000
	// rc1ValveEvery is how soon (ms) the valve runs again after it could not
	// bring the state below Low (every signer was already monotonic).
	rc1ValveEvery = 1_000
	// rc1ValveLogEvery is how often (ms) at most that is logged.
	rc1ValveLogEvery = 60_000
	// rc1SignerBytes estimates one signer's state without its times and
	// AID: the map slot, the state and the slice header.
	rc1SignerBytes = 96
)

// rc1Verdict is what RC1 says about one signed time.
type rc1Verdict int

const (
	rc1Accepted rc1Verdict = iota
	// rc1Outside: more than MaxSkew from this hub's clock (unauthorized).
	rc1Outside
	// rc1Stale: at or below the floor (ts_stale, with the floor).
	rc1Stale
	// rc1Replayed: accepted before (replayed).
	rc1Replayed
)

// rc1State is RC1 for every signer of this hub.
type rc1State struct {
	shards []rc1Shard
	seed   maphash.Seed
	// bytes estimates the memory the signers' states take.
	bytes atomic.Int64
	// high and low are the valve (rc1MemHigh, rc1MemLow; smaller in tests).
	high, low int64
	// valving is held by the one goroutine running the valve; nextValve is
	// the earliest hub time (ms) it runs again after it fell short, and
	// logged when (hub ms) it last said so.
	valving   atomic.Bool
	nextValve atomic.Int64
	logged    atomic.Int64
	// next is the part the next accepted request also sweeps when due, so
	// that every part is swept while requests come in, whoever signs them.
	next atomic.Uint32
}

// rc1Shard is one part of the state, under one lock. A signer's lock is
// its part's: the check and the insertion are one step under it.
type rc1Shard struct {
	mu      sync.Mutex
	signers map[string]*rc1Signer
	// gone is the floor of a signer without state here: the largest top
	// of the signers dropped from this part, and at least the millisecond
	// before the state was made.
	gone uint64
	// swept is when (hub ms) this part was last swept.
	swept int64
}

// rc1Signer is one signer's state (PAY-R4).
type rc1Signer struct {
	floor   uint64
	maxSeen uint64
	// recent holds the accepted times above floor, ascending.
	recent []uint64
}

// newRC1 makes the RC1 state at hub time now (ms) with the given number of
// parts and valve. A time signed before now is refused (ts_stale, with the
// floor now − 1), so a request accepted before this state existed is not
// accepted again when it was signed before now; one signed later than now
// is not known here.
func newRC1(now int64, shards int, high, low int64) *rc1State {
	r := &rc1State{shards: make([]rc1Shard, shards), seed: maphash.MakeSeed(), high: high, low: low}
	for i := range r.shards {
		r.shards[i].signers = map[string]*rc1Signer{}
		r.shards[i].gone = uint64(max(now-1, 0))
		r.shards[i].swept = now
	}
	return r
}

func (r *rc1State) shard(aid string) *rc1Shard {
	return &r.shards[maphash.String(r.seed, aid)%uint64(len(r.shards))]
}

// rc1InWindow reports whether ts is within MaxSkew of now (PAY-R2 2). A ts
// above 2^62 is refused before the difference is taken: int64(ts) would
// overflow for one 2^63 away.
func rc1InWindow(ts uint64, now int64) bool {
	if ts > uint64(1)<<62 {
		return false
	}
	skew := now - int64(ts)
	if skew < 0 {
		skew = -skew
	}
	return skew <= relayauth.MaxSkewMillis
}

// signerBytes is the estimated memory of one signer's state.
func signerBytes(aid string, s *rc1Signer) int64 {
	return int64(rc1SignerBytes + len(aid) + 8*cap(s.recent))
}

// accept is PAY-R2 2 and 3 and PAY-R5 for one signed time of aid, whose
// signature verified, with recent-set capacity k, at hub time now (ms). It
// returns the verdict and, for rc1Stale, the floor.
func (r *rc1State) accept(aid string, ts uint64, k int, now int64) (rc1Verdict, uint64) {
	sh := r.shard(aid)
	sh.mu.Lock()
	v, floor := r.acceptLocked(sh, aid, ts, k, now)
	if now-sh.swept >= rc1SweepEvery {
		r.sweepLocked(sh, now)
	}
	sh.mu.Unlock()
	r.sweepNext(now)
	r.relieve(now)
	return v, floor
}

func (r *rc1State) acceptLocked(sh *rc1Shard, aid string, ts uint64, k int, now int64) (rc1Verdict, uint64) {
	if !rc1InWindow(ts, now) {
		return rc1Outside, 0
	}
	s := sh.signers[aid]
	if s == nil {
		if ts <= sh.gone {
			return rc1Stale, sh.gone
		}
		s = &rc1Signer{floor: sh.gone}
		sh.signers[aid] = s
		r.bytes.Add(signerBytes(aid, s))
	}
	if ts <= s.floor {
		return rc1Stale, s.floor
	}
	i, seen := slices.BinarySearch(s.recent, ts)
	if seen {
		return rc1Replayed, 0
	}
	before := signerBytes(aid, s)
	s.recent = slices.Insert(s.recent, i, ts)
	s.maxSeen = max(s.maxSeen, ts)
	if s.maxSeen > rc1W && s.maxSeen-rc1W > s.floor {
		s.raiseFloor(s.maxSeen - rc1W)
	}
	for len(s.recent) > max(k, 1) {
		s.raiseFloor(s.recent[0])
	}
	r.bytes.Add(signerBytes(aid, s) - before)
	return rc1Accepted, 0
}

// raiseFloor sets the floor to f and drops the times at or below it.
func (s *rc1Signer) raiseFloor(f uint64) {
	s.floor = f
	j, _ := slices.BinarySearch(s.recent, f+1)
	n := copy(s.recent, s.recent[j:])
	s.recent = s.recent[:n]
}

// sweepLocked drops every signer of sh whose largest accepted time and
// floor are older than MaxSkew at now (PAY-R6); what it drops raises gone.
func (r *rc1State) sweepLocked(sh *rc1Shard, now int64) {
	sh.swept = now
	limit := now - relayauth.MaxSkewMillis
	if limit <= 0 {
		return
	}
	for aid, s := range sh.signers {
		if top := max(s.floor, s.maxSeen); top < uint64(limit) {
			sh.gone = max(sh.gone, top)
			delete(sh.signers, aid)
			r.bytes.Add(-signerBytes(aid, s))
		}
	}
}

// sweepNext sweeps the next part in turn when it is due and free.
func (r *rc1State) sweepNext(now int64) {
	sh := &r.shards[r.next.Add(1)%uint32(len(r.shards))]
	if !sh.mu.TryLock() {
		return
	}
	if now-sh.swept >= rc1SweepEvery {
		r.sweepLocked(sh, now)
	}
	sh.mu.Unlock()
}

// relieve is the valve (PAY-R7). Past high it first drops what may be
// dropped, then, by largest accepted time from the oldest, makes signers
// strictly monotonic (floor = maxSeen, no recent times) until the state is
// below low. Nobody is refused for it. A signer made monotonic has its
// next time accepted when it is above everything it signed before, which
// is what a MonoClock client sends; a request of it still in flight with
// an earlier time is answered ts_stale and signed again.
func (r *rc1State) relieve(now int64) {
	if r.bytes.Load() <= r.high || now < r.nextValve.Load() || !r.valving.CompareAndSwap(false, true) {
		return
	}
	defer r.valving.Store(false)
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		r.sweepLocked(sh, now)
		sh.mu.Unlock()
	}
	type idle struct {
		maxSeen uint64
		aid     string
		sh      *rc1Shard
	}
	var list []idle
	if r.bytes.Load() >= r.low {
		for i := range r.shards {
			sh := &r.shards[i]
			sh.mu.Lock()
			for aid, s := range sh.signers {
				if cap(s.recent) > 0 {
					list = append(list, idle{s.maxSeen, aid, sh})
				}
			}
			sh.mu.Unlock()
		}
		slices.SortFunc(list, func(a, b idle) int { return cmp.Compare(a.maxSeen, b.maxSeen) })
	}
	for _, c := range list {
		if r.bytes.Load() < r.low {
			break
		}
		c.sh.mu.Lock()
		if s := c.sh.signers[c.aid]; s != nil {
			before := signerBytes(c.aid, s)
			s.floor = max(s.floor, s.maxSeen)
			s.recent = nil
			r.bytes.Add(signerBytes(c.aid, s) - before)
		}
		c.sh.mu.Unlock()
	}
	if held := r.bytes.Load(); held >= r.low {
		r.nextValve.Store(now + rc1ValveEvery)
		if last := r.logged.Load(); last == 0 || now-last >= rc1ValveLogEvery {
			r.logged.Store(now)
			log.Printf("hub: replay state holds %d MiB with every signer strictly monotonic; nothing is refused for it",
				held>>20)
		}
	}
}

// rc1K is K for the signer of a request whose signature verified (PAY-R4:
// the class is known only then): 16 for an AID not registered here (only a
// newcomer's /register gets this far without a registration) or on
// probation (store.ProbationUntil), 64 for an agent.
func (s *Server) rc1K(aid, action string) int {
	if action == relayauth.ActionRegister && !s.store.KnowsAgent(aid) {
		return rc1KNew
	}
	if _, on := s.store.ProbationUntil(aid); on {
		return rc1KNew
	}
	return rc1KAgent
}

// ---- refusals and verification ----

// authFailure is a refusal of a signed request.
type authFailure struct {
	// code picks the reason: 401 (reason below), 413 too_large,
	// 400 bad_request, 500 internal.
	code int
	// reason, for a 401: unauthorized (empty), key_retired, ts_stale or
	// replayed.
	reason wire3.Reason
	err    error
	// floor is the signer's floor, for ts_stale.
	floor uint64
}

func (f *authFailure) Error() string {
	if f.err == nil {
		return string(f.reason)
	}
	return f.err.Error()
}

// writeAuthFailure answers a refusal with the wire-3 error body (core G1).
// ts_stale carries the floor as the member "floor" and as X-ANet-TS-Floor
// (HPP PAY-R3); it and replayed keep their default sentences (HPP §5.5).
func writeAuthFailure(w http.ResponseWriter, f *authFailure) {
	switch f.code {
	case http.StatusRequestEntityTooLarge:
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTooLarge, Error: sentence(f)})
	case http.StatusBadRequest:
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadRequest, Error: sentence(f)})
	case http.StatusInternalServerError:
		wire3.Internal(w, f)
	default:
		switch f.reason {
		case wire3.ReasonTSStale:
			w.Header().Set(headerTSFloor, strconv.FormatUint(f.floor, 10))
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonTSStale, Extra: map[string]any{"floor": f.floor}})
		case wire3.ReasonReplayed:
			wire3.Refuse(w, wire3.ReasonReplayed)
		case wire3.ReasonKeyRetired:
			wire3.Refuse(w, wire3.ReasonKeyRetired)
		default:
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: sentence(f)})
		}
	}
}

// headerTSFloor carries the floor of a ts_stale refusal (core §2.12.1).
const headerTSFloor = "X-ANet-TS-Floor"

func unauthorized(format string, args ...any) *authFailure {
	return &authFailure{code: http.StatusUnauthorized, err: fmt.Errorf(format, args...)}
}

// errOutsideWindow is the refusal of a time more than MaxSkew from this
// hub's clock.
var errOutsideWindow = fmt.Errorf("%s is more than %d minutes from this hub's clock; correct the system clock and sign again",
	relayauth.HeaderTS, relayauth.MaxSkewMillis/60_000)

// verifyV2 checks a parsed header tuple against kel for one request.
//
// The order is: time window, signature, then RC1. RC1 is asked only about
// a signature that verified under the tip of kel (PAY-R8): an
// unauthenticated caller adds no state and learns no floor, and neither
// does one signing with a key it has rotated away from (key_retired).
func (s *Server) verifyV2(r *http.Request, action string, body []byte, a v2Auth, kel []identity.SignedEvent) *authFailure {
	if s.hubAID == "" {
		return &authFailure{code: http.StatusInternalServerError,
			err: errors.New("this hub has no identity; relay v2 signatures bind the hub AID")}
	}
	now := time.Now().UnixMilli()
	if !rc1InWindow(a.TS, now) {
		return &authFailure{code: http.StatusUnauthorized, err: errOutsideWindow}
	}
	pre := relayauth.PreimageV2(action, a.AID, s.hubAID, a.TS, r.Method, r.URL.RequestURI(), body)
	if f := signatureFailure(action, a, pre, kel); f != nil {
		return f
	}
	return s.rc1Check(a, action, now)
}

// signatureFailure verifies a's signature over pre against kel. A request
// is signed under the tip of kel, while that tip is active (KEL H-3, core
// CORE-K16): only the identity's current key speaks for it now, with no
// grace for a key it has rotated away from. A signature that verifies
// under an earlier key state, one the signer has retired, is 401
// key_retired, which tells the signer to look at its key history;
// anything else (a key state past kel, a bad signature, a deactivated
// identity's own state) is 401 unauthorized.
//
// Checking the signature against the signing time instead, as an object's
// signature is (identity.VerifyObject at msgTime), would let a retired key
// sign requests for as long as the signing time may lie in the past
// (relayauth.MaxSkewMillis): a thief of the old key could keep polling the
// mailbox after the owner rotated.
func signatureFailure(action string, a v2Auth, pre []byte, kel []identity.SignedEvent) *authFailure {
	// The key the KEL names first, so that a bad signature does not cost a
	// replay of the signer's KEL (kelreplay.go) [redteam:F36].
	if verr := plausibleSignature(kel, a.Seq, pre, a.Sig); verr != nil {
		return unauthorized("signature does not verify for action %q: %v", action, verr)
	}
	states, err := identity.Replay(kel)
	if err != nil || states[len(states)-1].AID != a.AID {
		return unauthorized("signature does not verify for action %q: the key history does not replay to the signer", action)
	}
	if tip := states[len(states)-1]; a.Seq != tip.KeyStateSeq || tip.Status != identity.StatusActive {
		// plausibleSignature verified the signature under the key of
		// state a.Seq, which this replay holds: a key the signer had and
		// has since retired.
		return &authFailure{code: http.StatusUnauthorized, reason: wire3.ReasonKeyRetired,
			err: fmt.Errorf("signed at key state %d for action %q; the signer's key history is at %d", a.Seq, action, tip.KeyStateSeq)}
	}
	if err := identity.VerifyObject(kel, a.AID, a.Seq, a.TS, pre, a.Sig); err != nil {
		return unauthorized("signature does not verify for action %q: %v", action, err)
	}
	return nil
}

// rc1Check runs RC1 for a request whose signature verified.
func (s *Server) rc1Check(a v2Auth, action string, now int64) *authFailure {
	switch v, floor := s.replay.accept(a.AID, a.TS, s.rc1K(a.AID, action), now); v {
	case rc1Stale:
		return &authFailure{code: http.StatusUnauthorized, reason: wire3.ReasonTSStale, floor: floor}
	case rc1Replayed:
		return &authFailure{code: http.StatusUnauthorized, reason: wire3.ReasonReplayed}
	case rc1Outside:
		return &authFailure{code: http.StatusUnauthorized, err: errOutsideWindow}
	}
	return nil
}

// readRawBody reads the whole request body under limit. The body is read
// before anything is decoded because the signature covers these bytes.
func readRawBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, *authFailure) {
	body, err := readAllLimited(w, r, limit)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, &authFailure{code: http.StatusRequestEntityTooLarge,
				err: fmt.Errorf("request body exceeds %d bytes", limit)}
		}
		return nil, &authFailure{code: http.StatusBadRequest, err: fmt.Errorf("reading request body: %v", err)}
	}
	return body, nil
}

// readAllLimited reads r.Body, failing with *http.MaxBytesError past limit.
func readAllLimited(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

// authed is an authenticated request: the signer, the raw body, and the
// stored key history the signature was verified against.
type authed struct {
	AID  string
	Body []byte
	KEL  []byte
}

// authRegistered authenticates a request from an agent registered here,
// against its stored KEL. On failure it writes the response and returns
// false.
//
// The headers are checked, and the signer looked up, before the body is
// read, so a request without authentication or from an unknown signer is
// refused without this hub buffering its body.
//
// On success it also pays the account's trial credit when its probation is
// over and the credit is still pending (hub-payment-privacy PAY-A5): any
// signed request of the account is the moment to check, and the client's
// network is what the day's budget is counted on.
func (s *Server) authRegistered(w http.ResponseWriter, r *http.Request, action string, limit int64) (authed, bool) {
	a, err := parseV2Headers(r)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: sentence(err)})
		return authed{}, false
	}
	kelBytes, err := s.store.AgentKEL(a.AID)
	if err != nil {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: "The signer " + a.AID + " is not registered here; register first."})
		return authed{}, false
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		wire3.Internal(w, fmt.Errorf("the stored key history of %s does not decode: %w", a.AID, err))
		return authed{}, false
	}
	body, f := readRawBody(w, r, limit)
	if f != nil {
		writeAuthFailure(w, f)
		return authed{}, false
	}
	if f := s.verifyV2(r, action, body, a, kel); f != nil {
		writeAuthFailure(w, f)
		return authed{}, false
	}
	// Signed under the tip of the stored key history (H-3): after a
	// restore, that is what releases the AID once its wait is over (KEL
	// H-20 b), before the answer that may carry its notice.
	s.store.releaseOnCurrentKey(a.AID)
	if _, err := s.store.maybeGrantTrial(a.AID, clientAddr(r)); err != nil {
		log.Printf("hub: trial credit of %s: %v", a.AID, err)
	}
	return authed{AID: a.AID, Body: body, KEL: kelBytes}, true
}

// authSelf is authRegistered for an endpoint that acts on the AID in its
// path: the signer must be that AID.
func (s *Server) authSelf(w http.ResponseWriter, r *http.Request, action string, limit int64) (authed, bool) {
	aid := r.PathValue("aid")
	if hdr, ok := singleHeader(r, relayauth.HeaderAID); ok && !ValidAID(hdr) {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized, Error: sentence(errSignerNotAnAID)})
		return authed{}, false
	} else if ok && hdr != aid {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonUnauthorized,
			Error: relayauth.HeaderAID + " does not name the agent in the path; an agent acts only on itself."})
		return authed{}, false
	}
	return s.authRegistered(w, r, action, limit)
}

// signedBodyLimit caps the body of every signed endpoint other than
// /relay/send and /register.
const signedBodyLimit = 1 << 20
