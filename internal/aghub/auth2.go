package aghub

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
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
// A signature is additionally accepted once. The replay cache remembers
// every accepted (AID, signature) until the end of its skew window, after
// which the timestamp check refuses it anyway. A client that retries a
// request must sign it again.

// errNoAuthHeaders is the refusal for a request without v2 headers, which
// is what a wire-1 daemon sends.
var errNoAuthHeaders = errors.New("relay v2 authentication headers " +
	relayauth.HeaderAID + ", " + relayauth.HeaderTS + ", " + relayauth.HeaderSeq + ", " +
	relayauth.HeaderSig + " are required; this hub speaks wire 2 and needs anet >= 0.2.0")

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

// parseV2Headers reads and syntax-checks the authentication headers. The
// numbers must be in canonical decimal form so that each request has one
// accepted spelling.
func parseV2Headers(r *http.Request) (v2Auth, error) {
	aid, ok1 := singleHeader(r, relayauth.HeaderAID)
	ts, ok2 := singleHeader(r, relayauth.HeaderTS)
	seq, ok3 := singleHeader(r, relayauth.HeaderSeq)
	sig, ok4 := singleHeader(r, relayauth.HeaderSig)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return v2Auth{}, errNoAuthHeaders
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

// replayCache remembers accepted signatures until their window ends.
//
// Keys are the first 16 bytes of SHA-256(aid ‖ 0x00 ‖ sig), which keeps an
// entry at a fixed small size; a collision would need a second preimage of
// a 128-bit truncation. The cache is bounded: when it holds max live
// entries, new requests are refused (503) rather than older entries being
// evicted, because eviction would re-admit the evicted signatures.
type replayCache struct {
	mu    sync.Mutex
	seen  map[[16]byte]int64 // key -> window end, unix ms
	max   int
	swept int64
}

// defaultReplayCacheMax bounds the replay cache. At about 40 bytes per
// entry this is some 40 MiB, and at the longest window (ts up to MaxSkew
// in the future plus MaxSkew after it, 10 minutes) it admits about 1,600
// signed requests per second sustained.
const defaultReplayCacheMax = 1 << 20

func newReplayCache(max int) *replayCache {
	return &replayCache{seen: map[[16]byte]int64{}, max: max}
}

var errReplayed = errors.New("this signature was already used; sign each request anew")

var errReplayCacheFull = errors.New("replay cache full; retry later")

// admit records a signature. It fails when the signature was seen before
// within its window, or when the cache is full.
func (c *replayCache) admit(aid string, sig []byte, windowEnd, now int64) error {
	h := sha256.New()
	h.Write([]byte(aid))
	h.Write([]byte{0})
	h.Write(sig)
	var key [16]byte
	copy(key[:], h.Sum(nil))

	c.mu.Lock()
	defer c.mu.Unlock()
	// Expired entries are swept every 10 seconds, and sooner when the
	// cache is full, but at most once a second: a sweep walks every entry,
	// and sweeping on each request while the cache is full of live entries
	// would cost a full walk per refused request.
	if now-c.swept > 10_000 || (len(c.seen) >= c.max && now-c.swept > 1000) {
		for k, end := range c.seen {
			if end < now {
				delete(c.seen, k)
			}
		}
		c.swept = now
	}
	if end, ok := c.seen[key]; ok && end >= now {
		return errReplayed
	}
	if len(c.seen) >= c.max {
		return errReplayCacheFull
	}
	c.seen[key] = windowEnd
	return nil
}

// authFailure is a refusal with its HTTP status.
type authFailure struct {
	code int
	err  error
}

func (f *authFailure) Error() string { return f.err.Error() }

func unauthorized(format string, args ...any) *authFailure {
	return &authFailure{code: http.StatusUnauthorized, err: fmt.Errorf(format, args...)}
}

// verifyV2 checks a parsed header tuple against kel for one request.
//
// The order is: time window, signature, then the replay cache. The cache
// is written only for a valid signature, so an unauthenticated caller
// cannot fill it.
func (s *Server) verifyV2(r *http.Request, action string, body []byte, a v2Auth, kel []identity.SignedEvent) *authFailure {
	if s.hubAID == "" {
		return &authFailure{code: http.StatusServiceUnavailable,
			err: errors.New("this hub has no identity; relay v2 signatures bind the hub AID")}
	}
	now := time.Now().UnixMilli()
	skew := now - int64(a.TS)
	if skew < 0 {
		skew = -skew
	}
	if a.TS > uint64(1)<<62 || skew > relayauth.MaxSkewMillis {
		return unauthorized("%s is outside the ±%d ms window", relayauth.HeaderTS, relayauth.MaxSkewMillis)
	}
	pre := relayauth.PreimageV2(action, a.AID, s.hubAID, a.TS, r.Method, r.URL.RequestURI(), body)
	if err := identity.VerifyObject(kel, a.AID, a.Seq, a.TS, pre, a.Sig); err != nil {
		return unauthorized("signature does not verify for action %q: %v", action, err)
	}
	if err := s.replay.admit(a.AID, a.Sig, int64(a.TS)+relayauth.MaxSkewMillis, now); err != nil {
		if errors.Is(err, errReplayCacheFull) {
			return &authFailure{code: http.StatusServiceUnavailable, err: err}
		}
		return unauthorized("%v", err)
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

// authed is an authenticated request: the signer and the raw body.
type authed struct {
	AID  string
	Body []byte
}

// authRegistered authenticates a request from an agent registered here,
// against its stored KEL. On failure it writes the response and returns
// false.
//
// The headers are checked, and the signer looked up, before the body is
// read, so a request without authentication or from an unknown signer is
// refused without this hub buffering its body.
func (s *Server) authRegistered(w http.ResponseWriter, r *http.Request, action string, limit int64) (authed, bool) {
	a, err := parseV2Headers(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return authed{}, false
	}
	kelBytes, err := s.store.AgentKEL(a.AID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "the signer " + a.AID + " is not registered here"})
		return authed{}, false
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stored kel corrupt"})
		return authed{}, false
	}
	body, f := readRawBody(w, r, limit)
	if f != nil {
		writeJSON(w, f.code, map[string]string{"error": f.Error()})
		return authed{}, false
	}
	if f := s.verifyV2(r, action, body, a, kel); f != nil {
		writeJSON(w, f.code, map[string]string{"error": f.Error()})
		return authed{}, false
	}
	return authed{AID: a.AID, Body: body}, true
}

// authSelf is authRegistered for an endpoint that acts on the AID in its
// path: the signer must be that AID.
func (s *Server) authSelf(w http.ResponseWriter, r *http.Request, action string, limit int64) (authed, bool) {
	aid := r.PathValue("aid")
	if hdr, ok := singleHeader(r, relayauth.HeaderAID); ok && hdr != aid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": relayauth.HeaderAID + " does not name the agent in the path; an agent acts only on itself"})
		return authed{}, false
	}
	return s.authRegistered(w, r, action, limit)
}

// signedBodyLimit caps the body of every signed endpoint other than
// /relay/send and /register.
const signedBodyLimit = 1 << 20
