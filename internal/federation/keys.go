package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// Federated key lookup: GET /fed/v2/keys/{aid} (A2A-DESIGN §3.9, [C32]).
//
// A sender on hub A that wants to seal a message to an agent registered on
// hub B needs B's copy of that agent's encryption key set. The card sync
// carries key sets only for agents that federate their card, and the
// default visibility is hub-local, so without this lookup a cross-hub
// delegation to a default-configured agent could not be encrypted.
//
// The endpoint answers for any AID registered on this hub, whatever its
// visibility, but only by exact AID and only to hubs in the peer table.
// The answer is self-authenticating (the key set is signed by the agent's
// KEL and the requester verifies it with the AID it asked for), so the
// answering hub vouches for nothing. The requesting hub relays the answer
// to the daemon that asked and does not store it: it does not enter any
// directory, listing or index. What this discloses to a peer hub is the
// key material of an AID it already names; whether an AID is registered
// here was already observable through /fed/v1/forward (404 versus 202).
//
// The request is signed by the origin hub with its hub identity, using
// the relayauth v2 header scheme and preimage (action "fedkeys", the
// answering hub's AID, method GET, the request target and an empty body),
// and verified against the origin's KEL pinned from its /hub/identity, the
// same trust anchor /fed/v1/forward uses.

// actionFedKeys is the relayauth v2 action of a /fed/v2/keys request. It
// is hub-to-hub only, so it is defined here rather than in ANetCore.
const actionFedKeys = "fedkeys"

// ErrNoKeys means no key set is held for the AID: KeySource.LocalKeys for
// an AID not registered here or registered without a key set, and
// LookupKeys when every peer answered 404.
var ErrNoKeys error = &seamError{msg: "federation: no key set for this AID", kind: seamNoKeys}

// KeySource is what the kernel supplies to answer /fed/v2/keys.
type KeySource interface {
	// LocalKeys returns the seal.SignedEncKeySet encoding and the KEL of
	// an AID registered on this hub, or an error wrapping ErrNoKeys.
	LocalKeys(aid string) (keyset, kel []byte, err error)
}

// SetKeySource wires the key lookup seam.
func (s *Service) SetKeySource(k KeySource) { s.keys = k }

// KeysAnswer is the /fed/v2/keys/{aid} response.
type KeysAnswer struct {
	KeySet string `json:"keyset"` // base64 (std) of the seal.SignedEncKeySet encoding
	KEL    string `json:"kel"`    // base64 (std) of identity.MarshalKEL
}

// maxKeysAnswer bounds a /fed/v2/keys response a requester reads: a key
// set is under 1 KiB and a KEL is capped at 64 KiB (seal.MaxKELBytes).
const maxKeysAnswer = 1 << 20

// hKeys serves GET /fed/v2/keys/{aid}.
func (s *Service) hKeys(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() || s.keys == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "delivery federation disabled")
		return
	}
	a, err := parseHubAuth(r)
	if err != nil {
		fedErr(w, http.StatusUnauthorized, "AUTH_REQUIRED", err.Error())
		return
	}
	peer := s.peer(a.aid)
	if peer == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "origin hub not in peer table")
		return
	}
	now := time.Now().UnixMilli()
	skew := now - int64(a.ts)
	if skew < 0 {
		skew = -skew
	}
	if a.ts > uint64(1)<<62 || skew > relayauth.MaxSkewMillis {
		fedErr(w, http.StatusUnauthorized, "INVALID_SIGNATURE", "request time outside the skew window")
		return
	}
	kel, err := s.peerKEL(peer)
	if err != nil {
		fedErr(w, http.StatusBadGateway, "POLICY_REFUSED", "peer kel unavailable: "+err.Error())
		return
	}
	pre := relayauth.PreimageV2(actionFedKeys, a.aid, s.id.AID, a.ts, r.Method, r.URL.RequestURI(), nil)
	if err := identity.VerifyObject(kel, a.aid, a.seq, a.ts, pre, a.sig); err != nil {
		fedErr(w, http.StatusUnauthorized, "INVALID_SIGNATURE", err.Error())
		return
	}
	if err := s.replay.admit(a.aid, a.sig, int64(a.ts)+relayauth.MaxSkewMillis, now); err != nil {
		if errors.Is(err, errReplayGuardFull) {
			fedErr(w, http.StatusServiceUnavailable, "BUSY", err.Error())
			return
		}
		fedErr(w, http.StatusUnauthorized, "REPLAYED", err.Error())
		return
	}
	keyset, agentKEL, err := s.keys.LocalKeys(r.PathValue("aid"))
	if errors.Is(err, ErrNoKeys) {
		fedErr(w, http.StatusNotFound, "NOT_FOUND", "no key set for this AID here")
		return
	}
	if err != nil {
		fedErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, KeysAnswer{
		KeySet: base64.StdEncoding.EncodeToString(keyset),
		KEL:    base64.StdEncoding.EncodeToString(agentKEL),
	})
}

// LookupKeys asks each peer, in peer-table order (the order TryForward
// uses), for aid's key set. accept is called on each answer; an answer it
// refuses is skipped. It returns the first accepted answer, an error
// wrapping ErrNoKeys when every peer answered 404, or the last other
// failure.
func (s *Service) LookupKeys(ctx context.Context, aid string,
	accept func(keyset, kel []byte) error) (keyset, kel []byte, peerAID string, err error) {
	if !s.Enabled() {
		return nil, nil, "", ErrNoKeys
	}
	var lastErr error
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		ks, kl, err := s.askKeys(ctx, p, aid)
		if errors.Is(err, ErrNoKeys) {
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		if accept != nil {
			if aerr := accept(ks, kl); aerr != nil {
				lastErr = fmt.Errorf("peer %s served a key set that was refused: %w", p.AID, aerr)
				continue
			}
		}
		return ks, kl, p.AID, nil
	}
	if lastErr != nil {
		return nil, nil, "", lastErr
	}
	return nil, nil, "", ErrNoKeys
}

// askKeys performs one signed /fed/v2/keys request to one peer.
func (s *Service) askKeys(ctx context.Context, p *Peer, aid string) (keyset, kel []byte, err error) {
	target := strings.TrimSuffix(p.Endpoint, "/") + "/fed/v2/keys/" + url.PathEscape(aid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	ts := uint64(time.Now().UnixMilli())
	pre := relayauth.PreimageV2(actionFedKeys, s.id.AID, p.AID, ts, http.MethodGet, req.URL.RequestURI(), nil)
	sig, seq := s.id.Sign(pre)
	req.Header.Set(relayauth.HeaderAID, s.id.AID)
	req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
	req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("peer %s: %w", p.AID, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysAnswer))
	if err != nil {
		return nil, nil, fmt.Errorf("peer %s: %w", p.AID, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil, ErrNoKeys
	default:
		return nil, nil, fmt.Errorf("peer %s: HTTP %d: %s", p.AID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var ans KeysAnswer
	if err := json.Unmarshal(body, &ans); err != nil {
		return nil, nil, fmt.Errorf("peer %s: malformed key answer: %w", p.AID, err)
	}
	if keyset, err = base64.StdEncoding.DecodeString(ans.KeySet); err != nil || len(keyset) == 0 {
		return nil, nil, fmt.Errorf("peer %s: key answer keyset not base64", p.AID)
	}
	if kel, err = base64.StdEncoding.DecodeString(ans.KEL); err != nil || len(kel) == 0 {
		return nil, nil, fmt.Errorf("peer %s: key answer kel not base64", p.AID)
	}
	return keyset, kel, nil
}

// hubAuth is the parsed relayauth v2 header tuple of a hub-to-hub request.
type hubAuth struct {
	aid string
	ts  uint64
	seq uint64
	sig []byte
}

func parseHubAuth(r *http.Request) (hubAuth, error) {
	get := func(name string) (string, bool) {
		vs := r.Header.Values(name)
		if len(vs) != 1 || vs[0] == "" {
			return "", false
		}
		return vs[0], true
	}
	aid, ok1 := get(relayauth.HeaderAID)
	ts, ok2 := get(relayauth.HeaderTS)
	seq, ok3 := get(relayauth.HeaderSeq)
	sig, ok4 := get(relayauth.HeaderSig)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return hubAuth{}, errors.New("signed hub request required: " + relayauth.HeaderAID + ", " +
			relayauth.HeaderTS + ", " + relayauth.HeaderSeq + ", " + relayauth.HeaderSig)
	}
	var a hubAuth
	var err error
	a.aid = aid
	if a.ts, err = strconv.ParseUint(ts, 10, 64); err != nil || strconv.FormatUint(a.ts, 10) != ts {
		return hubAuth{}, errors.New(relayauth.HeaderTS + " is not a canonical decimal time")
	}
	if a.seq, err = strconv.ParseUint(seq, 10, 64); err != nil || strconv.FormatUint(a.seq, 10) != seq {
		return hubAuth{}, errors.New(relayauth.HeaderSeq + " is not a canonical decimal seq")
	}
	if a.sig, err = relayauth.DecodeSig(sig); err != nil {
		return hubAuth{}, err
	}
	return a, nil
}

// replayGuard remembers accepted request signatures until their window
// ends. It is swept on each insert once a second has passed since the
// last sweep.
//
// Only a peer hub can add an entry (the signature is verified first), but
// a peer's rate is not only its own: a peer answers GET
// /agents/{aid}/keys for anonymous callers by asking this hub. The set is
// therefore bounded. When it holds max live entries a new request is
// refused (503) rather than an entry evicted, because eviction would
// re-admit the evicted signature.
type replayGuard struct {
	mu    sync.Mutex
	seen  map[[16]byte]int64
	max   int
	swept int64
}

// defaultReplayGuardMax bounds the /fed/v2/keys replay set: about 10 MiB,
// or some 400 lookups per second sustained over the 10-minute window.
const defaultReplayGuardMax = 1 << 18

func newReplayGuard() *replayGuard {
	return &replayGuard{seen: map[[16]byte]int64{}, max: defaultReplayGuardMax}
}

var (
	errRequestReplayed = errors.New("this request signature was already used")
	errReplayGuardFull = errors.New("replay set full; retry later")
)

func (g *replayGuard) admit(aid string, sig []byte, windowEnd, now int64) error {
	h := sha256.New()
	h.Write([]byte(aid))
	h.Write([]byte{0})
	h.Write(sig)
	var key [16]byte
	copy(key[:], h.Sum(nil))
	g.mu.Lock()
	defer g.mu.Unlock()
	// At most one sweep a second, full or not: a sweep walks every entry.
	if now-g.swept > 1000 {
		for k, end := range g.seen {
			if end < now {
				delete(g.seen, k)
			}
		}
		g.swept = now
	}
	if end, ok := g.seen[key]; ok && end >= now {
		return errRequestReplayed
	}
	if len(g.seen) >= g.max {
		return errReplayGuardFull
	}
	g.seen[key] = windowEnd
	return nil
}
