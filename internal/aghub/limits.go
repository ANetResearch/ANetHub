package aghub

import (
	"crypto/ed25519"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/seal"
)

// Limits are the operator-set bounds of the relay and of registration
// (A2A-DESIGN §3.7). Each is a flag on cmd/anet-hub; DefaultLimits returns
// the design's defaults.
//
// Sending is not signed in wire 3 (sealed-sender §4.2): a first contact is
// sent under a short-lived session the sender opened with its signature, and
// every later message under a delivery credential the recipient issued, which
// names no sender. The rate of a send is therefore bounded per session holder
// and per credential, and those buckets are code constants (relayBuckets
// below, sealed-sender §2.12 and SSR-H21), not flags. What is left here is
// what an operator sizes to its machine: the largest envelope, what may pile
// up for one recipient and for how long, how much one poll returns, and how
// fast one address may register.
type Limits struct {
	// MaxEnvelope is the largest sealed envelope /relay/send accepts
	// (413 above it). The request body is the envelope itself.
	MaxEnvelope int64
	// MailboxMessages and MailboxBytes bound one recipient's undelivered
	// envelopes (507 when a send would exceed either). The non-contact part
	// of a mailbox is a share of these (quota.go).
	MailboxMessages int
	MailboxBytes    int64
	// UndeliveredTTL is how long an envelope waits for its recipient
	// before the janitor deletes it; at most MaxUndeliveredTTL.
	UndeliveredTTL time.Duration
	// PollBudget bounds the cumulative envelope bytes of one /relay/poll
	// response (the first message is always returned).
	PollBudget int64
	// RegisterPerMinute and RegisterBurst are the per-client-IP token
	// bucket on /register (429 + Retry-After when empty).
	RegisterPerMinute float64
	RegisterBurst     int
}

// DefaultLimits returns the defaults of A2A-DESIGN §3.7.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelope:       96 << 20,
		MailboxMessages:   5000,
		MailboxBytes:      1 << 30,
		UndeliveredTTL:    14 * 24 * time.Hour,
		PollBudget:        48 << 20,
		RegisterPerMinute: 10,
		RegisterBurst:     20,
	}
}

// MaxUndeliveredTTL is the longest an undelivered envelope may be kept
// (forward-secrecy FS-T1): this hub accepts an envelope up to
// DeliveryDeadline after its key's not_after, and the recipient deletes the
// key at not_after + seal.MaxMessageLifetimeMS by a clock that may run up to
// seal.ClockSkewMS ahead. An envelope kept longer could outlive the only key
// that opens it, so the operator cannot set a longer -relay-ttl. It is 14
// days 22 hours 55 minutes; the default is 14 days.
const MaxUndeliveredTTL = time.Duration(seal.MaxMessageLifetimeMS-seal.DeliveryDeadlineMS-seal.ClockSkewMS) * time.Millisecond

// Validate reports the first limit that is not positive, or the undelivered
// TTL past MaxUndeliveredTTL.
func (l Limits) Validate() error {
	switch {
	case l.MaxEnvelope <= 0:
		return fmt.Errorf("envelope limit must be positive")
	case l.MailboxMessages <= 0 || l.MailboxBytes <= 0:
		return fmt.Errorf("mailbox limits must be positive")
	case l.UndeliveredTTL <= 0:
		return fmt.Errorf("undelivered TTL must be positive")
	case l.UndeliveredTTL > MaxUndeliveredTTL:
		return fmt.Errorf("undelivered TTL %s is longer than %s, after which a recipient may have deleted the key "+
			"that opens an envelope; set -relay-ttl to %s or less", l.UndeliveredTTL, MaxUndeliveredTTL, MaxUndeliveredTTL)
	case l.PollBudget <= 0:
		return fmt.Errorf("poll budget must be positive")
	case l.RegisterPerMinute <= 0 || l.RegisterBurst <= 0:
		return fmt.Errorf("register rate and burst must be positive")
	}
	return nil
}

// sendBodyLimit is the largest /relay/send request body: the envelope
// itself (application/vnd.anet.envelope+cbor), so MaxEnvelope. It is also
// the largest body any route accepts (limitBody).
func (l Limits) sendBodyLimit() int64 {
	return l.MaxEnvelope
}

// rateLimiter is a set of token buckets keyed by a string (a sender AID or
// a client IP).
//
// Buckets that have refilled completely carry no information and are
// dropped by a periodic sweep, so the map holds only keys that were active
// within the last burst/rate seconds.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*tokenBucket
	swept   time.Time
	now     func() time.Time
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

func newRateLimiter(ratePerSecond float64, burst int) *rateLimiter {
	return &rateLimiter{
		rate: ratePerSecond, burst: float64(burst),
		buckets: map[string]*tokenBucket{}, now: time.Now,
	}
}

// allow takes one token for key. When the bucket is empty it returns false
// and how long until one token is available.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.swept) > time.Minute {
		for k, b := range l.buckets {
			if b.tokens+now.Sub(b.at).Seconds()*l.rate >= l.burst {
				delete(l.buckets, k)
			}
		}
		l.swept = now
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.at).Seconds()*l.rate)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// empty reports, without taking a token, whether key's bucket holds less
// than one token, and how long until it holds one. It lets a handler
// refuse before doing expensive work for a key whose bucket is already
// empty. Because it takes nothing, a caller that names someone else's key
// cannot use it to drain that bucket.
func (l *rateLimiter) empty(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false, 0
	}
	tokens := math.Min(l.burst, b.tokens+l.now().Sub(b.at).Seconds()*l.rate)
	if tokens >= 1 {
		return false, 0
	}
	return true, time.Duration((1 - tokens) / l.rate * float64(time.Second))
}

// retryAfter formats a wait as the whole seconds of a Retry-After header,
// rounded up and at least 1.
func retryAfter(d time.Duration) string {
	s := int64(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return fmt.Sprintf("%d", s)
}

// clientIP is the key a per-address limit is kept under.
//
// The hub normally runs behind a reverse proxy on the same machine
// (deploy/nginx-hub.conf), which connects from a loopback address and
// sets X-Real-IP to the client's address. X-Real-IP is therefore used only
// when the connection itself comes from loopback; from any other peer the
// header is caller-controlled and the connection address is used. The cost
// of this rule: a proxy on another host, or one that does not set
// X-Real-IP, makes every client share the proxy's bucket.
//
// An IPv6 address is keyed by its /64 prefix. An IPv6 subscriber is
// normally assigned a whole /64 and can send from any address in it, so a
// key per full address would give one client an unbounded number of
// buckets. The cost: clients that share one /64 share one bucket.
func clientIP(r *http.Request) string {
	ip := clientAddr(r)
	if ip == nil {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		return host
	}
	return rateKeyOf(ip)
}

// clientAddr is the client's address by the rule of clientIP, or nil when
// the connection's address does not parse. The registration quota and the
// trial budget key on its networks (admission.go).
func clientAddr(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			if p := net.ParseIP(real); p != nil {
				ip = p
			}
		}
	}
	return ip
}

// rateKeyOf is the per-address rate-limit key: the address itself for
// IPv4 (including an IPv4-mapped IPv6 address), the /64 prefix for IPv6.
func rateKeyOf(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ---- the relay's buckets (sealed-sender §2.12, §4.2.1, §4.2.3) ----
//
// Every number below is a code constant: a hub does not tune them, and no
// flag sets them (SSR-H21). An operator can only raise one recipient's
// first-contact rate and non-contact share (anet-hub quota, quota.go).
//
// The buckets are kept in this process's memory only and are keyed by what
// they limit: a session holder's AID, a delivery credential's (owner,
// cap_id), a recipient's AID, a client address. None of those keys is
// written to a log, a metric label, the database or the admin console
// (SSR-H7, SSR-H19).

// relayRate is one bucket's refill per second and size.
type relayRate struct {
	perSec float64
	burst  float64
}

// The relay's rates.
var (
	// rateSessionSend is a session holder's sends, past its probation
	// (SSR-H8): 20 a second, 200 at once.
	rateSessionSend = relayRate{20, 200}
	// rateSessionSendProbation is the same during the probation of an
	// account that came in through open registration or a sign-up window
	// (SSR-H8; hub-payment-privacy, Store.ProbationUntil): 2 a second, 20
	// at once.
	rateSessionSendProbation = relayRate{2, 20}
	// rateContactCap is one contact capability's sends: 20 a second, 200 at
	// once.
	rateContactCap = relayRate{20, 200}
	// rateStrangerCap is one stranger capability's sends: 1 a second, 10 at
	// once.
	rateStrangerCap = relayRate{1, 10}
	// rateAddrFailure is one client address's refused kind-1 sends
	// (§4.2.1 step 1a, SSR-H3b): 60 a minute, 30 at once. It is debited only
	// after a 403 access_invalid has been answered, never on a send that
	// was accepted.
	rateAddrFailure = relayRate{1, 30}
)

// firstContactRate is a recipient's first-contact bucket: its quota's
// first contacts per minute, twice that at once (30 a minute and 60 by
// default, quota.go).
func firstContactRate(q Quota) relayRate {
	return relayRate{float64(q.FirstContactsPerMin) / 60, float64(q.FirstContactsBurst())}
}

// MaxStrangerCapRows is how many undelivered rows one stranger capability
// may have in a mailbox (§4.2.2): more is 429 strangers_busy.
const MaxStrangerCapRows = 200

// MaxRedeliveries is how many times one env_digest may be queued within
// RedeliveryWindow (§4.2.1 step 9): the next is 429 redelivery_limited.
const MaxRedeliveries = 3

// RedeliveryWindow is the window MaxRedeliveries counts in.
const RedeliveryWindow = 24 * time.Hour

// StrangersBusyRetry is the Retry-After of a strangers_busy from a full
// non-contact share (§4.2.2).
const StrangersBusyRetry = time.Minute

// MaxAccessHeader bounds X-ANet-Access (core §2.12.1): a kind-1 access is
// about 400 characters.
const MaxAccessHeader = 1 << 10

// equalVerifyKey is the public key step 2 of a kind-1 send verifies a
// signature under when it refused before it reached Cap.sig (SSR-H3a): an
// Ed25519 key of no AID and of no use, whose result is thrown away, so that
// every refusal of step 2 costs exactly one Ed25519 verification whatever
// its cause. It is a valid point: a key that does not decode would make the
// verification return before doing the work.
var equalVerifyKey = ed25519.PublicKey{
	0x24, 0x2c, 0xcd, 0x70, 0xc1, 0x27, 0xb0, 0xcb, 0x2d, 0x65, 0x5f, 0x1b, 0xce, 0xdc, 0xd8, 0x5e,
	0x3f, 0x41, 0xaf, 0x11, 0xe3, 0x1e, 0x0d, 0x20, 0xe6, 0x9a, 0x9a, 0xb2, 0x87, 0x60, 0x21, 0xff,
}

// verifyEd25519 is ed25519.Verify; a test counts the verifications of step
// 2 through it (TestKind1Step2ConstantVerifyCount).
var verifyEd25519 = ed25519.Verify

// bucketSet is a set of token buckets keyed by a string, each with the rate
// it is used at. Unlike rateLimiter it can look without taking (peek),
// take one token from several buckets together and give a token back
// (refund): a refused send costs nobody a token (§4.2.1, SSR-H2).
//
// Buckets that have refilled completely carry no information and are
// dropped by a periodic sweep, so the map holds only keys that were used
// within the last burst/rate seconds.
type bucketSet struct {
	mu      sync.Mutex
	buckets map[string]*relayBucket
	swept   time.Time
	now     func() time.Time
}

type relayBucket struct {
	tokens float64
	at     time.Time
	rate   relayRate
}

func newBucketSet(now func() time.Time) *bucketSet {
	return &bucketSet{buckets: map[string]*relayBucket{}, now: now}
}

// level is key's bucket refilled to now, at rate r, created full when
// there is none. The caller holds mu.
func (b *bucketSet) level(key string, r relayRate, now time.Time) *relayBucket {
	if now.Sub(b.swept) > time.Minute {
		for k, x := range b.buckets {
			if x.tokens+now.Sub(x.at).Seconds()*x.rate.perSec >= x.rate.burst {
				delete(b.buckets, k)
			}
		}
		b.swept = now
	}
	x, ok := b.buckets[key]
	if !ok {
		x = &relayBucket{tokens: r.burst, at: now}
		b.buckets[key] = x
	}
	if d := now.Sub(x.at); d > 0 {
		x.tokens += d.Seconds() * r.perSec
	}
	x.tokens = math.Min(r.burst, x.tokens)
	x.at, x.rate = now, r
	return x
}

// waitFor is how long until x holds one token at rate r.
func waitFor(x *relayBucket, r relayRate) time.Duration {
	if x.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - x.tokens) / r.perSec * float64(time.Second))
}

// peek reports, without taking a token, whether key's bucket holds less
// than one token at rate r, and how long until it holds one.
func (b *bucketSet) peek(key string, r relayRate) (empty bool, wait time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	x, ok := b.buckets[key]
	if !ok {
		return false, 0
	}
	tokens := x.tokens
	if d := now.Sub(x.at); d > 0 {
		tokens += d.Seconds() * r.perSec
	}
	tokens = math.Min(r.burst, tokens)
	if tokens >= 1 {
		return false, 0
	}
	return true, time.Duration((1 - tokens) / r.perSec * float64(time.Second))
}

// take takes one token from key's bucket at rate r. When the bucket holds
// less than one it takes nothing and returns false and the wait.
func (b *bucketSet) take(key string, r relayRate) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	x := b.level(key, r, b.now())
	if x.tokens < 1 {
		return false, waitFor(x, r)
	}
	x.tokens--
	return true, 0
}

// takeN takes n tokens (at most the burst) from key's bucket at rate r, or
// nothing and the wait when it holds fewer.
func (b *bucketSet) takeN(key string, r relayRate, n float64) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n = math.Min(n, r.burst)
	x := b.level(key, r, b.now())
	if x.tokens < n {
		return false, time.Duration((n - x.tokens) / r.perSec * float64(time.Second))
	}
	x.tokens -= n
	return true, 0
}

// refund gives back the token take took from key's bucket.
func (b *bucketSet) refund(key string, r relayRate) {
	b.mu.Lock()
	defer b.mu.Unlock()
	x := b.level(key, r, b.now())
	x.tokens = math.Min(r.burst, x.tokens+1)
}

// debit takes up to n tokens from key's bucket at rate r, as many as it
// holds: a penalty, not a request, so it never refuses and never takes the
// bucket below empty.
func (b *bucketSet) debit(key string, r relayRate, n float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	x := b.level(key, r, b.now())
	x.tokens = math.Max(0, x.tokens-n)
}

// forget drops key's bucket: it starts full the next time.
func (b *bucketSet) forget(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.buckets, key)
}

// tokens is how many tokens key's bucket holds now at rate r (a full
// bucket when there is none). Tests read it.
func (b *bucketSet) tokens(key string, r relayRate) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	x, ok := b.buckets[key]
	if !ok {
		return r.burst
	}
	t := x.tokens
	if d := b.now().Sub(x.at); d > 0 {
		t += d.Seconds() * r.perSec
	}
	return math.Min(r.burst, t)
}

// bucketTake is one token a send takes: from which set, under which key and
// at which rate.
type bucketTake struct {
	set  *bucketSet
	key  string
	rate relayRate
}

// takeAll takes one token from every bucket of ts, or from none: the first
// bucket without a token is reported (its index and wait), and what was
// taken before it is given back.
func takeAll(ts []bucketTake) (failed int, wait time.Duration) {
	for i, t := range ts {
		if ok, w := t.set.take(t.key, t.rate); !ok {
			refundAll(ts[:i])
			return i, w
		}
	}
	return -1, 0
}

// refundAll gives back one token to every bucket of ts.
func refundAll(ts []bucketTake) {
	for _, t := range ts {
		t.set.refund(t.key, t.rate)
	}
}
