package aghub

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limits are the application-level bounds of A2A-DESIGN §3.7. Each is a
// flag on cmd/anet-hub; DefaultLimits returns the design's defaults.
//
// They exist because /relay/send is authenticated but registration is
// open: any caller can create an AID and send as it. The per-sender bucket
// bounds what one AID can make this hub store per second, the mailbox
// quota bounds what can pile up for one recipient, the TTL bounds how long
// it stays, and the per-IP registration limit bounds how quickly a caller
// can mint new senders to get new buckets.
type Limits struct {
	// MaxEnvelope is the largest sealed envelope /relay/send accepts
	// (413 above it).
	MaxEnvelope int64
	// SendRate and SendBurst are the per-sender token bucket on
	// /relay/send: tokens per second and bucket size (429 + Retry-After
	// when empty).
	SendRate  float64
	SendBurst int
	// MailboxMessages and MailboxBytes bound one recipient's undelivered
	// envelopes (507 when a send would exceed either).
	MailboxMessages int
	MailboxBytes    int64
	// UndeliveredTTL is how long an envelope waits for its recipient
	// before the janitor deletes it.
	UndeliveredTTL time.Duration
	// PollBudget bounds the cumulative envelope bytes of one /relay/poll
	// response (the first message is always returned).
	PollBudget int64
	// RegisterPerMinute and RegisterBurst are the per-client-IP token
	// bucket on /register (429 + Retry-After when empty).
	RegisterPerMinute float64
	RegisterBurst     int
	// KeysLookupPerMinute and KeysLookupBurst are the per-client-IP token
	// bucket on the federated half of GET /agents/{aid}/keys: a lookup
	// for an AID this hub does not hold, which it answers by asking every
	// peer hub over /fed/v2/keys (429 + Retry-After when empty). The
	// endpoint is unauthenticated, so without a bound one caller could
	// make this hub send signed requests to its peers at whatever rate the
	// caller chooses. Answers from local registrations and from synced
	// cards are not limited.
	KeysLookupPerMinute float64
	KeysLookupBurst     int
}

// DefaultLimits returns the defaults of A2A-DESIGN §3.7.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelope:         96 << 20,
		SendRate:            20,
		SendBurst:           200,
		MailboxMessages:     5000,
		MailboxBytes:        1 << 30,
		UndeliveredTTL:      14 * 24 * time.Hour,
		PollBudget:          48 << 20,
		RegisterPerMinute:   10,
		RegisterBurst:       20,
		KeysLookupPerMinute: 60,
		KeysLookupBurst:     30,
	}
}

// Validate reports the first limit that is not positive.
func (l Limits) Validate() error {
	switch {
	case l.MaxEnvelope <= 0:
		return fmt.Errorf("envelope limit must be positive")
	case l.SendRate <= 0 || l.SendBurst <= 0:
		return fmt.Errorf("send rate and burst must be positive")
	case l.MailboxMessages <= 0 || l.MailboxBytes <= 0:
		return fmt.Errorf("mailbox limits must be positive")
	case l.UndeliveredTTL <= 0:
		return fmt.Errorf("undelivered TTL must be positive")
	case l.PollBudget <= 0:
		return fmt.Errorf("poll budget must be positive")
	case l.RegisterPerMinute <= 0 || l.RegisterBurst <= 0:
		return fmt.Errorf("register rate and burst must be positive")
	case l.KeysLookupPerMinute <= 0 || l.KeysLookupBurst <= 0:
		return fmt.Errorf("federated key lookup rate and burst must be positive")
	}
	return nil
}

// sendBodyLimit is the largest /relay/send request body: the base64 of the
// largest envelope plus room for the JSON around it and the recipient AID.
func (l Limits) sendBodyLimit() int64 {
	return base64Len(l.MaxEnvelope) + 64<<10
}

// base64Len is the standard-encoding length of n bytes.
func base64Len(n int64) int64 { return (n + 2) / 3 * 4 }

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
	if ip == nil {
		return host
	}
	return rateKeyOf(ip)
}

// rateKeyOf is the per-address rate-limit key: the address itself for
// IPv4 (including an IPv4-mapped IPv6 address), the /64 prefix for IPv6.
func rateKeyOf(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
