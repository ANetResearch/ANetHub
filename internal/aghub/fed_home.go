package aghub

import (
	"bytes"
	"container/list"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/dirbox"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Federation v3, the kernel's half (sealed-sender §2.9, §4.2.6, §4.2.7).
//
// A recipient registered at a peer hub is reached through that one hub, its
// home. This hub finds the home without asking anybody for the recipient by
// AID (SSR-H12): the sender's hint (X-ANet-Home) when it names a peer, else
// the home of the recipient's federated A2A card, else the recipient's
// directory entry, found in the bucket of its directory hash that each peer
// answers (/fed/v3/directory:bucket) and opened with the AID. A send under a
// delivery credential needs the owner's mailbox key as well, to check the
// credential before anything is forwarded (SSR-H14): from the card's key
// set or from the entry.
//
// Everything learned is kept in this process's memory only (sealed-sender
// §3.1), and nothing of it is logged under an AID (SSR-H19):
//
//   - homes: the resolved home and mailbox key of an AID, for a day;
//   - refreshed: when an AID's resolution was last made again on demand,
//     so that is at most once a minute (§2.12);
//   - neg: the credentials a home refused, by (home, owner, cap_id), until
//     their cap_exp (SSR-H14a);
//   - buckets: each peer's answer for a bucket, for ten minutes (SSR-W19),
//     and each peer's dir_max_bits as it last stated it.

// The federation constants of the kernel (sealed-sender §2.12). None of them
// is a flag.
const (
	// HomeCacheTTL is how long a resolved home and mailbox key are used.
	HomeCacheTTL = 24 * time.Hour
	// HomeRefreshEvery is how often at most one AID's resolution is made
	// again on demand: after a credential under an older epoch than the one
	// held, or after its home refused a credential.
	HomeRefreshEvery = time.Minute
	// HomeCacheMax bounds the AIDs whose resolution is kept.
	HomeCacheMax = 100_000
	// NegCacheMax bounds the refused credentials kept (SSR-H14a).
	NegCacheMax = 100_000
	// BucketCacheTTL is how long a peer's answer for a bucket is used.
	BucketCacheTTL = 10 * time.Minute
	// BucketCacheBytes bounds the peers' answers kept, all together.
	BucketCacheBytes = 64 << 20
	// PeerBucketMaxBytes bounds one peer's answer for one bucket, all its
	// pages together; a larger answer is taken as no answer.
	PeerBucketMaxBytes = 16 << 20
	// FedSourcePenalty is what a source hub's bucket loses for a forwarded
	// credential the source hub should have refused itself (SSR-H15a).
	FedSourcePenalty = 10
)

// rateFedSource is a peer hub's bucket at this hub as the home of its
// recipients (§4.2.7): 1000 forwards a second, 10 000 at once.
var rateFedSource = relayRate{1000, 10_000}

// Federation is the federation module as the kernel asks it
// (cmd/anet-hub wires *federation.Service with SetFederation): which hubs
// are peers of delivery, and the two requests this hub makes to one. Its
// methods take standard types only, so the kernel does not import the
// module for it (K207). Nil in a build without federation, or with
// delivery federation off: then a recipient is registered here or unknown.
type Federation interface {
	// DeliveryPeers is the hubs this one forwards to, in the order of the
	// peer table; none when delivery federation is off.
	DeliveryPeers() []string
	// IsDeliveryPeer reports whether hubAID is one of them.
	IsDeliveryPeer(hubAID string) bool
	// DeliveryPeerAt is the AID of the delivery peer at the hub URL home,
	// or "".
	DeliveryPeerAt(home string) string
	// Forward hands an envelope on to the peer with /fed/v3/forward;
	// access is X-ANet-Access. The response is the caller's to close.
	Forward(ctx context.Context, peerAID string, envelope []byte, access string) (*http.Response, error)
	// Bucket asks the peer for a bucket with /fed/v3/directory:bucket; body
	// is the JSON request. The response is the caller's to close.
	Bucket(ctx context.Context, peerAID string, body []byte) (*http.Response, error)
}

// SetFederation wires the federation module. Call it before serving.
func (s *Server) SetFederation(f Federation) { s.fed = f }

// delivering reports whether this hub forwards to any peer.
func (s *Server) delivering() bool { return s.fed != nil && len(s.fed.DeliveryPeers()) > 0 }

// ---- the caches ----

// lru is a map bounded by its number of entries (or by the size its owner
// counts), evicting the least recently used. Not safe for concurrent use;
// fedState holds its lock around it.
type lru[K comparable, V any] struct {
	max   int
	order *list.List // front: most recent; values are *lruItem[K, V]
	items map[K]*list.Element
}

type lruItem[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](max int) *lru[K, V] {
	return &lru[K, V]{max: max, order: list.New(), items: map[K]*list.Element{}}
}

func (c *lru[K, V]) get(k K) (V, bool) {
	if e, ok := c.items[k]; ok {
		c.order.MoveToFront(e)
		return e.Value.(*lruItem[K, V]).val, true
	}
	var zero V
	return zero, false
}

// put stores v under k and returns what it evicted.
func (c *lru[K, V]) put(k K, v V) (evicted []V) {
	if e, ok := c.items[k]; ok {
		old := e.Value.(*lruItem[K, V]).val
		e.Value.(*lruItem[K, V]).val = v
		c.order.MoveToFront(e)
		return []V{old}
	}
	c.items[k] = c.order.PushFront(&lruItem[K, V]{k, v})
	for c.order.Len() > c.max {
		evicted = append(evicted, c.removeElement(c.order.Back()))
	}
	return evicted
}

// oldest removes and returns the least recently used entry.
func (c *lru[K, V]) oldest() (V, bool) {
	if e := c.order.Back(); e != nil {
		return c.removeElement(e), true
	}
	var zero V
	return zero, false
}

func (c *lru[K, V]) remove(k K) {
	if e, ok := c.items[k]; ok {
		c.removeElement(e)
	}
}

func (c *lru[K, V]) removeElement(e *list.Element) V {
	it := c.order.Remove(e).(*lruItem[K, V])
	delete(c.items, it.key)
	return it.val
}

func (c *lru[K, V]) len() int { return c.order.Len() }

// homeInfo is a resolved home: the peer hub an AID is registered at, and
// the mailbox key of its key set there.
type homeInfo struct {
	home  string
	mbox  seal.Mbox
	at    time.Time
	stale bool // its home refused a credential since: make it again at the next use
}

// negKey is a credential a home refused (SSR-H14a): the key holds the home,
// so the owner's moving to another hub ends the entry's effect.
type negKey struct {
	home, owner, capID string
}

// bucketKey is a peer's bucket: the peer, the prefix and its bits.
type bucketKey struct {
	peer   string
	prefix string
	bits   int
}

// bucketAnswer is what a peer answered for one bucket: its entries, decoded,
// and its size in bytes.
type bucketAnswer struct {
	key     bucketKey
	entries []peerEntry
	size    int
	at      time.Time
}

// peerEntry is one entry of a peer's bucket.
type peerEntry struct {
	h, box []byte
}

// fedState is what the federation part of the kernel keeps in memory.
type fedState struct {
	mu          sync.Mutex
	homes       *lru[string, homeInfo]
	refreshed   *lru[string, time.Time]
	neg         *lru[negKey, uint64]
	buckets     *lru[bucketKey, *bucketAnswer]
	bucketBytes int
	peerBits    map[string]int
}

func newFedState() *fedState {
	return &fedState{homes: newLRU[string, homeInfo](HomeCacheMax), refreshed: newLRU[string, time.Time](HomeCacheMax),
		neg: newLRU[negKey, uint64](NegCacheMax), buckets: newLRU[bucketKey, *bucketAnswer](1 << 20),
		peerBits: map[string]int{}}
}

// home is the resolution kept for aid, if it is younger than HomeCacheTTL.
func (f *fedState) home(aid string, now time.Time) (homeInfo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.homes.get(aid)
	if !ok || now.Sub(h.at) >= HomeCacheTTL || now.Before(h.at) {
		return homeInfo{}, false
	}
	return h, true
}

func (f *fedState) putHome(aid string, h homeInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.homes.put(aid, h)
}

// forgetHome drops what is kept for aid.
func (f *fedState) forgetHome(aid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.homes.remove(aid)
}

// markStale has aid's resolution made again at its next use (SSR-H14a 2,
// §2.12): after its home refused a credential, or a credential did not
// verify under the mailbox key held. When nothing is kept for aid (its key
// came from its federated card), a mark alone is kept.
func (f *fedState) markStale(aid string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.homes.get(aid)
	if !ok || now.Sub(h.at) >= HomeCacheTTL || now.Before(h.at) {
		h = homeInfo{at: now}
	}
	h.stale = true
	f.homes.put(aid, h)
}

// mayRefresh reports whether aid's resolution may be made again on demand
// now, and if so records that it is: at most once every HomeRefreshEvery.
func (f *fedState) mayRefresh(aid string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if last, ok := f.refreshed.get(aid); ok && now.Sub(last) < HomeRefreshEvery && !now.Before(last) {
		return false
	}
	f.refreshed.put(aid, now)
	return true
}

// negative reports whether the home refused the credential and it has not
// expired; an expired entry is dropped.
func (f *fedState) negative(k negKey, nowMS uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.neg.get(k)
	if !ok {
		return false
	}
	if exp < nowMS {
		f.neg.remove(k)
		return false
	}
	return true
}

func (f *fedState) putNegative(k negKey, capExp uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.neg.put(k, capExp)
}

// bucket is the answer kept for k, if it is younger than BucketCacheTTL.
func (f *fedState) bucket(k bucketKey, now time.Time) (*bucketAnswer, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.buckets.get(k)
	if !ok || now.Sub(a.at) >= BucketCacheTTL || now.Before(a.at) {
		return nil, false
	}
	return a, true
}

func (f *fedState) putBucket(a *bucketAnswer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, old := range f.buckets.put(a.key, a) {
		f.bucketBytes -= old.size
	}
	f.bucketBytes += a.size
	for f.bucketBytes > BucketCacheBytes && f.buckets.len() > 1 {
		old, _ := f.buckets.oldest()
		f.bucketBytes -= old.size
	}
}

// bitsOf is the dir_max_bits peer last stated, or -1 when it has not.
func (f *fedState) bitsOf(peer string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.peerBits[peer]; ok {
		return b
	}
	return -1
}

func (f *fedState) setBits(peer string, bits int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peerBits[peer] = bits
}

// ---- a peer's bucket ----

// peerBucket is the part of the bucket (prefix, bits) that the peer hub
// answers for (SSR-W19): asked at min(bits, the peer's dir_max_bits) and
// filtered to (prefix, bits). It is taken from the cache when it was asked
// for in the last BucketCacheTTL, unless fresh is set. ok is false when the
// peer did not answer (a timeout, a refusal, a failure, an answer too
// large) and nothing is cached.
func (s *Server) peerBucket(ctx context.Context, peer string, prefix []byte, bits int, fresh bool) ([]peerEntry, bool) {
	asked := bits
	if pb := s.fedState.bitsOf(peer); pb >= 0 && pb < asked {
		asked = pb
	}
	var a *bucketAnswer
	for attempt := 0; ; attempt++ {
		p := truncatePrefix(prefix, asked)
		key := bucketKey{peer: peer, prefix: string(p), bits: asked}
		if !fresh {
			if c, ok := s.fedState.bucket(key, s.store.now()); ok {
				a = c
				break
			}
		}
		got, narrower, err := s.askPeerBucket(ctx, peer, p, asked)
		if narrower >= 0 && narrower < asked && attempt == 0 {
			asked = narrower
			continue
		}
		if err != nil {
			if c, ok := s.fedState.bucket(key, s.store.now()); ok {
				a = c
				break
			}
			return nil, false
		}
		got.key, got.at = key, s.store.now()
		s.fedState.putBucket(got)
		a = got
		break
	}
	var out []peerEntry
	for _, e := range a.entries {
		if dirbox.InBucket(e.h, prefix, bits) {
			out = append(out, e)
		}
	}
	return out, true
}

// truncatePrefix is the prefix of bits bits that prefix (of at least as
// many) starts with.
func truncatePrefix(prefix []byte, bits int) []byte {
	n := (bits + 7) / 8
	p := bytes.Clone(prefix[:n])
	if r := bits % 8; r != 0 {
		p[n-1] &= byte(0xff << (8 - r))
	}
	return p
}

// errNoBucket is a peer's bucket that cannot be had.
var errNoBucket = errors.New("hub: the peer did not answer for the bucket")

// askPeerBucket asks peer for the bucket (prefix, bits), page by page. A
// refusal bucket_too_narrow reports the max_bits it names as narrower (else
// -1), so the caller asks once more at that width.
func (s *Server) askPeerBucket(ctx context.Context, peer string, prefix []byte, bits int) (*bucketAnswer, int, error) {
	a := &bucketAnswer{}
	cursor := ""
	for {
		body, err := json.Marshal(DirBucketRequest{Prefix: ptr(wire3.EncodeB64URL(prefix)), Bits: ptr(uint(bits)), Cursor: cursor})
		if err != nil {
			return nil, -1, err
		}
		resp, err := s.fed.Bucket(ctx, peer, body)
		if err != nil {
			return nil, -1, err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, DirPageBytes+1<<20))
		resp.Body.Close()
		if err != nil {
			return nil, -1, err
		}
		if resp.StatusCode != http.StatusOK {
			var ref struct {
				Reason  string `json:"reason"`
				MaxBits *int   `json:"max_bits"`
			}
			if json.Unmarshal(raw, &ref) == nil && ref.Reason == string(wire3.ReasonBucketTooNarrow) &&
				ref.MaxBits != nil && *ref.MaxBits >= 0 && *ref.MaxBits <= dirbox.HashBits {
				s.fedState.setBits(peer, *ref.MaxBits)
				return nil, *ref.MaxBits, errNoBucket
			}
			return nil, -1, errNoBucket
		}
		page, err := decodeFedBucketPage(raw, prefix, bits)
		if err != nil {
			return nil, -1, err
		}
		s.fedState.setBits(peer, int(page.maxBits))
		a.entries = append(a.entries, page.entries...)
		a.size += len(raw)
		if a.size > PeerBucketMaxBytes {
			log.Printf("hub: federation peer %s answered a bucket with more than %d bytes; it is left out of the merged bucket", peer, PeerBucketMaxBytes)
			return nil, -1, errNoBucket
		}
		if page.next == nil {
			return a, -1, nil
		}
		cursor = wire3.EncodeB64URL(page.next)
	}
}

func ptr[T any](v T) *T { return &v }

// fedBucketPage is one decoded page of a peer's bucket answer.
type fedBucketPage struct {
	maxBits uint
	entries []peerEntry
	next    []byte
}

// decodeFedBucketPage decodes one page of a peer's answer for the bucket
// (prefix, bits): {max_bits, entries: [{h, box}], next?}, every binary
// value base64url. An entry whose h is not a directory hash in the bucket,
// or whose box is larger than a directory carries, is left out: the peer
// answers for that bucket only. A next that is not a hash of the bucket
// after the last entry is an error, as is a member the answer does not
// have: the next page would be another bucket's.
func decodeFedBucketPage(raw, prefix []byte, bits int) (*fedBucketPage, error) {
	var ans FedBucketResponse
	if err := wire3.DecodeStrict(raw, &ans); err != nil {
		return nil, err
	}
	p := &fedBucketPage{maxBits: ans.MaxBits}
	var last []byte
	for _, e := range ans.Entries {
		h, herr := wire3.DecodeB64URLSize("h", e.H, dirbox.HashLen)
		box, berr := wire3.DecodeB64URL("box", e.Box)
		if herr != nil || berr != nil || len(box) > dirbox.MaxBoxLen || !dirbox.InBucket(h, prefix, bits) {
			continue
		}
		if last != nil && bytes.Compare(h, last) < 0 {
			return nil, errors.New("hub: a peer's bucket is not in hash order")
		}
		last = h
		p.entries = append(p.entries, peerEntry{h: h, box: box})
	}
	if ans.Next != "" {
		next, err := wire3.DecodeB64URLSize("next", ans.Next, dirbox.HashLen)
		if err != nil || !dirbox.InBucket(next, prefix, bits) || last == nil || bytes.Compare(next, last) < 0 {
			return nil, errors.New("hub: a peer's bucket names a next page outside it")
		}
		p.next = next
	}
	return p, nil
}

// ---- resolving a home ----

// resolvedEntry is a directory entry of an AID that verified: where it was
// found (its home), the mailbox key of its key set, its KEL and the seq of
// its key set.
type resolvedEntry struct {
	home    string
	mbox    seal.Mbox
	kel     []identity.SignedEvent
	keysSeq uint64
}

// lookupEntry finds aid's directory entry in the buckets of the given peers
// (SSR-H12 step 4) and selects one by SSR-W22: every entry filed under aid's
// hash is opened with aid and verified (verifyEntry), and the one with the
// longest KEL wins; two that verify with KELs of which neither extends the
// other are a fork, and nothing is resolved. Equal KELs are told apart by
// the newer key set, then by the order of the peer table. fresh asks the
// peers again instead of using what they answered in the last
// BucketCacheTTL.
func (s *Server) lookupEntry(ctx context.Context, aid string, peers []string, fresh bool) (*resolvedEntry, bool) {
	h, err := dirbox.Hash(aid)
	if err != nil || len(peers) == 0 {
		return nil, false
	}
	type found struct {
		peer    string
		entries []peerEntry
	}
	results := make([]found, len(peers))
	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			es, _ := s.peerBucket(ctx, peer, h, dirbox.HashBits, fresh)
			results[i] = found{peer, es}
		}()
	}
	wg.Wait()
	now := s.store.now()
	var best *resolvedEntry
	for _, r := range results {
		for _, pe := range r.entries {
			e, ok := s.verifyEntry(aid, r.peer, pe, now)
			if !ok {
				continue
			}
			switch {
			case best == nil:
				best = e
			case identity.ExtendsKEL(best.kel, e.kel) == nil && len(e.kel) > len(best.kel):
				best = e
			case identity.ExtendsKEL(e.kel, best.kel) == nil:
				if len(e.kel) == len(best.kel) && e.keysSeq > best.keysSeq {
					best = e
				}
			default:
				return nil, false // a fork: neither KEL extends the other
			}
		}
	}
	return best, best != nil
}

// verifyEntry opens one entry of aid that the peer served and verifies it
// (SSR-W22): the box opens under aid and names aid; its home is the peer
// that served it, since a peer answers for its own agents only (SSR-W20);
// the KEL replays to aid; the key set verifies against the KEL and carries a
// mailbox key of a usable epoch; the A2A card, if any, verifies against the
// KEL; the witness notice, if any, confirms the KEL's tip (KEL C-51, at
// now, against the peers' key histories this hub holds).
func (s *Server) verifyEntry(aid, peer string, pe peerEntry, now time.Time) (*resolvedEntry, bool) {
	e, err := dirbox.Open(aid, pe.h, pe.box)
	if err != nil || e.Home != peer {
		return nil, false
	}
	kel, err := seal.ParseKEL(e.KEL)
	if err != nil {
		return nil, false
	}
	states, err := identity.Replay(kel)
	if err != nil || states[len(states)-1].AID != aid {
		return nil, false
	}
	signed, err := seal.UnmarshalSignedEncKeySet(e.Keys)
	if err != nil {
		return nil, false
	}
	set, err := seal.VerifyEncKeySet(signed, aid, kel, uint64(now.UnixMilli()))
	if err != nil || !usableMbox(set.Mbox) {
		return nil, false
	}
	if len(e.Card) > 0 {
		if _, err := verifyA2ACardFor(aid, e.Card, kel, now); err != nil {
			return nil, false
		}
	}
	if len(e.Notice) > 0 {
		hubKELs := func(hubAID string) ([]identity.SignedEvent, bool) {
			k, err := s.peerKEL(hubAID)
			return k, err == nil
		}
		if err := identity.VerifyNotice(e.Notice, kel, hubKELs, uint64(now.UnixMilli())); err != nil {
			return nil, false
		}
	}
	return &resolvedEntry{home: peer, mbox: set.Mbox, kel: kel, keysSeq: set.Seq}, true
}

// usableMbox reports whether m is a mailbox key a credential can be checked
// under: an Ed25519 key of an epoch in [1, 2^53).
func usableMbox(m seal.Mbox) bool {
	return m.Epoch >= 1 && m.Epoch < MaxMboxEpoch && len(m.Pub) == ed25519.PublicKeySize
}

// hintHome is the sender's X-ANet-Home when it names a delivery peer
// (SSR-H12 step 2), else "".
func (s *Server) hintHome(hint string) string {
	if hint != "" && hint != s.hubAID && s.fed.IsDeliveryPeer(hint) {
		return hint
	}
	return ""
}

// cardHome is where the federated A2A card of aid says it lives, when that
// is a delivery peer (SSR-H12 step 3), and the mailbox key of the key set
// the card arrived with, if any.
func (s *Server) cardHome(aid string) (home string, mbox seal.Mbox, ok bool) {
	url, keys, err := s.store.fedCardRoute(aid)
	if err != nil || url == "" {
		return "", seal.Mbox{}, false
	}
	home = s.fed.DeliveryPeerAt(url)
	if home == "" {
		return "", seal.Mbox{}, false
	}
	if len(keys) > 0 {
		if signed, err := seal.UnmarshalSignedEncKeySet(keys); err == nil {
			if m, err := mboxOf(signed.Set); err == nil && usableMbox(*m) {
				mbox = *m
			}
		}
	}
	return home, mbox, true
}

// resolveRecipient is the home of a first contact's recipient aid, which is
// not registered here (SSR-H12 for kind 0): the hint when it names a peer,
// the home of the recipient's federated card, the home last resolved, or
// the home its directory entry names, asked of every peer. ok is false when
// none is found: the recipient is unknown.
func (s *Server) resolveRecipient(ctx context.Context, aid, hint string) (string, bool) {
	if !s.delivering() {
		return "", false
	}
	if h := s.hintHome(hint); h != "" {
		return h, true
	}
	if h, _, ok := s.cardHome(aid); ok {
		return h, true
	}
	now := s.store.now()
	if c, ok := s.fedState.home(aid, now); ok && !c.stale {
		return c.home, true
	}
	e, ok := s.lookupEntry(ctx, aid, s.fed.DeliveryPeers(), false)
	if !ok {
		return "", false
	}
	s.fedState.putHome(aid, homeInfo{home: e.home, mbox: e.mbox, at: now})
	return e.home, true
}

// resolveOwner is the home and the mailbox key of a credential's owner,
// which is not registered here (SSR-H12 for kind 1, §4.2.6): the home by
// the order of resolveRecipient, the mailbox key from the resolution kept
// or the federated card's key set. They are made again, asking the peers
// rather than their cached answers, when there is no mailbox key, when the
// credential names a newer epoch than the one held, or when the owner's home
// refused a credential or a credential did not verify under the key held
// since (markStale); at most once a minute for one owner
// (HomeRefreshEvery). When only the hint named a home, only that peer is
// asked. ok is false without a home or a mailbox key.
func (s *Server) resolveOwner(ctx context.Context, owner, hint string, capEpoch uint64) (string, seal.Mbox, bool) {
	if !s.delivering() {
		return "", seal.Mbox{}, false
	}
	now := s.store.now()
	hinted := s.hintHome(hint)
	cardAt, cardMbox, carded := s.cardHome(owner)
	var held homeInfo
	cached, haveCache := s.fedState.home(owner, now)
	switch {
	case haveCache && usableMbox(cached.mbox):
		held = cached
	case carded && usableMbox(cardMbox):
		held = homeInfo{home: cardAt, mbox: cardMbox, stale: haveCache && cached.stale}
	}
	behind := !usableMbox(held.mbox) || capEpoch > held.mbox.Epoch || held.stale
	if behind && (!haveCache && !carded || s.fedState.mayRefresh(owner, now)) {
		peers := s.fed.DeliveryPeers()
		switch {
		case hinted != "":
			peers = []string{hinted}
		case carded:
			peers = []string{cardAt}
		}
		if e, ok := s.lookupEntry(ctx, owner, peers, haveCache || carded); ok {
			held = homeInfo{home: e.home, mbox: e.mbox, at: now}
			s.fedState.putHome(owner, held)
		}
	}
	home := hinted
	if home == "" && carded {
		home = cardAt
	}
	if home == "" {
		home = held.home
	}
	if home == "" || !usableMbox(held.mbox) {
		return "", seal.Mbox{}, false
	}
	return home, held.mbox, true
}

// ---- the merged bucket (SSR-W19, SSR-W21) ----

// mergedBucket is the page of the bucket (prefix, bits) after the hash
// after: this hub's own entries and every delivery peer's, in hash order,
// at most DirPageBytes. partial is set when a peer did not answer and
// nothing it answered is cached. next is the hash the next page starts
// after, nil at the end. Entries of one hash (an agent the directory of two
// hubs holds) are never split across pages.
func (s *Server) mergedBucket(ctx context.Context, prefix []byte, bits int, after []byte) (entries []DirBucketEntry, next []byte, partial bool, err error) {
	local, localNext, err := s.store.DirBucket(prefix, bits, after)
	if err != nil {
		return nil, nil, false, err
	}
	if !s.delivering() {
		return local, localNext, false, nil
	}
	peers := s.fed.DeliveryPeers()
	got := make([][]peerEntry, len(peers))
	failed := make([]bool, len(peers))
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i, peer := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			es, ok := s.peerBucket(ctx, peer, prefix, bits, false)
			got[i], failed[i] = es, !ok
		}()
	}
	wg.Wait()
	type item struct {
		h []byte
		e DirBucketEntry
	}
	var all []item
	for _, e := range local {
		h, err := wire3.DecodeB64URL("h", e.H)
		if err != nil {
			return nil, nil, false, err
		}
		all = append(all, item{h, e})
	}
	// With a page of this hub's own cut short, nothing past its last hash
	// is on this page: the rest of the hub's own comes first next time.
	var bound []byte
	if localNext != nil {
		bound = localNext
	}
	for i, es := range got {
		partial = partial || failed[i]
		for _, pe := range es {
			if after != nil && bytes.Compare(pe.h, after) <= 0 || bound != nil && bytes.Compare(pe.h, bound) > 0 {
				continue
			}
			all = append(all, item{pe.h, DirBucketEntry{H: wire3.EncodeB64URL(pe.h), Box: wire3.EncodeB64URL(pe.box)}})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return bytes.Compare(all[i].h, all[j].h) < 0 })
	entries = []DirBucketEntry{}
	size := dirBucketAnswerOverhead
	for i := 0; i < len(all); {
		j, group := i, 0
		for ; j < len(all) && bytes.Equal(all[j].h, all[i].h); j++ {
			group += len(all[j].e.H) + len(all[j].e.Box) + dirBucketEntryOverhead
		}
		if size+group > DirPageBytes && len(entries) > 0 {
			return entries, all[i-1].h, partial, nil
		}
		for k := i; k < j; k++ {
			entries = append(entries, all[k].e)
		}
		size += group
		i = j
	}
	return entries, localNext, partial, nil
}
