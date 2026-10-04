package aghub

import (
	"encoding/binary"
	"testing"
	"time"
)

func cacheID(n int) []byte {
	id := make([]byte, 16)
	binary.BigEndian.PutUint64(id[8:], uint64(n))
	return id
}

// A reader that read the table before a revocation committed must not cache
// what it read: CapRevoked would go on answering "not revoked" for a revoked
// credential. put is given the generation the reader saw before reading;
// every revocation and every deregistration advances it.
func TestRevokedCacheDropsARacedRead(t *testing.T) {
	var c revokedCache
	now := time.Now()
	id := cacheID(1)

	gen := c.generation()                         // the reader starts
	c.add("owner", [][]byte{id}, now.UnixMilli()) // a revocation commits
	c.put(gen, "owner", id, 0)                    // the reader caches "not revoked"
	if _, ok := c.get("owner", id, now); ok {
		t.Fatal("a read that raced with a revocation was cached")
	}

	gen = c.generation()
	c.forget() // a deregistration
	c.put(gen, "owner", id, now.UnixMilli())
	if _, ok := c.get("owner", id, now); ok {
		t.Fatal("a read that raced with a deregistration was cached")
	}

	// Without a race the read is cached, and a later revocation of a
	// cached id marks it revoked.
	c.put(c.generation(), "owner", id, 0)
	if v, ok := c.get("owner", id, now); !ok || v {
		t.Fatalf("an uncontested read: cached %v, revoked %v", ok, v)
	}
	c.add("owner", [][]byte{id}, now.UnixMilli())
	if v, ok := c.get("owner", id, now); !ok || !v {
		t.Fatalf("after a revocation the cached entry says revoked %v (cached %v)", v, ok)
	}
	if v, _ := c.get("owner", id, now.Add(RevocationKeep)); v {
		t.Fatal("a cached revocation outlives its 31 days")
	}
}

// The cache holds at most revokedCacheSize entries, dropping the least
// recently used.
func TestRevokedCacheIsBounded(t *testing.T) {
	var c revokedCache
	now := time.Now()
	for i := 0; i < revokedCacheSize+10; i++ {
		c.put(c.generation(), "owner", cacheID(i), 0)
		if i == revokedCacheSize-1 {
			c.get("owner", cacheID(0), now) // 0 is used again just before the cache is full
		}
	}
	if n := c.order.Len(); n != revokedCacheSize || len(c.entries) != revokedCacheSize {
		t.Fatalf("%d entries (%d in the map), want %d", n, len(c.entries), revokedCacheSize)
	}
	if _, ok := c.get("owner", cacheID(0), now); !ok {
		t.Error("a recently used entry was dropped")
	}
	if _, ok := c.get("owner", cacheID(1), now); ok {
		t.Error("the least recently used entry was kept")
	}
}
