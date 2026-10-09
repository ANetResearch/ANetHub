package aghub

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/seal"
)

// FuzzKidAndMore runs a script of key set publications, clock steps,
// envelopes queued for one recipient (sealed to a key it publishes, one it
// published before, or a random one; some with an outer exp), polls and
// acks against the store, and checks it against a model of forward-secrecy
// §4.2:
//
//   - an envelope is queued if and only if its kid is in the recipient's
//     current key set and the clock is at most D past that key's not_after
//     (FS-H1); a refusal is ErrKidStale and queues nothing;
//   - a publication that follows the stored set is stored, the stored set
//     sent again is unchanged whatever its prev_seq, and one that follows an
//     older set is a *KeysRollbackError naming the stored seq (FS-H4);
//   - a page holds the returnable envelopes (not acked, exp unset or after
//     now) in id order, as many as the limit and the byte budget allow (the
//     first always), and more says whether a returnable one follows it
//     (FS-H5, CUX-H2).
//
// Script bytes are read in pairs (op, arg).
func FuzzKidAndMore(f *testing.F) {
	for _, s := range []string{
		"\x02\x00\x02\x01\x03\x01\x03\x05",                 // two queued, a page of one and of two
		"\x02\x00\x00\x01\x02\x01\x02\x00\x03\x04",         // a key replaced, the old one refused
		"\x02\x00\x01\x60\x02\x00\x01\x05\x02\x00\x03\x09", // past not_after, then past D
		"\x02\x82\x02\x8f\x01\x01\x03\x04\x04\x00\x03\x04", // with exp, a step past it, an ack
		"\x05\x00\x05\x01\x00\x00\x05\x02\x02\x02\x03\x07", // republications, a random kid
	} {
		f.Add([]byte(s))
	}
	h := newRelayHub(f)
	start := h.nowMS()
	f.Fuzz(func(t *testing.T, script []byte) {
		if len(script) > 200 {
			script = script[:200]
		}
		h.setClockMS(start) // each script starts at the same time, with a new recipient
		fz := &kidModel{t: t, h: h, a: fuzzRecipient(t, h), keys: map[[seal.KIDLen]byte]uint64{}}
		k := fixtureKey(t, fz.a.aid)
		fz.keys[[seal.KIDLen]byte(k.KID)] = k.NotAfter
		fz.history = append(fz.history, k.KID)
		fz.storedSeq = fz.seqOf()
		for i := 0; i+1 < len(script); i += 2 {
			fz.step(script[i], script[i+1])
		}
	})
}

// fuzzRecipient is h.agent for a fuzz iteration: errors go to t.
func fuzzRecipient(t *testing.T, h *relayHub) *relayAgent {
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	kel, err := identity.MarshalKEL(c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutAgent(c.AID(), "n", nil, kel); err != nil {
		t.Fatal(err)
	}
	a := &relayAgent{c: c, aid: c.AID()}
	fixturePublish(t, h.store, a, 1, h.clock())
	return a
}

// kidModel is FuzzKidAndMore's model of one recipient.
type kidModel struct {
	t         *testing.T
	h         *relayHub
	a         *relayAgent
	keys      map[[seal.KIDLen]byte]uint64 // the current set: kid -> not_after
	history   [][]byte                     // every kid ever published
	storedSeq uint64
	storedRaw []byte
	rows      []kidRow // queued and not acked, in id order
	n         int
}

type kidRow struct {
	id   int64
	size int64
	exp  *uint64
}

func (m *kidModel) seqOf() uint64 {
	var seq uint64
	var raw []byte
	if err := m.h.store.db.QueryRow(`SELECT seq, keyset FROM agent_keys WHERE aid=?`, m.a.aid).Scan(&seq, &raw); err != nil {
		m.t.Fatal(err)
	}
	m.storedRaw = raw
	return seq
}

func (m *kidModel) step(op, arg byte) {
	t, h := m.t, m.h
	now := h.nowMS()
	switch op % 6 {
	case 0: // a new set, keeping the mailbox key: one or two keys valid now
		var keys []seal.EncKey
		for j := 0; j <= int(arg%2); j++ {
			nb := now - 60_000 + uint64(j)*3_600_000
			kp, err := seal.GenerateKeyPair(seal.SuiteX25519, nb, nb+uint64(arg%4+1)*12*3_600_000)
			if err != nil {
				t.Fatal(err)
			}
			keys = append(keys, kp.Public)
		}
		set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: m.a.aid, Seq: m.storedSeq + 1 + uint64(arg),
			Keys: keys, IssuedAt: now, Mbox: m.a.mbox}
		signed, err := seal.SignEncKeySet(set, m.a.c.Sign)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := signed.Marshal()
		if st, err := h.store.PublishKeys(m.a.aid, raw, m.storedSeq, m.a.c.KEL(), h.clock()); err != nil || st != KeysStatusOK {
			t.Fatalf("a set following the stored one: %s %v", st, err)
		}
		m.keys = map[[seal.KIDLen]byte]uint64{}
		for _, k := range keys {
			m.keys[[seal.KIDLen]byte(k.KID)] = k.NotAfter
			m.history = append(m.history, k.KID)
		}
		m.storedSeq = m.seqOf()
	case 1: // the clock steps forward
		h.advance(time.Duration(arg) * 15 * time.Minute)
	case 2: // an envelope
		var kid []byte
		switch arg % 3 {
		case 0:
			var cur [][]byte
			for k := range m.keys {
				cur = append(cur, append([]byte(nil), k[:]...))
			}
			sort.Slice(cur, func(i, j int) bool { return bytes.Compare(cur[i], cur[j]) < 0 })
			kid = cur[int(arg/3)%len(cur)]
		case 1:
			kid = m.history[int(arg/3)%len(m.history)]
		default:
			kid = make([]byte, seal.KIDLen)
			_, _ = rand.Read(kid)
		}
		var exp *uint64
		if arg&0x80 != 0 {
			e := now + uint64(arg%16)*60_000
			exp = &e
		}
		m.n++
		ct := bytes.Repeat([]byte{'k'}, 16+int(arg%8)*100)
		copy(ct, strconv.Itoa(m.n)+" ")
		env, err := (&seal.SealedEnvelope{V: seal.EnvelopeVersion, To: m.a.aid, Suite: seal.SuiteX25519, KID: kid,
			Enc: bytes.Repeat([]byte{9}, 32), CT: ct, Access: &seal.Access{Kind: seal.AccessKindSession}, Exp: exp}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		na, inSet := m.keys[[seal.KIDLen]byte(kid)]
		want := inSet && now <= na+seal.DeliveryDeadlineMS
		q, err := h.store.QueueEnvelope(m.a.aid, env)
		switch {
		case want && err != nil:
			t.Fatalf("kid in the set, %d ms past its not_after: refused %v", int64(now)-int64(na), err)
		case !want && err == nil:
			t.Fatalf("kid in the set %v, %d ms past its not_after: queued", inSet, int64(now)-int64(na))
		case !want && !errors.Is(err, ErrKidStale):
			t.Fatalf("refused with %v, want kid_stale", err)
		case want:
			m.rows = append(m.rows, kidRow{id: q.ID, size: int64(len(env)), exp: exp})
		}
	case 3: // a page
		limit, budget := int(arg%5)+1, int64(arg/5%4+1)*600
		msgs, more, err := h.store.RelayPoll(m.a.aid, 0, limit, budget)
		if err != nil {
			t.Fatal(err)
		}
		var page []int64
		var acc int64
		wantMore := false
		for _, r := range m.rows {
			if r.exp != nil && *r.exp <= now {
				continue
			}
			if len(page) == limit || len(page) > 0 && acc+r.size > budget {
				wantMore = true
				break
			}
			acc += r.size
			page = append(page, r.id)
		}
		if len(msgs) != len(page) || more != wantMore {
			t.Fatalf("limit %d, budget %d: %d messages, more %v; want %d, more %v", limit, budget, len(msgs), more, len(page), wantMore)
		}
		for i, msg := range msgs {
			if msg.ID != page[i] {
				t.Fatalf("message %d is %d, want %d", i, msg.ID, page[i])
			}
		}
	case 4: // the first rows acked
		n := int(arg%3) + 1
		var ids []int64
		for len(ids) < n && len(m.rows) > 0 {
			ids = append(ids, m.rows[0].id)
			m.rows = m.rows[1:]
		}
		if _, err := h.store.RelayAck(m.a.aid, ids); err != nil {
			t.Fatal(err)
		}
	case 5: // the stored set again, or a set that follows an older one
		if arg%2 == 0 {
			if st, err := h.store.PublishKeys(m.a.aid, m.storedRaw, uint64(arg), m.a.c.KEL(), h.clock()); err != nil {
				// A stored set that has expired by now no longer verifies.
				if !errors.Is(err, ErrKeysInvalid) {
					t.Fatalf("the stored set again: %v", err)
				}
			} else if st != KeysStatusUnchanged {
				t.Fatalf("the stored set again: %s", st)
			}
			return
		}
		kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now-60_000+seal.MaxKeyValidityMS)
		if err != nil {
			t.Fatal(err)
		}
		set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: m.a.aid, Seq: m.storedSeq + 10,
			Keys: []seal.EncKey{kp.Public}, IssuedAt: now, Mbox: m.a.mbox}
		signed, _ := seal.SignEncKeySet(set, m.a.c.Sign)
		raw, _ := signed.Marshal()
		_, err = h.store.PublishKeys(m.a.aid, raw, m.storedSeq-1, m.a.c.KEL(), h.clock())
		var rb *KeysRollbackError
		if !errors.As(err, &rb) || rb.StoredSeq != m.storedSeq {
			t.Fatalf("a set following seq %d with %d stored: %v", m.storedSeq-1, m.storedSeq, err)
		}
	}
}
