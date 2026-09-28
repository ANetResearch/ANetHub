package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// goldenA2ACard is ANetCore's conformance card (a2acard/testdata), a
// structurally complete card signed by an identity this hub never holds.
func goldenA2ACard(tb testing.TB) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "ANetCore", "a2acard", "testdata", "golden-card.json"))
	if err != nil {
		return []byte(`{"name":"golden card missing"}`)
	}
	return bytes.TrimSpace(b)
}

// verifiesFor reports whether card verifies as aid's own card against kel
// now, the way a consumer of the registry checks it.
func verifiesFor(card []byte, aid string, kel []identity.SignedEvent) error {
	v, err := a2acard.Verify(card, func(a string) ([]identity.SignedEvent, error) {
		if a != aid {
			return nil, os.ErrNotExist
		}
		return kel, nil
	}, uint64(time.Now().UnixMilli()))
	if err != nil {
		return err
	}
	if v.AID != aid {
		return os.ErrInvalid
	}
	return nil
}

// indexInvariants: whatever the hub holds for aid in the A2A registry and
// its skill and tag indexes comes from a card that verifies against the
// KEL it holds for aid; with no such card, aid is in no index.
func indexInvariants(t *testing.T, h *fz, aid string) {
	t.Helper()
	card, err := h.store.VerifiedA2ACard(aid, false)
	if err != nil {
		t.Fatal(err)
	}
	skills := h.count(t, `SELECT COUNT(*) FROM agent_skill WHERE aid=?`, aid)
	tags := h.count(t, `SELECT COUNT(*) FROM agent_tag WHERE aid=?`, aid)
	if card == nil {
		if skills != 0 || tags != 0 {
			t.Fatalf("%s has no verified A2A card but %d skill and %d tag index rows", aid, skills, tags)
		}
		return
	}
	kelBytes, err := h.store.AgentKEL(aid)
	if err != nil {
		t.Fatalf("a verified A2A card is listed for %s, which is not registered: %v", aid, err)
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifiesFor(card, aid, kel); err != nil {
		t.Fatalf("the registry lists a card for %s that does not verify against its KEL: %v", aid, err)
	}
}

// FuzzHubRegister fuzzes a registration: profile text, capability list,
// ADP card, A2A card, encryption key set and KEL, each either valid,
// another agent's, mutated, or raw fuzz bytes. The request is always
// signed by the registrant. Properties:
//
//   - the answer is 200, 400, 401, 409 or 413, never a 5xx;
//   - 200 only for a KEL that replays to the AID claimed, and the hub
//     then holds exactly that KEL;
//   - an A2A card is listed only if it verifies against that KEL, and the
//     skill and tag indexes hold nothing for an agent without one;
//   - a key set is stored only if it verifies for the agent;
//   - a refused first registration leaves no agent, card or balance
//     behind, and a first registration is granted exactly once;
//   - the ledger invariants hold.
func FuzzHubRegister(f *testing.F) {
	h := newFZ(f)
	regular, _ := h.agent(f, "fuzz-regular", []string{"fuzz.reg"}, true)
	stranger, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	// A KEL past seal.MaxKELEvents, built once: no sender accepts it, and
	// neither may /register [redteam:F36].
	big, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	for i := 0; i <= seal.MaxKELEvents; i++ {
		if err := big.Rotate(uint64(time.Now().UnixMilli())); err != nil {
			f.Fatal(err)
		}
	}
	golden := goldenA2ACard(f)

	f.Add(uint8(0), "agent", "a.b,c.d", "sum", "readme", "price", uint8(1), []byte(nil), uint8(1), []byte(nil), uint8(1), []byte(nil), uint8(0), []byte(nil), uint64(1))
	f.Add(uint8(1), "again", "a.b", "", "", "", uint8(1), []byte(nil), uint8(1), []byte(nil), uint8(5), []byte(nil), uint8(0), []byte(nil), uint64(2))
	f.Add(uint8(2), "rotated", "", "", "", "", uint8(0), []byte(nil), uint8(1), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint64(1))
	f.Add(uint8(0), "raw card", "x", "", "", "", uint8(2), []byte(`{"subject_did":"x"}`), uint8(2), golden, uint8(2), []byte{1, 2, 3}, uint8(0), []byte(nil), uint64(0))
	f.Add(uint8(0), "others", "x", "", "", "", uint8(3), []byte(nil), uint8(5), []byte(nil), uint8(4), []byte(nil), uint8(3), []byte(nil), uint64(0))
	f.Add(uint8(0), "mutated", "x", "", "", "", uint8(4), []byte{9}, uint8(3), []byte{17}, uint8(6), []byte{3}, uint8(2), []byte{5}, uint64(0))
	f.Add(uint8(0), "big kel", "", "", "", "", uint8(0), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint8(4), []byte(nil), uint64(0))
	f.Add(uint8(1), "withdraw", "", "", "", "", uint8(0), []byte(nil), uint8(4), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint64(0))
	f.Add(uint8(3), "raw body", "", "", "", "", uint8(0), []byte(`{"aid":"x","kel":"AAAA"}`), uint8(0), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint64(0))
	f.Add(uint8(1), "big seq", "a.b", "", "", "", uint8(1), []byte(nil), uint8(1), []byte(nil), uint8(5), []byte(nil), uint8(0), []byte(nil), uint64(math.MaxInt64))
	f.Add(uint8(0), "long caps", strings.Repeat("c,", 300), "", "", "", uint8(1), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint8(0), []byte(nil), uint64(0))

	f.Fuzz(func(t *testing.T, who uint8, name, capsRaw, summary, readme, pricing string,
		cardMode uint8, cardRaw []byte, a2aMode uint8, a2aRaw []byte, keysMode uint8, keysRaw []byte,
		kelMode uint8, kelRaw []byte, seq uint64) {
		name, summary, readme, pricing = clip(name, 512), clip(summary, 2048), clip(readme, 4096), clip(pricing, 512)
		capsRaw = clip(capsRaw, 80<<10)
		cardRaw, a2aRaw, keysRaw, kelRaw = clipB(cardRaw, 16<<10), clipB(a2aRaw, 70<<10), clipB(keysRaw, 8<<10), clipB(kelRaw, 16<<10)

		// The registrant: a new identity, the one registered at setup
		// (re-registration), or a new identity rotated a few times.
		c := regular
		if who%4 != 1 {
			if c, err = identity.Incept(); err != nil {
				t.Fatal(err)
			}
			if who%4 == 2 {
				for i := 0; i < int(seq%3)+1; i++ {
					if err := c.Rotate(uint64(time.Now().UnixMilli())); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		fresh := !h.store.KnowsAgent(c.AID())
		var caps []string
		if capsRaw != "" {
			caps = strings.Split(capsRaw, ",")
		}

		kel, err := identity.MarshalKEL(c.KEL())
		if err != nil {
			t.Fatal(err)
		}
		switch kelMode % 5 {
		case 1:
			kel = kelRaw
		case 2:
			if len(kelRaw) > 0 {
				kel = append([]byte(nil), kel...)
				i := int(kelRaw[0]) * 7 % len(kel)
				kel[i] ^= 1 << (kelRaw[0] % 8)
			}
		case 3:
			kel, _ = identity.MarshalKEL(stranger.KEL())
		case 4:
			kel, _ = identity.MarshalKEL(big.KEL())
		}
		body := map[string]any{
			"aid": c.AID(), "name": name, "caps": caps,
			"summary": summary, "readme": readme, "pricing": pricing,
			"kel": base64.StdEncoding.EncodeToString(kel),
		}
		switch cardMode % 5 {
		case 1:
			body["card"] = fzADPCard(t, c, name, caps)
		case 2:
			if json.Valid(cardRaw) {
				body["card"] = json.RawMessage(cardRaw)
			}
		case 3:
			body["card"] = fzADPCard(t, stranger, name, caps)
		case 4:
			card := []byte(fzADPCard(t, c, name, caps))
			if len(cardRaw) > 0 {
				card[int(cardRaw[0])%len(card)] ^= 1
			}
			if json.Valid(card) {
				body["card"] = json.RawMessage(card)
			}
		}
		skills := func(card map[string]any) {
			if capsRaw == "" {
				return
			}
			var out []any
			for i, id := range caps {
				if i == 4 {
					break
				}
				out = append(out, map[string]any{"id": id, "name": clip(name, 64), "description": "d",
					"tags": []any{clip(summary, 32)}})
			}
			card["skills"] = out
		}
		switch a2aMode % 7 {
		case 1:
			body["a2a_card"] = fzA2ACardOrRaw(t, c, seq, skills)
		case 2:
			if json.Valid(a2aRaw) {
				body["a2a_card"] = json.RawMessage(a2aRaw)
			}
		case 3:
			card := []byte(fzA2ACardOrRaw(t, c, seq, skills))
			if len(a2aRaw) > 0 {
				card[int(a2aRaw[0])*13%len(card)] ^= 1 << (a2aRaw[0] % 7)
			}
			if json.Valid(card) {
				body["a2a_card"] = json.RawMessage(card)
			}
		case 4:
			body["a2a_card"] = json.RawMessage(`null`)
		case 5:
			body["a2a_card"] = fzA2ACard(t, stranger, seq)
		case 6:
			body["a2a_card"] = json.RawMessage(golden)
		}
		switch keysMode % 7 {
		case 1:
			raw, _ := fzKeySet(t, c, seq|1, 0)
			body["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
		case 2:
			body["enc_keys"] = base64.StdEncoding.EncodeToString(keysRaw)
		case 3:
			body["enc_keys"] = string(keysRaw)
		case 4:
			raw, _ := fzKeySet(t, stranger, seq|1, 0)
			body["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
		case 5:
			var shift int64
			if len(keysRaw) > 0 {
				shift = int64(int8(keysRaw[0])) * 86_400_000 / 8
			}
			raw, _ := fzKeySet(t, c, seq, shift)
			body["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
		case 6:
			raw, _ := fzKeySet(t, c, seq|1, 0)
			if len(keysRaw) > 0 {
				raw[int(keysRaw[0])%len(raw)] ^= 1
			}
			body["enc_keys"] = base64.StdEncoding.EncodeToString(raw)
		}
		raw := fzJSON(t, body)
		if who%4 == 3 {
			raw = cardRaw
		}

		balBefore := h.balance(t, c.AID())
		rec := h.register(c, raw)
		if !allowed(rec.Code, 200, 400, 401, 409, 413) {
			t.Fatalf("register: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		defer indexInvariants(t, h, c.AID())
		defer h.ledgerInvariants(t)
		if rec.Code != http.StatusOK {
			if fresh {
				if h.store.KnowsAgent(c.AID()) {
					t.Fatalf("a refused registration (%d) left an agent row", rec.Code)
				}
				if b := h.balance(t, c.AID()); b != 0 {
					t.Fatalf("a refused registration (%d) left a balance of %d", rec.Code, b)
				}
			}
			return
		}
		var out aghub.RegisterResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.AID != c.AID() || out.Status != "registered" {
			t.Fatalf("register answered 200 with %s", rec.Body.Bytes())
		}
		var sent aghub.RegisterRequest
		if err := json.Unmarshal(raw, &sent); err != nil {
			t.Fatalf("a body that does not decode was registered: %v", err)
		}
		sentKEL, err := base64.StdEncoding.DecodeString(sent.KEL)
		if err != nil {
			t.Fatal(err)
		}
		events, err := identity.UnmarshalKEL(sentKEL)
		if err != nil {
			t.Fatalf("an undecodable KEL was registered: %v", err)
		}
		states, err := identity.Replay(events)
		if err != nil || states[len(states)-1].AID != c.AID() {
			t.Fatalf("a KEL that does not replay to %s was registered: %v", c.AID(), err)
		}
		stored, err := h.store.AgentKEL(c.AID())
		if err != nil || !bytes.Equal(stored, sentKEL) {
			t.Fatalf("the hub holds another KEL than the one registered: %v", err)
		}
		if fresh && h.balance(t, c.AID())-balBefore != aghub.RegistrationGrant {
			t.Fatalf("first registration granted %d", h.balance(t, c.AID())-balBefore)
		}
		if !fresh && h.balance(t, c.AID()) != balBefore {
			t.Fatalf("re-registration moved the balance %d -> %d", balBefore, h.balance(t, c.AID()))
		}
		if out.KeysStatus == aghub.KeysStatusOK || out.KeysStatus == aghub.KeysStatusUnchanged {
			ks, kl, _, err := h.store.LocalKeys(c.AID())
			if err != nil {
				t.Fatal(err)
			}
			signed, err := seal.UnmarshalSignedEncKeySet(ks)
			if err != nil {
				t.Fatal(err)
			}
			ev, err := identity.UnmarshalKEL(kl)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := seal.VerifyEncKeySet(signed, c.AID(), ev, uint64(time.Now().UnixMilli())); err != nil {
				t.Fatalf("keys_status %s for a key set that does not verify: %v", out.KeysStatus, err)
			}
		}
		if fresh && out.CardStatus != aghub.CardStatusOK && out.CardStatus != aghub.CardStatusUnchanged {
			if card, _ := h.store.VerifiedA2ACard(c.AID(), false); card != nil {
				t.Fatalf("card_status %s, yet a card is listed", out.CardStatus)
			}
		}
	})
}

// FuzzHubKeys publishes key sets (valid with fuzzed terms, another
// agent's, mutated, or raw bytes) and looks up keys, KELs and cards with
// fuzzed bodies and paths. Properties:
//
//   - POST /agents/{aid}/keys answers 200, 400 or 409; 200 "ok" only for
//     a set whose seq is above the stored one, "unchanged" only for the
//     stored seq; after any answer the stored set verifies for the agent,
//     and a refusal leaves it as it was;
//   - the lookups answer 200, 400, 404 or 413 and never serve a key set,
//     KEL or card that does not verify for the AID that was asked for.
func FuzzHubKeys(f *testing.F) {
	h := newFZ(f)
	k, _ := h.agent(f, "fuzz-keys", nil, true)
	other, _ := h.agent(f, "fuzz-keys-other", nil, false)
	withCard, _ := h.agent(f, "fuzz-keys-card", nil, true)
	if rec := h.register(withCard, fzJSON(f, func() map[string]any {
		b := h.registration(f, withCard, "fuzz-keys-card", nil)
		b["a2a_card"] = fzA2ACard(f, withCard, 1)
		return b
	}())); rec.Code != http.StatusOK {
		f.Fatalf("register with card: %d %s", rec.Code, rec.Body.Bytes())
	}
	stranger, _ := identity.Incept()

	f.Add(uint8(0), uint64(2), int64(0), []byte(nil), []byte(`{"aid":"`+k.AID()+`"}`), k.AID())
	f.Add(uint8(0), uint64(1), int64(0), []byte(nil), []byte(`{"aid":"`+other.AID()+`"}`), other.AID())
	f.Add(uint8(1), uint64(0), int64(0), []byte{1, 2}, []byte(`{"aid":"`+withCard.AID()+`"}`), withCard.AID())
	f.Add(uint8(2), uint64(9), int64(0), []byte{40}, []byte(`{"aid":""}`), "")
	f.Add(uint8(3), uint64(10), int64(0), []byte(nil), []byte(`{"aid":"`+h.hubAID+`"}`), h.hubAID)
	f.Add(uint8(4), uint64(0), int64(0), []byte(`{"keyset":"!!"}`), []byte(`{}`), "x/y")
	f.Add(uint8(0), uint64(1<<63), int64(-86_400_000*30), []byte(nil), []byte(`null`), "%zz")
	// Go's fuzzer changes an integer by at most 100 per mutation, so the
	// int64 boundary has to come from a seed.
	f.Add(uint8(0), uint64(math.MaxInt64), int64(0), []byte(nil), []byte(`{"aid":"`+k.AID()+`"}`), k.AID())

	f.Fuzz(func(t *testing.T, mode uint8, seq uint64, shift int64, raw, lookup []byte, getAID string) {
		raw, lookup, getAID = clipB(raw, 8<<10), clipB(lookup, 8<<10), clip(getAID, 512)
		shift %= 60 * 86_400_000
		before, _, _, _ := h.store.LocalKeys(k.AID())
		var body []byte
		switch mode % 5 {
		case 0:
			ks, _ := fzKeySet(t, k, seq, shift)
			body = fzJSON(t, map[string]any{"keyset": base64.StdEncoding.EncodeToString(ks)})
		case 1:
			body = fzJSON(t, map[string]any{"keyset": base64.StdEncoding.EncodeToString(raw)})
		case 2:
			ks, _ := fzKeySet(t, k, seq, shift)
			if len(raw) > 0 {
				ks[int(raw[0])%len(ks)] ^= 1 << (raw[0] % 8)
			}
			body = fzJSON(t, map[string]any{"keyset": base64.StdEncoding.EncodeToString(ks)})
		case 3:
			// Named for k, signed by somebody else.
			now := uint64(time.Now().UnixMilli())
			kp, err := seal.GenerateKeyPair(seal.SuiteX25519, now-60_000, now+seal.KeyLifetimeMS)
			if err != nil {
				t.Fatal(err)
			}
			set := &seal.EncKeySet{Type: seal.EncKeySetType, AID: k.AID(), Seq: seq,
				Keys: []seal.EncKey{kp.Public}, IssuedAt: now}
			signed, err := seal.SignEncKeySet(set, stranger.Sign)
			if err != nil {
				t.Fatal(err)
			}
			ks, _ := signed.Marshal()
			body = fzJSON(t, map[string]any{"keyset": base64.StdEncoding.EncodeToString(ks)})
		case 4:
			body = raw
		}
		rec := h.signedDo(k, relayauth.ActionKeys, http.MethodPost, "/agents/"+k.AID()+"/keys", "", body)
		if !allowed(rec.Code, 200, 400, 409) {
			t.Fatalf("publish: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		after, kelBytes, _, _ := h.store.LocalKeys(k.AID())
		afterSet, err := seal.UnmarshalSignedEncKeySet(after)
		if err != nil {
			t.Fatal(err)
		}
		kel, _ := identity.UnmarshalKEL(kelBytes)
		now := uint64(time.Now().UnixMilli())
		if rec.Code != http.StatusOK {
			if !bytes.Equal(before, after) {
				t.Fatalf("a refused publish (%d) changed the stored key set", rec.Code)
			}
		} else {
			var out aghub.KeysPublishResponse
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			set, err := seal.VerifyEncKeySet(afterSet, k.AID(), kel, now)
			if err != nil {
				t.Fatalf("keys_status %s for a set that does not verify: %v", out.KeysStatus, err)
			}
			var priorSeq uint64
			if p := decodeSetSeq(before); p != nil {
				priorSeq = *p
			}
			switch out.KeysStatus {
			case aghub.KeysStatusOK:
				if set.Seq <= priorSeq {
					t.Fatalf("keys_status ok for seq %d over the stored %d", set.Seq, priorSeq)
				}
			case aghub.KeysStatusUnchanged:
				if set.Seq != priorSeq {
					t.Fatalf("keys_status unchanged for seq %d over the stored %d", set.Seq, priorSeq)
				}
			default:
				t.Fatalf("200 with keys_status %q", out.KeysStatus)
			}
		}

		// The lookups, with the fuzzed body and path.
		var lreq aghub.KeysLookupRequest
		lerr := json.Unmarshal(lookup, &lreq)
		for _, path := range []string{aghub.KeysLookupPath, aghub.KELLookupPath, aghub.CardLookupPath} {
			rec := h.serve(h.request(http.MethodPost, path, "", lookup))
			if !allowed(rec.Code, 200, 400, 404, 413) {
				t.Fatalf("%s %q: unexpected %d %s", path, lookup, rec.Code, rec.Body.Bytes())
			}
			if rec.Code == http.StatusOK && (lerr != nil || lreq.AID == "") {
				t.Fatalf("%s answered 200 for a body naming no AID: %q", path, lookup)
			}
			if rec.Code == http.StatusOK {
				checkLookup(t, h, path, lreq.AID, rec.Body.Bytes())
			}
		}
		for _, path := range []string{"/agents/" + url.PathEscape(getAID) + "/keys",
			"/agents/" + url.PathEscape(getAID) + "/kel", "/a2a/v1/agents/" + url.PathEscape(getAID) + "/card",
			"/agents/" + url.PathEscape(getAID) + "/jwks.json"} {
			rec := h.serve(h.request(http.MethodGet, path, "", nil))
			if !allowed(rec.Code, 200, 301, 307, 400, 404) {
				t.Fatalf("GET %s: unexpected %d %s", path, rec.Code, rec.Body.Bytes())
			}
		}
	})
}

// decodeSetSeq reads the seq of a stored signed key set.
func decodeSetSeq(raw []byte) *uint64 {
	signed, err := seal.UnmarshalSignedEncKeySet(raw)
	if err != nil {
		return nil
	}
	var set seal.EncKeySet
	if err := coredet.Unmarshal(signed.Set, &set); err != nil {
		return nil
	}
	return &set.Seq
}

// checkLookup verifies a 200 lookup answer for aid.
func checkLookup(t *testing.T, h *fz, path, aid string, body []byte) {
	t.Helper()
	switch path {
	case aghub.KeysLookupPath:
		var v aghub.KeysView
		if err := json.Unmarshal(body, &v); err != nil || v.AID != aid {
			t.Fatalf("keys lookup for %s answered %s", aid, body)
		}
		ks, _ := base64.StdEncoding.DecodeString(v.KeySet)
		kl, _ := base64.StdEncoding.DecodeString(v.KEL)
		signed, err := seal.UnmarshalSignedEncKeySet(ks)
		if err != nil {
			t.Fatalf("keys lookup served an undecodable set: %v", err)
		}
		kel, err := seal.ParseKEL(kl)
		if err != nil {
			t.Fatalf("keys lookup served a KEL no sender accepts: %v", err)
		}
		if _, err := seal.VerifyEncKeySet(signed, aid, kel, uint64(time.Now().UnixMilli())); err != nil {
			t.Fatalf("keys lookup for %s served a set that does not verify for it: %v", aid, err)
		}
	case aghub.KELLookupPath:
		var v struct {
			AID string `json:"aid"`
			KEL string `json:"kel"`
		}
		if err := json.Unmarshal(body, &v); err != nil || v.AID != aid {
			t.Fatalf("kel lookup for %s answered %s", aid, body)
		}
		kl, _ := base64.StdEncoding.DecodeString(v.KEL)
		kel, err := identity.UnmarshalKEL(kl)
		if err != nil {
			t.Fatal(err)
		}
		states, err := identity.Replay(kel)
		if err != nil || states[len(states)-1].AID != aid {
			t.Fatalf("kel lookup for %s served a KEL that is not its own: %v", aid, err)
		}
	case aghub.CardLookupPath:
		kelBytes, err := h.store.AgentKEL(aid)
		if err != nil {
			t.Fatalf("card lookup served a card for %s, which is not registered", aid)
		}
		kel, _ := identity.UnmarshalKEL(kelBytes)
		if err := verifiesFor(body, aid, kel); err != nil {
			t.Fatalf("card lookup for %s served a card that does not verify: %v", aid, err)
		}
	}
}
