package aghub_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// FuzzHubMailboxRevoke (sealed-sender SSR-H10, SSR-H11; core CORE-E5,
// CORE-E7): an owner posts fuzzed /mailbox/revoke bodies, raw or built from
// fuzzed ids (some spelled wrong). Properties:
//
//   - no answer is a 5xx;
//   - 200 exactly for one JSON object {"cap_ids": [...]} with 1 to 1000
//     ids, each 16 bytes in base64url's one spelling;
//   - on 200, revoked is how many distinct ids were not revoked before,
//     total is the owner's count afterwards, and every id is revoked;
//   - any other answer leaves the owner's revocations as they were; 429
//     only when the new ids would pass the bound (revocation_list_full).
func FuzzHubMailboxRevoke(f *testing.F) {
	h := newFZ(f)
	owner, _ := h.agent(f, "fuzz-revoke", nil, false)
	f.Add(uint8(0), []byte(`{"cap_ids":["AAAAAAAAAAAAAAAAAAAAAA"]}`))
	f.Add(uint8(0), []byte(`{"cap_ids":[]}`))
	f.Add(uint8(0), []byte(`{"cap_ids":["AAAAAAAAAAAAAAAAAAAAAA=="]}`))
	f.Add(uint8(0), []byte(`{"cap_ids":["AAAAAAAAAAAAAAAAAAAAAB"]}`))
	f.Add(uint8(0), []byte(`{"cap_ids":["AAAAAAAAAAAAAAAAAAAAAA"],"cap_ids":[]}`))
	f.Add(uint8(0), []byte(`{"cap_ids":"AAAAAAAAAAAAAAAAAAAAAA"}`))
	f.Add(uint8(1), bytes.Repeat([]byte{1}, 48))
	f.Add(uint8(2), bytes.Repeat([]byte{2, 3}, 40))
	f.Add(uint8(3), []byte("0123456789abcdef"))
	f.Add(uint8(4), []byte("0123456789abcdef0123456789abcdef"))
	f.Add(uint8(5), []byte("0123456789abcdef"))

	f.Fuzz(func(t *testing.T, mode uint8, raw []byte) {
		raw = clipB(raw, 64<<10)
		var body []byte
		var ids [][]byte // the ids the body names, when built
		valid := false
		switch mode % 6 {
		case 0:
			body = raw
		default:
			// Up to 64 ids of 16 bytes from raw, from a small space (the
			// first byte's low 6 bits and one more byte), so ids repeat.
			var strs []string
			for i := 0; i+2 <= len(raw) && len(ids) < 64; i += 2 {
				id := make([]byte, seal.CapIDLen)
				id[0], id[15] = raw[i]&0x3f, raw[i+1]
				ids = append(ids, id)
				strs = append(strs, base64.RawURLEncoding.EncodeToString(id))
			}
			valid = len(ids) > 0
			if len(strs) > 0 {
				last := len(strs) - 1
				switch mode % 6 {
				case 2:
					strs[last] += "=="
					valid = false
				case 3:
					strs[last] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 16))
					valid = false
				case 4:
					strs[last] = strs[last][:len(strs[last])-1]
					valid = false
				case 5:
					strs[last] = base64.RawURLEncoding.EncodeToString(append(ids[last], 0))
					valid = false
				}
			}
			if strs == nil {
				strs = []string{}
			}
			body = fzJSON(t, map[string]any{"cap_ids": strs})
		}
		countBefore, err := h.store.RevocationCount(owner.AID())
		if err != nil {
			t.Fatal(err)
		}
		fresh := map[string]bool{}
		for _, id := range ids {
			if r, err := h.store.CapRevoked(owner.AID(), id); err != nil {
				t.Fatal(err)
			} else if !r {
				fresh[string(id)] = true
			}
		}
		rec := h.signedDo(owner, relayauth.ActionRevoke, http.MethodPost, "/mailbox/revoke", "", body)
		if !allowed(rec.Code, 200, 400, 413, 429) {
			t.Fatalf("revoke: unexpected %d %s", rec.Code, rec.Body.Bytes())
		}
		if rec.Code == http.StatusTooManyRequests {
			if !bytes.Contains(rec.Body.Bytes(), []byte(`"revocation_list_full"`)) ||
				mode%6 != 0 && countBefore+len(fresh) <= aghub.MaxRevocationsPerOwner {
				t.Fatalf("429 with %d revocations and %d new: %s", countBefore, len(fresh), rec.Body.Bytes())
			}
		}
		countAfter, err := h.store.RevocationCount(owner.AID())
		if err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK {
			if countAfter != countBefore {
				t.Fatalf("a refused request (%d) changed the count from %d to %d", rec.Code, countBefore, countAfter)
			}
			if mode%6 != 0 && valid && rec.Code != http.StatusTooManyRequests {
				t.Fatalf("a well-formed request of %d ids was refused: %d %s", len(ids), rec.Code, rec.Body.Bytes())
			}
			return
		}
		if mode%6 != 0 && !valid {
			t.Fatalf("a malformed id was accepted: %s", body)
		}
		var out aghub.MailboxRevokeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if mode%6 != 0 && out.Revoked != uint64(len(fresh)) {
			t.Fatalf("revoked %d, want the %d distinct ids not revoked before", out.Revoked, len(fresh))
		}
		if out.Total != uint64(countAfter) || countAfter != countBefore+int(out.Revoked) {
			t.Fatalf("total %d, revoked %d: the count went from %d to %d", out.Total, out.Revoked, countBefore, countAfter)
		}
		if mode%6 == 0 {
			// A raw body that was accepted names ids; read them back.
			var req aghub.MailboxRevokeRequest
			if err := json.Unmarshal(body, &req); err != nil || len(req.CapIDs) == 0 || len(req.CapIDs) > aghub.MaxRevokeBatch {
				t.Fatalf("accepted a body that is not 1 to 1000 ids: %q", body)
			}
			for _, s := range req.CapIDs {
				id, err := base64.RawURLEncoding.Strict().DecodeString(s)
				if err != nil || len(id) != seal.CapIDLen || base64.RawURLEncoding.EncodeToString(id) != s {
					t.Fatalf("accepted the id %q", s)
				}
				ids = append(ids, id)
			}
		}
		for _, id := range ids {
			if r, _ := h.store.CapRevoked(owner.AID(), id); !r {
				t.Fatalf("an id of an accepted request is not revoked: %x", id)
			}
		}
	})
}
