package aghub

// FuzzRegisterAdmission fuzzes POST /register through the admission gate
// (hub-payment-privacy PAY-A1): the body (fields the fuzzer composes, or raw
// bytes), check_only, the proof of work, the admission mode and the
// registrant. Properties:
//
//   - never a 5xx; every refusal is a wire-3 error body of a hub code;
//   - a body that is a JSON object with a member "invite" is invite_removed;
//   - a refusal at the gate (admission_required, pow_required,
//     registration_quota) cost no KEL replay (PAY-A2);
//   - a refused registration of an unknown AID leaves no agent row and no
//     held place;
//   - check_only never writes;
//   - registration pays no credit.

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

func FuzzRegisterAdmission(f *testing.F) {
	g := newGateHub(f)
	listed, _ := identitytest.Hub()
	if _, err := g.store.Admit(listed.AID(), 0, "", false); err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), uint8(0), false, uint8(0), []byte(nil), []byte(nil), "", []byte(nil), false)
	f.Add(uint8(1), uint8(1), false, uint8(1), []byte(nil), []byte(nil), "", []byte(nil), false)
	f.Add(uint8(1), uint8(1), true, uint8(0), []byte(nil), []byte(nil), "", []byte(nil), false)
	f.Add(uint8(2), uint8(1), false, uint8(1), []byte(nil), []byte(nil), "", []byte(nil), false)
	f.Add(uint8(0), uint8(1), false, uint8(2), bytes.Repeat([]byte{7}, 32), []byte{1, 2}, "", []byte(nil), false)
	f.Add(uint8(0), uint8(0), false, uint8(0), []byte(nil), []byte(nil), `"invite":"x"`, []byte(nil), false)
	f.Add(uint8(0), uint8(0), false, uint8(0), []byte(nil), []byte(nil), `"zz":1,"invite":null`, []byte(nil), false)
	f.Add(uint8(0), uint8(0), false, uint8(0), []byte(nil), []byte(nil), "", []byte(`{"aid":"x","kel":"AAAA","invite":"y"}`), true)
	f.Add(uint8(1), uint8(1), false, uint8(3), []byte(nil), []byte(nil), `"pow":{"seed":"A=","nonce":"+/"}`, []byte(nil), false)

	f.Fuzz(func(t *testing.T, mode, who uint8, checkOnly bool, powMode uint8, seed, nonce []byte,
		extra string, raw []byte, useRaw bool) {
		if len(extra) > 4096 || len(raw) > 64<<10 || len(seed) > 64 || len(nonce) > 64 {
			return
		}
		g.t = t // the helpers report to this input's test
		switch mode % 3 {
		case 0:
			_ = g.store.SetAdmissionMode(AdmissionClosed)
		case 1:
			_ = g.store.SetAdmissionMode(AdmissionOpen)
		case 2:
			_ = g.store.SetAdmissionMode(AdmissionClosed)
			if _, ok, _ := openWindow(g.store.db, g.now); !ok {
				_, _ = g.store.OpenWindow(time.Hour, 3, "fuzz")
			}
		}
		var c *identity.Controller
		switch who % 3 {
		case 0:
			c = listed
		default:
			var err error
			if c, err = identitytest.Hub(); err != nil {
				t.Fatal(err)
			}
		}
		known := g.store.KnowsAgent(c.AID())
		body := raw
		if !useRaw {
			kel, _ := identity.MarshalKEL(c.KEL())
			m := map[string]any{"aid": c.AID(), "name": "fz", "kel": base64.RawURLEncoding.EncodeToString(kel)}
			if checkOnly {
				m["check_only"] = true
			}
			switch powMode % 4 {
			case 1:
				for k, v := range g.pow(c.AID(), "good") {
					m[k] = v
				}
			case 2:
				m["pow"] = map[string]any{"seed": base64.RawURLEncoding.EncodeToString(seed),
					"nonce": base64.RawURLEncoding.EncodeToString(nonce)}
			case 3:
				m["pow"] = map[string]any{"seed": string(seed), "nonce": string(nonce)}
			}
			b, err := json.Marshal(m)
			if err != nil {
				return
			}
			if extra != "" {
				b = append(append(b[:len(b)-1], ','), append([]byte(extra), '}')...)
			}
			body = b
		}
		before := g.light()
		replays := registerKELReplays.Load()
		code, out := g.post(c.AID(), c, body)

		if code >= 500 || code == 0 {
			t.Fatalf("register: %d %s", code, out["_raw"])
		}
		reason, _ := out["reason"].(string)
		if code != 200 {
			if !wire3.Known(wire3.Reason(reason)) {
				t.Fatalf("a refusal without a hub code: %d %s", code, out["_raw"])
			}
		}
		var top map[string]json.RawMessage
		if json.Unmarshal(body, &top) == nil {
			if _, ok := top["invite"]; ok && reason != "invite_removed" {
				t.Fatalf("a body with an invite member: %d %s", code, out["_raw"])
			}
		}
		switch reason {
		case "admission_required", "pow_required", "registration_quota":
			if d := registerKELReplays.Load() - replays; d != 0 {
				t.Fatalf("%s after %d KEL replay(s)", reason, d)
			}
		}
		if code != 200 && !known && g.store.KnowsAgent(c.AID()) {
			t.Fatalf("a refused registration (%d %s) left an agent row", code, reason)
		}
		if _, _, w := g.store.GateCountsForTest(); w != 0 {
			t.Fatalf("%d window places held after the request", w)
		}
		if code == 200 && out["status"] != "registered" {
			// check_only
			if after := g.light(); after != before {
				t.Fatalf("check_only wrote: %s -> %s", before, after)
			}
		}
		if bal, _ := g.store.Balance(c.AID()); bal != 0 {
			t.Fatalf("registration paid %d", bal)
		}
	})
}

// light is a cheap fingerprint of what registration writes.
func (g *gateHub) light() string {
	var agents, admitted, used, entries int
	_ = g.store.db.QueryRow(`SELECT COUNT(*) FROM agent`).Scan(&agents)
	_ = g.store.db.QueryRow(`SELECT COUNT(*) FROM admitted`).Scan(&admitted)
	_ = g.store.db.QueryRow(`SELECT COALESCE(SUM(used),0) FROM admission_window`).Scan(&used)
	_ = g.store.db.QueryRow(`SELECT COUNT(*) FROM credit_entry`).Scan(&entries)
	signup, trials, _ := g.store.GateCountsForTest()
	return fmt.Sprint(agents, admitted, used, entries, signup, trials)
}

// FuzzValidAID: ValidAID accepts exactly the canonical spelling of a
// 36-byte CIDv1 dag-cbor sha2-256 identifier.
func FuzzValidAID(f *testing.F) {
	c, _ := identitytest.Hub()
	f.Add(c.AID())
	f.Add("b" + strings.Repeat("a", 58))
	f.Add(strings.ToUpper(c.AID()))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		ok := ValidAID(s)
		if !ok {
			return
		}
		// An oracle of its own, not the implementation's tables: CIDv1
		// (0x01), dag-cbor (0x71), sha2-256 (0x12) of 32 bytes (0x20), in
		// lower-case unpadded base32 after the multibase "b".
		enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
		raw, err := enc.DecodeString(s[1:])
		if err != nil || len(raw) != 36 || !bytes.Equal(raw[:4], []byte{0x01, 0x71, 0x12, 0x20}) {
			t.Fatalf("%q accepted: %x %v", s, raw, err)
		}
		if "b"+enc.EncodeToString(raw) != s {
			t.Fatalf("%q accepted but is not the canonical spelling", s)
		}
	})
}

// FuzzAdmitFile: a file is imported whole or not at all; what is imported
// is exactly its distinct AID lines; a bad line is reported by number.
func FuzzAdmitFile(f *testing.F) {
	g := newGateHub(f)
	a, _ := identitytest.Hub()
	b, _ := identitytest.Hub()
	f.Add([]byte(a.AID() + "\n" + b.AID() + "\n"))
	f.Add([]byte("# c\n\n" + a.AID() + "\r\n  " + b.AID() + "  \n"))
	f.Add([]byte(a.AID() + "\nnope\n"))
	f.Add([]byte{})
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content []byte) {
		if len(content) > 64<<10 {
			return
		}
		if _, err := g.store.db.Exec(`DELETE FROM admitted`); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "aids.txt")
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		n, _, err := g.store.AdmitFile(p, 0, "", false)
		want := map[string]bool{}
		badLine := 0
		for i, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !ValidAID(line) {
				badLine = i + 1
				break
			}
			want[line] = true
		}
		var count int
		_ = g.store.db.QueryRow(`SELECT COUNT(*) FROM admitted`).Scan(&count)
		var bl *BadLineError
		switch {
		case errors.As(err, &bl):
			if count != 0 {
				t.Fatalf("a refused file imported %d", count)
			}
			if bl.Line != badLine {
				t.Fatalf("refused line %d, the first line that is not an AID is %d", bl.Line, badLine)
			}
		case err != nil:
			// a line longer than the scanner takes, say: nothing imported
			if count != 0 {
				t.Fatalf("a failed import (%v) imported %d", err, count)
			}
		default:
			if badLine != 0 {
				t.Fatalf("a file with a bad line %d was imported", badLine)
			}
			if n != len(want) || count != len(want) {
				t.Fatalf("imported %d (%d rows), want %d", n, count, len(want))
			}
		}
	})
}
