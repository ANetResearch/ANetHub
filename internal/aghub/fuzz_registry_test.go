package aghub_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

// registryWorld is a hub with agents whose A2A cards carry a spread of
// skills, tags and names, plus agents without a card.
type registryWorld struct {
	h    *fz
	kels map[string][]identity.SignedEvent
}

func newRegistryWorld(f *testing.F) *registryWorld {
	h := newFZ(f)
	w := &registryWorld{h: h, kels: map[string][]identity.SignedEvent{}}
	cards := []struct {
		name   string
		skills [][]string
	}{
		{"Echo Agent", [][]string{{"echo", "Echo", "text", "echo"}}},
		{"翻译 Agent", [][]string{{"translate", "翻译", "text", "中文"}, {"echo", "Echo", "text"}}},
		{"Weather", [][]string{{"weather.now", "Weather now", "weather", "Forecast"}}},
		{"ÄÖÜ İstanbul", [][]string{{"geo.lookup", "Geo", "GEO", "map"}}},
		{"Many", [][]string{{"a.1", "One", "t1"}, {"a.2", "Two", "t2"}, {"a.3", "Three", "t3"}}},
	}
	for i, c := range cards {
		ctrl, err := identity.Incept()
		if err != nil {
			f.Fatal(err)
		}
		skills := c.skills
		name := c.name
		body := h.registration(f, ctrl, name, nil)
		body["a2a_card"] = fzA2ACard(f, ctrl, uint64(i+1), withSkills(skills...), func(m map[string]any) {
			m["name"] = name
			m["description"] = "Card " + strconv.Itoa(i) + " for the registry fuzz."
		})
		if rec := h.register(ctrl, fzJSON(f, body)); rec.Code != http.StatusOK {
			f.Fatalf("register %s: %d %s", name, rec.Code, rec.Body.Bytes())
		}
		w.kels[ctrl.AID()] = ctrl.KEL()
	}
	for i := 0; i < 2; i++ {
		c, _ := h.agent(f, "no-card-"+strconv.Itoa(i), []string{"plain.cap", "echo"}, false)
		w.kels[c.AID()] = c.KEL()
	}
	return w
}

// list fetches /a2a/v1/agents with a raw query.
func (w *registryWorld) list(t *testing.T, rawQuery string) (int, aghub.A2AAgentList, []byte) {
	t.Helper()
	rec := w.h.serve(w.h.request(http.MethodGet, "/a2a/v1/agents", rawQuery, nil))
	var out aghub.A2AAgentList
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("registry answered 200 with %s", rec.Body.Bytes())
		}
	}
	return rec.Code, out, rec.Body.Bytes()
}

// FuzzHubRegistryQuery fuzzes the query of GET /a2a/v1/agents
// (skill, tag, q, cursor, limit) and of GET /agents (cap, q).
// Properties:
//
//   - the answer is 200 or 400, never a 5xx;
//   - a page is in strictly ascending AID order, above the cursor, no
//     longer than the limit asked for (and never above 200);
//   - every entry is an agent registered here whose card verifies against
//     its KEL and matches every filter given;
//   - nextCursor, when set, continues after the page's last entry, and
//     walking the pages yields the same entries as one large page;
//   - /agents answers 200 or 400 and lists only agents that match.
func FuzzHubRegistryQuery(f *testing.F) {
	w := newRegistryWorld(f)
	for _, q := range []string{"", "skill=echo", "tag=text", "q=echo", "q=%E7%BF%BB", "limit=1", "limit=0",
		"limit=-5", "limit=999999999999999999999", "cursor=%%%", "cursor=" + base64.RawURLEncoding.EncodeToString([]byte("bafy")),
		"skill=", "tag=%20", "q=" + strings.Repeat("a", 300), "skill=echo&tag=text&limit=1", "q=%C4%B0",
		"skill=echo&skill=weather.now", "q=AGENT", "q=istanbul"} {
		f.Add(q, "cap=echo", uint8(1))
	}
	f.Add("", "", uint8(0))
	f.Add("", "cap=", uint8(2))
	f.Add("", "q=Echo&cap=a.1", uint8(3))
	f.Add("", "cap=a", uint8(4))

	f.Fuzz(func(t *testing.T, rawQuery, agentsQuery string, pageSize uint8) {
		rawQuery, agentsQuery = clip(rawQuery, 2048), clip(agentsQuery, 2048)
		query, _ := url.ParseQuery(rawQuery)
		code, list, body := w.list(t, rawQuery)
		if !allowed(code, 200, 400) {
			t.Fatalf("GET /a2a/v1/agents?%s: %d %s", rawQuery, code, body)
		}
		if code == http.StatusOK {
			w.checkPage(t, query, list)
			// Walk the same filters in small pages.
			if pageSize%4 == 0 && list.NextCursor == "" {
				walked := w.walk(t, query, int(pageSize/4%5)+1)
				if len(walked) != len(list.Agents) {
					t.Fatalf("walking %q in pages found %d entries, one page %d", rawQuery, len(walked), len(list.Agents))
				}
				for i := range walked {
					if walked[i] != list.Agents[i].AID {
						t.Fatalf("walking %q in pages: %v, one page: %v", rawQuery, walked, list.Agents)
					}
				}
			}
		}

		rec := w.h.serve(w.h.request(http.MethodGet, "/agents", agentsQuery, nil))
		if !allowed(rec.Code, 200, 400) {
			t.Fatalf("GET /agents?%s: %d %s", agentsQuery, rec.Code, rec.Body.Bytes())
		}
		if rec.Code == http.StatusOK {
			var out struct {
				Agents []aghub.AgentView `json:"agents"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			aq, _ := url.ParseQuery(agentsQuery)
			for _, a := range out.Agents {
				if _, ok := w.kels[a.AID]; !ok {
					t.Fatalf("/agents?%s listed %s, which is not registered here", agentsQuery, a.AID)
				}
				if aq.Has("cap") {
					if !agentServes(a.Caps, strings.TrimSpace(aq.Get("cap"))) {
						t.Fatalf("/agents?%s listed %s serving %v", agentsQuery, a.AID, a.Caps)
					}
				}
			}
		}
	})
}

// agentServes applies /agents?cap= as documented: comma-separated
// alternatives, each an exact id or a family prefix ending in ".".
func agentServes(caps []string, filter string) bool {
	for _, f := range strings.Split(filter, ",") {
		f = strings.TrimSpace(f)
		for _, c := range caps {
			if c == f || strings.HasPrefix(c, f+".") || (strings.HasSuffix(f, ".") && strings.HasPrefix(c, f)) ||
				(strings.HasSuffix(f, "*") && strings.HasPrefix(c, strings.TrimSuffix(f, "*"))) {
				return true
			}
		}
	}
	return false
}

// checkPage asserts the page properties for the filters in q.
func (w *registryWorld) checkPage(t *testing.T, q url.Values, list aghub.A2AAgentList) {
	t.Helper()
	limit := 50
	if q.Has("limit") {
		n, _ := strconv.Atoi(q.Get("limit"))
		limit = min(n, 200)
	}
	if len(list.Agents) > limit {
		t.Fatalf("page of %d for limit %d", len(list.Agents), limit)
	}
	after := ""
	if c := q.Get("cursor"); c != "" {
		b, _ := base64.RawURLEncoding.DecodeString(c)
		after = string(b)
	}
	prev := after
	for _, e := range list.Agents {
		if e.AID <= prev {
			t.Fatalf("entries not ascending above the cursor %q: %s after %q", after, e.AID, prev)
		}
		prev = e.AID
		kel, ok := w.kels[e.AID]
		if !ok {
			t.Fatalf("registry lists %s, not registered here", e.AID)
		}
		if err := verifiesFor(e.Card, e.AID, kel); err != nil {
			t.Fatalf("registry lists a card for %s that does not verify: %v", e.AID, err)
		}
		if e.CardVerification != aghub.CardVerificationOK {
			t.Fatalf("entry %s cardVerification %q", e.AID, e.CardVerification)
		}
		var card struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Skills      []struct {
				ID   string   `json:"id"`
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"skills"`
		}
		if err := json.Unmarshal(e.Card, &card); err != nil {
			t.Fatal(err)
		}
		skill := strings.TrimSpace(q.Get("skill"))
		tag := strings.TrimSpace(q.Get("tag"))
		hasSkill, hasTag := skill == "", tag == ""
		text := []string{card.Name, card.Description}
		for _, s := range card.Skills {
			hasSkill = hasSkill || s.ID == skill
			for _, tg := range s.Tags {
				hasTag = hasTag || tg == tag
			}
			text = append(text, s.Name)
		}
		if !hasSkill || !hasTag {
			t.Fatalf("entry %s does not match skill=%q tag=%q", e.AID, skill, tag)
		}
		if qq := strings.TrimSpace(q.Get("q")); qq != "" &&
			!strings.Contains(strings.ToLower(strings.Join(text, "\n")), strings.ToLower(qq)) {
			t.Fatalf("entry %s does not mention q=%q", e.AID, qq)
		}
	}
	if list.NextCursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(list.NextCursor)
		if err != nil || len(list.Agents) == 0 || string(b) != list.Agents[len(list.Agents)-1].AID {
			t.Fatalf("nextCursor %q does not continue after the page", list.NextCursor)
		}
	}
}

// walk pages through the registry with the filters of q and pages of n.
func (w *registryWorld) walk(t *testing.T, q url.Values, n int) []string {
	t.Helper()
	p := url.Values{}
	for k, v := range q {
		if k != "cursor" && k != "limit" {
			p[k] = v
		}
	}
	p.Set("limit", strconv.Itoa(n))
	var out []string
	for i := 0; i < 100; i++ {
		code, list, body := w.list(t, p.Encode())
		if code != http.StatusOK {
			t.Fatalf("walk %s: %d %s", p.Encode(), code, body)
		}
		w.checkPage(t, p, list)
		for _, e := range list.Agents {
			out = append(out, e.AID)
		}
		if list.NextCursor == "" {
			return out
		}
		p.Set("cursor", list.NextCursor)
	}
	t.Fatalf("walking %s did not end", p.Encode())
	return nil
}

// ---- federation admission: what a peer's sync stream may put in ----

// FuzzHubFedAdmission hands the kernel's federation seam entries a peer
// could send: an A2A card stream entry, an ADP card stream entry and a
// review, each valid, mutated or raw. Properties: no panic; whatever is
// listed from a peer (fed_a2a_card rows with verified_at, the federated
// registry, fed_card rows) verifies against the KEL stored with it and
// speaks for the AID it is stored under; a card for an agent registered
// here is never admitted.
func FuzzHubFedAdmission(f *testing.F) {
	h := newFZ(f)
	local, _ := h.agent(f, "fuzz-local", nil, true)
	remote, err := identity.Incept()
	if err != nil {
		f.Fatal(err)
	}
	remoteKEL, _ := identity.MarshalKEL(remote.KEL())
	localKEL, _ := identity.MarshalKEL(local.KEL())
	h.srv.SetFederatedDirectory(func(string) ([]aghub.AgentView, error) { return nil, nil })
	peer := "peer-hub"
	validA2A := []byte(fzA2ACard(f, remote, 1))
	withdrawal := []byte(`{"aid":"` + remote.AID() + `","withdrawn":true}`)

	f.Add(uint8(0), uint8(0), uint64(1), []byte(nil), []byte(nil), "https://peer.example")
	f.Add(uint8(1), uint8(0), uint64(2), validA2A, remoteKEL, "")
	f.Add(uint8(2), uint8(0), uint64(3), []byte{7}, []byte(nil), "")
	f.Add(uint8(3), uint8(0), uint64(4), []byte(nil), []byte(nil), "")
	f.Add(uint8(4), uint8(0), uint64(5), withdrawal, []byte(nil), "")
	f.Add(uint8(0), uint8(1), uint64(6), []byte(nil), []byte(nil), "")
	f.Add(uint8(0), uint8(2), uint64(7), []byte(`{"subject_did":"x"}`), localKEL, "")
	f.Add(uint8(0), uint8(3), uint64(8), []byte(`{"receipt":"AAAA","review":"AAAA"}`), []byte(nil), "")

	f.Fuzz(func(t *testing.T, mode, stream uint8, seq uint64, raw, kelRaw []byte, home string) {
		raw, kelRaw, home = clipB(raw, 70<<10), clipB(kelRaw, 16<<10), clip(home, 256)
		switch stream % 4 {
		case 0, 1:
			// The A2A card stream.
			e := aghub.FedA2ACard{Format: federation.FormatA2ACard, KEL: remoteKEL, Home: home}
			switch mode % 6 {
			case 0:
				e.Card = fzA2ACard(t, remote, seq)
			case 1:
				e.Card, e.KEL = raw, kelRaw
			case 2:
				c := []byte(fzA2ACard(t, remote, seq))
				if len(raw) > 0 {
					c[int(raw[0])*11%len(c)] ^= 1 << (raw[0] % 7)
				}
				e.Card = c
			case 3:
				e.Card, e.KEL = fzA2ACard(t, local, seq), localKEL
			case 4:
				e.Format, e.Card = federation.FormatWithdrawal, raw
			case 5:
				e.Card = fzA2ACard(t, remote, seq)
				e.KEL = localKEL
			}
			if stream%4 == 1 {
				e.Keys = kelRaw
			}
			_ = h.store.AdmitFedA2ACard(peer, e)
		case 2:
			fc := aghub.FedCard{Card: raw, KEL: base64.StdEncoding.EncodeToString(kelRaw), Home: home}
			switch mode % 3 {
			case 0:
				fc.Card = fzADPCard(t, remote, "remote", []string{"r.x"})
				fc.KEL = base64.StdEncoding.EncodeToString(remoteKEL)
			case 1:
				fc.Card = fzADPCard(t, local, "local", nil)
				fc.KEL = base64.StdEncoding.EncodeToString(localKEL)
			}
			_ = h.store.AdmitFedCard(peer, fc)
		case 3:
			var fr aghub.FedReview
			if json.Unmarshal(raw, &fr) == nil {
				_ = h.store.AdmitFedReview(peer, fr)
			}
		}
		fedInvariants(t, h, local.AID())
	})
}

// fedInvariants checks everything a peer taught this hub.
func fedInvariants(t *testing.T, h *fz, localAID string) {
	t.Helper()
	now := uint64(time.Now().UnixMilli())
	_ = now
	rows, err := h.db.Query(`SELECT aid, card, kel FROM fed_a2a_card WHERE verified_at IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		aid       string
		card, kel []byte
	}
	var listed []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.aid, &r.card, &r.kel); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		listed = append(listed, r)
	}
	rows.Close()
	for _, r := range listed {
		if r.aid == localAID {
			t.Fatalf("a peer's A2A card for %s, an agent registered here, is listed", r.aid)
		}
		kel, err := identity.UnmarshalKEL(r.kel)
		if err != nil {
			t.Fatalf("listed federated card for %s carries an undecodable KEL: %v", r.aid, err)
		}
		states, err := identity.Replay(kel)
		if err != nil || states[len(states)-1].AID != r.aid {
			t.Fatalf("listed federated card for %s is stored with a KEL that is not its own: %v", r.aid, err)
		}
		if err := verifiesFor(r.card, r.aid, kel); err != nil {
			t.Fatalf("listed federated card for %s does not verify: %v", r.aid, err)
		}
	}
	rows, err = h.db.Query(`SELECT aid, kel FROM fed_card`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var aid string
		var kelBytes []byte
		if err := rows.Scan(&aid, &kelBytes); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if aid == localAID {
			rows.Close()
			t.Fatalf("a peer's ADP card for %s, an agent registered here, is stored", aid)
		}
		kel, err := identity.UnmarshalKEL(kelBytes)
		if err != nil {
			rows.Close()
			t.Fatalf("fed_card %s: %v", aid, err)
		}
		if states, err := identity.Replay(kel); err != nil || states[len(states)-1].AID != aid {
			rows.Close()
			t.Fatalf("fed_card %s stored with a KEL that is not its own: %v", aid, err)
		}
	}
	rows.Close()
	list, _, err := h.store.A2ARegistry(aghub.RegistryQuery{Federated: true, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		var kel []identity.SignedEvent
		if kb, err := h.store.AgentKEL(e.AID); err == nil {
			kel, _ = identity.UnmarshalKEL(kb)
		} else {
			var kb []byte
			if err := h.db.QueryRow(`SELECT kel FROM fed_a2a_card WHERE aid=?`, e.AID).Scan(&kb); err != nil {
				t.Fatalf("registry lists %s from nowhere: %v", e.AID, err)
			}
			kel, _ = identity.UnmarshalKEL(kb)
		}
		if err := verifiesFor(e.Card, e.AID, kel); err != nil {
			t.Fatalf("federated registry lists a card for %s that does not verify: %v", e.AID, err)
		}
	}
}
