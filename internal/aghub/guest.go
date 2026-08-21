package aghub

// guest.go is the v0.1 "访客模式" (guest mode) broker: it lets a first-time visitor with NO local daemon
// try the network — send a few REAL messages to dedicated guest-handler nodes — straight from the public
// Hub page, before installing anything.
//
// The browser has no identity and cannot sign, so the Hub brokers on its behalf with ONE ephemeral
// "guest broker" identity (a KEL, persisted in the Hub data dir, registered INVISIBLY — no caps/profile,
// so it never appears in the starfield/find). For each visitor session the broker signs a real delegation
// to a handler and relays the visitor's messages; the handler's replies come back to the broker mailbox,
// which the browser polls. Sessions live in memory only, are capped at the handler's guest_quota, and
// delivered relay rows are purged — so guest traffic leaves no durable trace ("数据不存储").
//
// There is no Hub-side handler list: guest mode is always on and a visitor is routed to ANY registered
// agent whose guest_quota > 0. Every agent accepts guestDefaultQuota (5) messages by default; an agent
// tunes or opts out via its daemon at register time (`anet hub-register … --guest-messages N`, 0 = off).

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/tsir"
)

const (
	guestDefaultQuota    = 5                // default guest trial messages an agent accepts (per session) — set at register
	guestMaxQuota        = 100              // clamp so a typo cannot let a session run unbounded
	guestSessionTTL      = 30 * time.Minute // idle sessions (and their relay rows) are dropped after this
	guestMaxSessions     = 2000             // hard cap so a flood cannot exhaust memory
	guestJanitorInterval = 5 * time.Minute  // background sweep cadence (expire sessions + purge relay rows)
)

// guestReply is one handler reply returned to the browser (system=true marks a Hub-generated notice).
// End marks an end-negotiation notice so the browser can offer an "end conversation" button: "proposed"
// = the handler asked to end (visitor should confirm), "accepted" = the conversation is now ended.
type guestReply struct {
	Body        string     `json:"body"`
	System      bool       `json:"system,omitempty"`
	End         string     `json:"end,omitempty"`
	Attachments []guestAtt `json:"attachments,omitempty"`
	// fromResult marks a reply reconstructed from the end-of-task result transcript (not a live chat).
	// Such messages were usually already shown live, so drainMailbox drops the ones we've already seen.
	// Unexported ⇒ never serialized to the browser.
	fromResult bool
}

// guestAtt is one attachment surfaced to a guest visitor. Because guests are ephemeral (no daemon, no
// store) the bytes are inlined as base64 for the browser to preview/download — but only up to
// guestInlineAttachMax; larger payloads are shown as a metadata chip (install anet to receive them).
type guestAtt struct {
	Name string `json:"name"`
	Mime string `json:"mime"`
	Size int64  `json:"size"`
	Data string `json:"data,omitempty"` // base64 (omitted when over the inline cap)
}

// guestInlineAttachMax bounds how large a single attachment we inline (base64) into a guest poll
// response. Guests are a lightweight trial; big files are for real (daemon-backed) interactions.
const guestInlineAttachMax = 20 << 20 // 20 MiB（v2 多模态：图/短音视频）

// guestMaxAttachPerMsg caps how many files a visitor may attach to one guest message (untrusted, ephemeral).
const guestMaxAttachPerMsg = 10 // v2：相册最多 10 张

// guestUpload is one file a visitor attaches from the browser: bytes carried inline as base64. The Hub
// content-addresses it (SumRaw) and relays it exactly like a real daemon would, so the handler needs no
// special guest handling.
type guestUpload struct {
	Name string `json:"name"`
	Mime string `json:"mime,omitempty"`
	Data string `json:"data"` // base64
}

// guestAttsFromUploads validates + content-addresses visitor uploads into relayable attachments.
func guestAttsFromUploads(ups []guestUpload) ([]delegation.Attachment, error) {
	if len(ups) == 0 {
		return nil, nil
	}
	if len(ups) > guestMaxAttachPerMsg {
		return nil, fmt.Errorf("一次最多上传 %d 个文件", guestMaxAttachPerMsg)
	}
	out := make([]delegation.Attachment, 0, len(ups))
	for _, u := range ups {
		data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(u.Data))
		if err != nil {
			return nil, fmt.Errorf("附件 %q 解码失败", u.Name)
		}
		if len(data) == 0 {
			continue
		}
		if len(data) > guestInlineAttachMax {
			return nil, fmt.Errorf("附件 %q 超过 %d MiB 访客上限（安装 anet 可发送更大文件）", u.Name, guestInlineAttachMax>>20)
		}
		name := filepath.Base(u.Name)
		if name == "" || name == "." || name == string(filepath.Separator) {
			name = "attachment"
		}
		cid, err := anetcid.SumRaw(data)
		if err != nil {
			return nil, err
		}
		mimeType := strings.TrimSpace(u.Mime)
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		out = append(out, delegation.Attachment{Name: name, Mime: mimeType, Size: int64(len(data)), CID: cid, Data: data})
	}
	return out, nil
}

// guestAttsFrom maps protocol attachments to browser-facing ones, inlining bytes under the cap.
func guestAttsFrom(atts []delegation.Attachment) []guestAtt {
	if len(atts) == 0 {
		return nil
	}
	out := make([]guestAtt, 0, len(atts))
	for _, a := range atts {
		ga := guestAtt{Name: a.Name, Mime: a.Mime, Size: a.Size}
		if int64(len(a.Data)) == a.Size && a.Size > 0 && a.Size <= guestInlineAttachMax {
			ga.Data = base64.StdEncoding.EncodeToString(a.Data)
		}
		out = append(out, ga)
	}
	return out
}

// guestSession is one visitor's ephemeral conversation with a handler node, keyed by an opaque token.
// interactionID is the shared id both sides address; pending buffers handler replies drained from the
// broker mailbox until the browser polls for THIS session.
type guestSession struct {
	token         string
	interactionID string
	handlerAID    string
	handlerName   string
	sent          int
	maxMessages   int  // this handler's guest_quota, captured at session start
	endProposed   bool // handler asked to end → /guest/end should ACCEPT (else it PROPOSES)
	ended         bool // conversation is over; further sends are rejected
	pending       []guestReply
	seen          map[string]bool // bodies already shown live, so the result transcript doesn't repeat them
	lastSeen      time.Time
}

// guestBroker holds the ephemeral broker identity + live sessions. All traffic is signed as brokerAID.
type guestBroker struct {
	mu      sync.Mutex
	ctrl    *identity.Controller
	aid     string
	kel     []byte // marshaled broker KEL (inlined into each delegation)
	byToken map[string]*guestSession
	byIX    map[string]*guestSession
}

// EnableGuestMode sets up the guest broker: it loads (or, first run, incepts + persists) the broker
// identity under dir and registers it invisibly so handlers can reply to its mailbox. Guest mode is
// always on — a no-daemon visitor is routed to any registered agent whose guest_quota > 0 (every agent
// accepts 5 by default; an agent opts out by registering with --guest-messages 0). Call once at startup.
// It also starts a background janitor (stopped when ctx is cancelled) that expires idle sessions and
// purges guest relay rows, so abandoned sessions leave no durable trace even if no one else visits/polls.
func (s *Server) EnableGuestMode(ctx context.Context, dir string) error {
	ctrl, err := loadOrInceptGuestIdentity(dir)
	if err != nil {
		return fmt.Errorf("guest: identity: %w", err)
	}
	kel, err := identity.MarshalKEL(ctrl.KEL())
	if err != nil {
		return err
	}
	// Register the broker invisibly (empty name, no caps/profile ⇒ not "listed" ⇒ absent from find/starfield;
	// guest_quota 0 ⇒ never picked as a handler) so the relay accepts handler replies to its mailbox.
	if err := s.store.PutAgent(ctrl.AID(), "", nil, 0, kel); err != nil {
		return fmt.Errorf("guest: register broker: %w", err)
	}
	s.guest = &guestBroker{
		ctrl: ctrl, aid: ctrl.AID(), kel: kel,
		byToken: map[string]*guestSession{}, byIX: map[string]*guestSession{},
	}
	go s.guest.runJanitor(ctx, s.store)
	return nil
}

// runJanitor periodically expires idle sessions and purges guest relay rows until ctx is cancelled. This
// is what makes guest traffic truly ephemeral without depending on new visitors arriving (which is what
// used to trigger the only sweep) or a session being polled (the only place delivered rows were purged).
func (g *guestBroker) runJanitor(ctx context.Context, store *Store) {
	t := time.NewTicker(guestJanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.mu.Lock()
			g.sweepLocked()
			g.mu.Unlock()
			_, _ = store.PurgeGuestRelay(g.aid)                                        // delivered rows, any age
			_, _ = store.PurgeStaleGuestRelay(g.aid, time.Now().Add(-guestSessionTTL)) // abandoned/undelivered past TTL
		}
	}
}

// loadOrInceptGuestIdentity restores the persisted guest-broker identity (stable AID across restarts, so
// invisible broker rows do not accumulate) or incepts + persists a fresh one on first run.
func loadOrInceptGuestIdentity(dir string) (*identity.Controller, error) {
	path := filepath.Join(dir, "guest_identity.kel")
	if b, err := os.ReadFile(path); err == nil {
		return identity.Restore(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ctrl, err := identity.Incept()
	if err != nil {
		return nil, err
	}
	blob, err := ctrl.Export()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, err
	}
	return ctrl, nil
}

// --- HTTP handlers (registered unconditionally; each reports disabled when guest mode is off) ---

// hGuestStart opens a guest session with a chosen agent (or, when no aid is given, any agent accepting
// guests), allocates the shared interaction id, and returns enough for the browser to greet. No message
// is sent yet (the first /guest/send carries the visitor's opening message as the delegation goal).
func (s *Server) hGuestStart(w http.ResponseWriter, r *http.Request) {
	if s.guest == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	var req struct {
		AID string `json:"aid"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // body is optional; ignore decode errors
	}
	var (
		h  guestHandler
		ok bool
	)
	if aid := strings.TrimSpace(req.AID); aid != "" {
		h, ok = s.pickHandlerFor(aid)
	} else {
		h, ok = s.pickHandler()
	}
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "reason": "no agent is accepting guests"})
		return
	}
	g := s.guest
	g.mu.Lock()
	g.sweepLocked()
	if len(g.byToken) >= guestMaxSessions {
		g.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "guest mode busy, try again later"})
		return
	}
	sess := &guestSession{
		token: randToken("gs_"), interactionID: randToken("ix_"),
		handlerAID: h.aid, handlerName: h.name, maxMessages: h.quota, lastSeen: time.Now(),
	}
	g.byToken[sess.token] = sess
	g.byIX[sess.interactionID] = sess
	g.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "session": sess.token, "handler": h.name, "handler_aid": h.aid,
		"remaining": h.quota,
	})
}

// hGuestSend relays one visitor message to the handler (the first becomes the signed delegation goal;
// later ones are chat messages). Enforces the per-session cap.
func (s *Server) hGuestSend(w http.ResponseWriter, r *http.Request) {
	if s.guest == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	var req struct {
		Session     string        `json:"session"`
		Body        string        `json:"body"`
		Attachments []guestUpload `json:"attachments,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	body := strings.TrimSpace(req.Body)
	atts, err := guestAttsFromUploads(req.Attachments)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body == "" && len(atts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty message"})
		return
	}
	g := s.guest
	g.mu.Lock()
	sess := g.byToken[req.Session]
	if sess == nil {
		g.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session expired — reload to start over"})
		return
	}
	if sess.ended {
		g.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ended": true, "remaining": 0})
		return
	}
	if sess.sent >= sess.maxMessages {
		g.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"limit_reached": true, "remaining": 0})
		return
	}
	first := sess.sent == 0
	handlerAID, ix := sess.handlerAID, sess.interactionID
	g.mu.Unlock()

	var (
		payload []byte
		kind    string
	)
	if first {
		goal := body
		if goal == "" {
			goal = "（见附件）"
		}
		payload, err = g.buildDelegate(ix, goal, atts)
		kind = RelayKindDelegate
	} else {
		payload, err = buildChatText(body, atts)
		kind = RelayKindMessage
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if _, err := s.store.RelayEnqueue(handlerAID, g.aid, kind, ix, payload); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	g.mu.Lock()
	sess.sent++
	sess.lastSeen = time.Now()
	remaining := sess.maxMessages - sess.sent
	g.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"remaining": remaining})
}

// hGuestPoll drains the broker mailbox (routing each reply to its session by interaction id), then
// returns and clears THIS session's buffered replies. Delivered relay rows are purged after draining.
func (s *Server) hGuestPoll(w http.ResponseWriter, r *http.Request) {
	if s.guest == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	var req struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	g := s.guest
	g.mu.Lock()
	sess := g.byToken[req.Session]
	g.mu.Unlock()
	if sess == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session expired — reload to start over"})
		return
	}
	g.drainMailbox(s.store)
	g.mu.Lock()
	out := sess.pending
	sess.pending = nil
	sess.lastSeen = time.Now()
	g.mu.Unlock()
	_, _ = s.store.PurgeGuestRelay(g.aid)
	if out == nil {
		out = []guestReply{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}

// hGuestEnd ends a guest conversation from the visitor's side. If the handler already proposed ending
// (ChatEndRequest), this ACCEPTS it (ChatEndAccept) so the handler's interaction actually closes; if not,
// it PROPOSES ending (ChatEndRequest). Ending never counts against the guest quota (it is a control
// action, not a trial message) and marks the session ended so no further messages are relayed.
func (s *Server) hGuestEnd(w http.ResponseWriter, r *http.Request) {
	if s.guest == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	var req struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	g := s.guest
	g.mu.Lock()
	sess := g.byToken[req.Session]
	if sess == nil {
		g.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session expired — reload to start over"})
		return
	}
	accept := sess.endProposed
	handlerAID, ix := sess.handlerAID, sess.interactionID
	hasConversation := sess.sent > 0
	sess.ended = true
	g.mu.Unlock()

	// A conversation only exists on the handler once the opening delegation was sent; if the visitor never
	// sent anything, there is nothing to close on the other side — just mark this session ended locally.
	if hasConversation {
		kind := delegation.ChatEndAccept
		if !accept {
			kind = delegation.ChatEndRequest
		}
		payload, err := buildChatEndKind(kind)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if _, err := s.store.RelayEnqueue(handlerAID, g.aid, RelayKindMessage, ix, payload); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ended": true, "accepted": accept})
}

// --- broker internals ---

// guestHandler is one agent a visitor can be routed to: its AID, display name, and per-session quota.
type guestHandler struct {
	aid   string
	name  string
	quota int
}

// pickHandler returns a random currently-listed agent that accepts guests (guest_quota > 0), excluding
// the invisible broker itself. The choice belongs to each agent (set at register), not the Hub operator —
// so "who greets visitors" is simply "everyone who didn't opt out". Returns ok=false if nobody accepts.
func (s *Server) pickHandler() (guestHandler, bool) {
	g := s.guest
	list, err := s.store.ListAgents("")
	if err != nil {
		return guestHandler{}, false
	}
	avail := make([]guestHandler, 0, len(list))
	for _, av := range list {
		if av.AID == g.aid || av.GuestQuota <= 0 {
			continue
		}
		name := av.Name
		if name == "" {
			name = shortAID(av.AID)
		}
		avail = append(avail, guestHandler{aid: av.AID, name: name, quota: av.GuestQuota})
	}
	if len(avail) == 0 {
		return guestHandler{}, false
	}
	return avail[mrand.IntN(len(avail))], true
}

// pickHandlerFor returns the specific agent the visitor tapped, provided it is listed and still accepts
// guests (guest_quota > 0) and is not the invisible broker. Lets the browser route a guest chat to the
// exact agent chosen in the directory (falling back to pickHandler when no aid is supplied).
func (s *Server) pickHandlerFor(aid string) (guestHandler, bool) {
	g := s.guest
	if aid == g.aid {
		return guestHandler{}, false
	}
	av, _, err := s.store.GetAgent(aid)
	if err != nil || av == nil || av.GuestQuota <= 0 {
		return guestHandler{}, false
	}
	name := av.Name
	if name == "" {
		name = shortAID(av.AID)
	}
	return guestHandler{aid: av.AID, name: name, quota: av.GuestQuota}, true
}

// drainMailbox pulls every pending broker reply once, routes each to its session's buffer by interaction
// id, and acks them. Called on each poll; replies for other live sessions are buffered, not dropped.
func (g *guestBroker) drainMailbox(store *Store) {
	msgs, err := store.RelayPoll(g.aid, 200)
	if err != nil || len(msgs) == 0 {
		return
	}
	acked := make([]int64, 0, len(msgs))
	g.mu.Lock()
	for _, m := range msgs {
		acked = append(acked, m.ID)
		sess := g.byIX[m.InteractionID]
		if sess == nil {
			continue // reply for an expired/unknown session — drop
		}
		for _, rep := range decodeReply(m.Kind, m.Payload) {
			// A live provider chat message and the end-of-task result transcript carry the same text; show
			// each body once. Track live-shown bodies and skip transcript replies we've already displayed.
			if rep.Body != "" && !rep.System {
				if sess.seen == nil {
					sess.seen = map[string]bool{}
				}
				if rep.fromResult && sess.seen[rep.Body] {
					continue
				}
				sess.seen[rep.Body] = true
			}
			sess.pending = append(sess.pending, rep)
			switch rep.End {
			case "proposed":
				sess.endProposed = true
			case "accepted":
				sess.ended = true
			}
		}
	}
	g.mu.Unlock()
	_, _ = store.RelayAck(g.aid, acked)
}

// decodeReply turns one relayed handler payload into zero or more chat replies to show the visitor.
func decodeReply(kind string, payload []byte) []guestReply {
	switch kind {
	case RelayKindMessage:
		cm, err := delegation.UnmarshalChatMsg(payload)
		if err != nil {
			return nil
		}
		switch cm.Kind {
		case delegation.ChatText:
			atts := guestAttsFrom(cm.Attachments)
			if strings.TrimSpace(cm.Body) == "" && len(atts) == 0 {
				return nil
			}
			return []guestReply{{Body: cm.Body, Attachments: atts}}
		case delegation.ChatEndRequest:
			return []guestReply{{Body: "对方提议结束这次对话。点「结束对话」即可确认。", System: true, End: "proposed"}}
		case delegation.ChatEndAccept:
			return []guestReply{{Body: "对话已结束。", System: true, End: "accepted"}}
		}
	case RelayKindResult:
		rr, err := delegation.UnmarshalResultResp(payload)
		if err != nil {
			return nil
		}
		var out []guestReply
		var ts []struct {
			From string `json:"from"`
			Body string `json:"body"`
		}
		if json.Unmarshal(rr.Deliverable, &ts) == nil {
			for _, m := range ts {
				if m.From == "provider" && strings.TrimSpace(m.Body) != "" {
					out = append(out, guestReply{Body: m.Body, fromResult: true})
				}
			}
		}
		out = append(out, guestReply{Body: "对方已完成并结束了任务。安装 anet 后即可发起真正可评价的委派。", System: true})
		return out
	}
	return nil
}

// buildDelegate signs a minimal TaskDoc (goal) as the broker and wraps it as a relayable DelegateReq —
// the same object a real requester's daemon sends, so a handler needs no special guest handling.
func (g *guestBroker) buildDelegate(interactionID, goal string, atts []delegation.Attachment) ([]byte, error) {
	td := &tsir.TaskDoc{Version: tsir.VersionPair{Major: 1}, Tasks: []tsir.Task{{Intent: tsir.Intent{Summary: goal, Body: goal}}}}
	if err := td.Sign(g.ctrl); err != nil {
		return nil, err
	}
	doc, err := coredet.Marshal(td)
	if err != nil {
		return nil, err
	}
	dr := &delegation.DelegateReq{TaskDoc: doc, Envelope: td.Envelope, KEL: g.kel, InteractionID: interactionID, Attachments: atts}
	return dr.Marshal()
}

// buildChatText marshals an unsigned text chat message (v0.1 chat is relayed unsigned), optionally with
// visitor attachments carried inline.
func buildChatText(body string, atts []delegation.Attachment) ([]byte, error) {
	cm := &delegation.ChatMsg{Kind: delegation.ChatText, Body: body, Attachments: atts}
	return cm.Marshal()
}

// buildChatEndKind marshals an unsigned end-negotiation chat message (delegation.ChatEndRequest/Accept).
func buildChatEndKind(kind string) ([]byte, error) {
	cm := &delegation.ChatMsg{Kind: kind}
	return cm.Marshal()
}

// sweepLocked drops idle sessions past their TTL. Caller holds g.mu.
func (g *guestBroker) sweepLocked() {
	cutoff := time.Now().Add(-guestSessionTTL)
	for tok, sess := range g.byToken {
		if sess.lastSeen.Before(cutoff) {
			delete(g.byToken, tok)
			delete(g.byIX, sess.interactionID)
		}
	}
}

// randToken returns prefix + 16 hex chars of crypto-random.
func randToken(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// shortAID abbreviates an AID for display (last 10 chars).
func shortAID(aid string) string {
	if len(aid) <= 12 {
		return aid
	}
	return "…" + aid[len(aid)-10:]
}
