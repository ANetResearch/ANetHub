package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/tsir"
	"github.com/ANetResearch/ANetHub/internal/protocol/delegation"
)

// Harvester turns live platform traffic into OKF dataset assets. Two sources:
//
//	hub-relay  — pages hub.db relay_message by rowid (before the retention roll deletes rows) and
//	             decodes each payload (DelegateReq / ChatMsg / ResultResp) into an append-only event
//	             JSONL per interaction + a regenerable session card. Attachment BYTES are dropped —
//	             only {name,mime,size,cid} metadata is kept, so bundles stay text-sized while content
//	             stays re-fetchable by CID if a store materializes later.
//	ai-studio  — tails an official agent's history.jsonl (JobRec per line, with per-step model timings)
//	             over ssh by byte offset. service_id doubles as the intent label — this is the highest-
//	             quality intent-grounding feed the platform currently produces.
//
// Both cursors persist in admin.db harvest_state, so runs are incremental and crash-safe (a re-run
// re-appends at most one partially processed batch; readers must tolerate duplicate event lines by
// relay_id / (ix,end_ms) dedup).
type Harvester struct {
	store *Store
	hub   *HubDB
	mon   *MonitorProxy // v2: HTTP harvest channel (works without ssh)
	root  string        // datasets root directory
}

// NewHarvester wires a harvester over the two stores; root is the datasets directory.
func NewHarvester(store *Store, hub *HubDB, mon *MonitorProxy, root string) *Harvester {
	return &Harvester{store: store, hub: hub, mon: mon, root: root}
}

// Root returns the datasets root directory.
func (hv *Harvester) Root() string { return hv.root }

// RunResult summarizes one harvest pass.
type RunResult struct {
	Source   string `json:"source"`
	Events   int    `json:"events"`
	Sessions int    `json:"sessions"`
	Cursor   string `json:"cursor"`
	Err      string `json:"err,omitempty"`
}

// RunAll runs every source once: hub-relay, then each official agent with datasets.harvest=true.
func (hv *Harvester) RunAll(ctx context.Context) []RunResult {
	var out []RunResult
	out = append(out, hv.runRelay(ctx))
	officials, err := hv.store.Officials()
	if err == nil {
		for _, m := range officials {
			if !m.Datasets.Harvest {
				continue
			}
			// Prefer the HTTP monitor channel (no ssh needed); fall back to ssh tail of history.jsonl.
			if hv.mon != nil && m.Monitor.URL != "" {
				out = append(out, hv.runHistoryHTTP(ctx, m))
			} else if m.Runtime.HistoryJSONL != "" {
				out = append(out, hv.runHistory(ctx, m))
			}
		}
	}
	return out
}

// idSafeRe sanitizes interaction ids into OKF concept-id segments.
var idSafeRe = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)

func safeID(s string) string {
	s = idSafeRe.ReplaceAllString(s, "_")
	if s == "" || s[0] == '.' || s[0] == '-' {
		s = "_" + s
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// relayEvent is one decoded relay row — one JSONL line in a hub-relay session's data file.
type relayEvent struct {
	Schema      string           `json:"schema"`
	RelayID     int64            `json:"relay_id"`
	IX          string           `json:"ix"`
	TS          string           `json:"ts"`
	Kind        string           `json:"kind"` // delegate | message | result
	From        string           `json:"from"`
	To          string           `json:"to"`
	Goal        string           `json:"goal,omitempty"`      // delegate: TaskDoc intent body
	ChatKind    string           `json:"chat_kind,omitempty"` // message: text | end_request | end_accept
	Body        string           `json:"body,omitempty"`
	Status      string           `json:"status,omitempty"` // result: queued | done | failed
	Deliverable string           `json:"deliverable,omitempty"`
	Attachments []attachmentMeta `json:"attachments,omitempty"`
	PayloadLen  int              `json:"payload_len"`
	DecodeErr   string           `json:"decode_err,omitempty"`
}

type attachmentMeta struct {
	Name string `json:"name"`
	Mime string `json:"mime,omitempty"`
	Size int64  `json:"size"`
	CID  string `json:"cid"`
}

const (
	maxBodyKeep   = 16 << 10  // per-event text cap in the dataset
	relayBatch    = 1000      // rows per page
	relayRunBytes = 256 << 20 // payload budget per harvest pass (first pass over a big backlog takes several passes)
)

func attMeta(atts []delegation.Attachment) []attachmentMeta {
	if len(atts) == 0 {
		return nil
	}
	out := make([]attachmentMeta, len(atts))
	for i, a := range atts {
		out[i] = attachmentMeta{Name: a.Name, Mime: a.Mime, Size: a.Size, CID: a.CID}
	}
	return out
}

func clipText(s string) string {
	if len(s) <= maxBodyKeep {
		return s
	}
	cut := s[:maxBodyKeep]
	for !utf8.ValidString(cut) && len(cut) > 0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…[clipped]"
}

// decodeRelay turns one raw relay row into a dataset event.
func decodeRelay(r RelayRow) relayEvent {
	ev := relayEvent{
		Schema: "anet-relay-event/1.0", RelayID: r.ID, IX: r.InteractionID, TS: r.CreatedAt,
		Kind: r.Kind, From: r.FromAID, To: r.ToAID, PayloadLen: len(r.Payload),
	}
	switch r.Kind {
	case "delegate":
		req, err := delegation.UnmarshalDelegateReq(r.Payload)
		if err != nil {
			ev.DecodeErr = err.Error()
			return ev
		}
		var td tsir.TaskDoc
		if err := coredet.Unmarshal(req.TaskDoc, &td); err == nil && len(td.Tasks) > 0 {
			if b := td.Tasks[0].Intent.Body; b != "" {
				ev.Goal = clipText(b)
			} else {
				ev.Goal = clipText(td.Tasks[0].Intent.Summary)
			}
		}
		ev.Attachments = attMeta(req.Attachments)
	case "message":
		msg, err := delegation.UnmarshalChatMsg(r.Payload)
		if err != nil {
			ev.DecodeErr = err.Error()
			return ev
		}
		ev.ChatKind = msg.Kind
		ev.Body = clipText(msg.Body)
		ev.Attachments = attMeta(msg.Attachments)
	case "result":
		res, err := delegation.UnmarshalResultResp(r.Payload)
		if err != nil {
			ev.DecodeErr = err.Error()
			return ev
		}
		ev.Status = res.Status
		if utf8.Valid(res.Deliverable) {
			ev.Deliverable = clipText(string(res.Deliverable))
		} else {
			ev.Deliverable = fmt.Sprintf("[binary deliverable, %d bytes]", len(res.Deliverable))
		}
	}
	return ev
}

// runRelay pages new relay rows into per-interaction event files + session cards.
func (hv *Harvester) runRelay(ctx context.Context) RunResult {
	const source = "hub-relay"
	res := RunResult{Source: source}
	st, err := hv.store.GetHarvestState(source)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	cursor, _ := strconv.ParseInt(st.Cursor, 10, 64)

	var spent int64
	touched := map[string]bool{} // shard dirs needing index regen
	for spent < relayRunBytes {
		if ctx.Err() != nil {
			break
		}
		rows, err := hv.hub.RelayRowsSince(cursor, relayBatch, relayRunBytes-spent)
		if err != nil {
			res.Err = err.Error()
			break
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			cursor = r.ID
			spent += int64(len(r.Payload))
			ev := decodeRelay(r)
			if ev.IX == "" {
				ev.IX = fmt.Sprintf("relay-%d", r.ID) // relay rows without an interaction id still get captured
			}
			if err := hv.appendRelayEvent(ev, len(r.Payload)); err != nil {
				log.Printf("admin: harvest relay ix %s: %v", ev.IX, err)
				continue
			}
			res.Events++
			if row, err := hv.store.GetSession(source, safeID(ev.IX)); err == nil {
				touched[filepath.Dir(filepath.Join(hv.root, source, row.CardPath))] = true
			}
		}
		if len(rows) < relayBatch {
			break
		}
	}
	res.Cursor = strconv.FormatInt(cursor, 10)

	for dir := range touched {
		_ = RegenIndex(dir, false)
	}
	_ = RegenIndex(filepath.Join(hv.root, source), true)
	if res.Events > 0 {
		_ = AppendLog(hv.root, source, fmt.Sprintf("harvested %d relay events (cursor %s).", res.Events, res.Cursor))
	}

	counts, _ := hv.store.SessionCounts()
	sess := 0
	if c, ok := counts[source]; ok {
		sess = int(c["sessions"])
	}
	res.Sessions = sess
	st.Cursor = res.Cursor
	st.LastRun = nowRFC3339()
	st.Sessions = sess
	st.Records += res.Events
	st.Note = res.Err
	if err := hv.store.PutHarvestState(st); err != nil && res.Err == "" {
		res.Err = err.Error()
	}
	return res
}

// appendRelayEvent appends ev to its session's data file and refreshes the session row + card.
func (hv *Harvester) appendRelayEvent(ev relayEvent, payloadLen int) error {
	const source = "hub-relay"
	id := safeID(ev.IX)

	row, err := hv.store.GetSession(source, id)
	newSession := err != nil
	shard := time.Now().UTC().Format("200601")
	if len(ev.TS) >= 7 {
		shard = strings.ReplaceAll(ev.TS[:7], "-", "")
	}
	if !newSession && row.DataPath != "" {
		// Keep appending where the session started, even across month boundaries.
		if m := regexp.MustCompile(`sessions/(\d{6})/`).FindStringSubmatch(row.DataPath); len(m) == 2 {
			shard = m[1]
		}
	}

	dataRel := dataRelPath(shard, id)
	full := filepath.Join(hv.root, source, dataRel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Fold the event into the session aggregate.
	if newSession {
		row = SessionRow{Source: source, SessionID: id, StartedAt: ev.TS}
	}
	row.Events++
	row.Bytes += int64(payloadLen)
	row.EndedAt = ev.TS
	if row.StartedAt == "" || ev.TS < row.StartedAt {
		row.StartedAt = ev.TS
	}
	switch ev.Kind {
	case "delegate":
		if ev.Goal != "" && row.Goal == "" {
			row.Goal = oneLine(ev.Goal, 200)
		}
		row.RequesterAID, row.ProviderAID = ev.From, ev.To
		if row.Status == "" {
			row.Status = "delegated"
		}
	case "message":
		if row.Status == "" || row.Status == "delegated" {
			row.Status = "chatting"
		}
		if ev.ChatKind == delegation.ChatEndAccept {
			row.Status = "ended"
		}
	case "result":
		if ev.Status != "" {
			row.Status = ev.Status
		}
		if row.ProviderAID == "" {
			row.ProviderAID, row.RequesterAID = ev.From, ev.To
		}
	}
	row.DataPath = filepath.ToSlash(dataRel)
	row.UpdatedAt = nowRFC3339()

	title := row.Goal
	if title == "" {
		title = "Interaction " + id
	}
	desc := fmt.Sprintf("%d relay events between %s and %s (status %s).",
		row.Events, short(row.RequesterAID), short(row.ProviderAID), orDash(row.Status))
	cardRel, err := WriteSessionCard(hv.root, SessionCard{
		Bundle: source, ID: id, Shard: shard,
		Title: title, Description: desc,
		Tags:     []string{"hub-relay"},
		Provider: row.ProviderAID, Requester: row.RequesterAID, Status: row.Status,
		StartedAt: row.StartedAt, EndedAt: row.EndedAt,
		Events: row.Events, Bytes: row.Bytes,
	})
	if err != nil {
		return err
	}
	row.CardPath = cardRel
	return hv.store.PutSession(row)
}

func short(aid string) string {
	if len(aid) > 16 {
		return aid[:16] + "…"
	}
	if aid == "" {
		return "unknown"
	}
	return aid
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- ai-studio (official-agent history.jsonl) source ---

// jobRec mirrors the classic official-agent monitor's history record (anet-ai-srv monitor.go JobRec).
type jobRec struct {
	IX        string `json:"ix"`
	Service   string `json:"service"`
	Peer      string `json:"peer"`
	Prompt    string `json:"prompt"`
	State     string `json:"state"`
	StartMs   int64  `json:"start_ms"`
	EndMs     int64  `json:"end_ms"`
	DurMs     int64  `json:"dur_ms"`
	OutKind   string `json:"out_kind"`
	OutBytes  int    `json:"out_bytes"`
	Err       string `json:"err"`
	Model     string `json:"model"`      // v2
	CostMilli int    `json:"cost_milli"` // v2
	Steps     []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Model string `json:"model"`
		Ms    int    `json:"ms"`
	} `json:"steps"`
}

// runHistoryHTTP harvests an official agent's recent jobs via its monitor /api/state (no ssh needed).
// The monitor keeps only the recent window (≤500 jobs), so this captures live activity forward from
// deploy; appendJob dedups by (shard,id) content so re-fetches are idempotent. Cursor = highest ix
// end time seen, stored as note only (the window, not a byte offset, bounds this source).
func (hv *Harvester) runHistoryHTTP(ctx context.Context, m *Manifest) RunResult {
	source := m.ID
	res := RunResult{Source: source}
	body, err := hv.mon.Fetch(ctx, m, "state")
	if err != nil {
		res.Err = "monitor state: " + err.Error()
		return res
	}
	var st struct {
		Jobs []jobRec `json:"jobs"`
	}
	if err := json.Unmarshal(body, &st); err != nil {
		res.Err = "decode state: " + err.Error()
		return res
	}
	for _, jr := range st.Jobs {
		if jr.IX == "" || jr.State == "running" {
			continue // skip in-flight; capture on a later pass when done
		}
		line, _ := json.Marshal(jr)
		if err := hv.appendJob(m, jr, line); err != nil {
			log.Printf("admin: harvest(http) %s job %s: %v", source, jr.IX, err)
			continue
		}
		res.Events++
	}
	_ = RegenIndex(filepath.Join(hv.root, source), true)
	if res.Events > 0 {
		_ = AppendLog(hv.root, source, fmt.Sprintf("harvested %d jobs via monitor http.", res.Events))
	}
	counts, _ := hv.store.SessionCounts()
	if c, ok := counts[source]; ok {
		res.Sessions = int(c["sessions"])
	}
	st2, _ := hv.store.GetHarvestState(source)
	st2.LastRun = nowRFC3339()
	st2.Sessions = res.Sessions
	st2.Records += res.Events
	st2.Cursor = "http:" + nowRFC3339()
	st2.Note = res.Err
	_ = hv.store.PutHarvestState(st2)
	return res
}

const historyChunk = 4 << 20 // bytes fetched per pass

// runHistory tails m's history.jsonl over ssh from the stored byte offset.
func (hv *Harvester) runHistory(ctx context.Context, m *Manifest) RunResult {
	source := m.ID
	res := RunResult{Source: source}
	st, err := hv.store.GetHarvestState(source)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	offset, _ := strconv.ParseInt(st.Cursor, 10, 64)

	// tail -c +N is 1-based; head bounds the chunk. A shrunk file (rotation) resets the cursor.
	remote := fmt.Sprintf("S=$(stat -c %%s %s 2>/dev/null || echo 0); echo $S; tail -c +%d %s | head -c %d",
		shq(m.Runtime.HistoryJSONL), offset+1, shq(m.Runtime.HistoryJSONL), historyChunk)
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	c := exec.CommandContext(cctx, "ssh", sshArgs(m, remote)...)
	var out bytes.Buffer
	c.Stdout = &out
	var errBuf bytes.Buffer
	c.Stderr = &errBuf
	if err := c.Run(); err != nil {
		res.Err = strings.TrimSpace(errBuf.String())
		if res.Err == "" {
			res.Err = err.Error()
		}
		return res
	}
	raw := out.Bytes()
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		res.Err = "unexpected ssh output"
		return res
	}
	fileSize, _ := strconv.ParseInt(strings.TrimSpace(string(raw[:nl])), 10, 64)
	chunk := raw[nl+1:]
	if fileSize < offset {
		offset = 0 // rotated/truncated upstream — start over (dedup below keeps cards idempotent)
	}

	consumed := 0
	sc := bufio.NewScanner(bytes.NewReader(chunk))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lineLen := len(sc.Bytes()) + 1
		if consumed+lineLen > len(chunk) {
			break // final line may be cut mid-write — leave it for the next pass
		}
		line := sc.Bytes()
		consumed += lineLen
		var jr jobRec
		if err := json.Unmarshal(line, &jr); err != nil || jr.IX == "" {
			continue
		}
		if err := hv.appendJob(m, jr, line); err != nil {
			log.Printf("admin: harvest %s job %s: %v", source, jr.IX, err)
			continue
		}
		res.Events++
	}
	// Only fully consumed lines advance the cursor.
	res.Cursor = strconv.FormatInt(offset+int64(consumed), 10)

	_ = RegenIndex(filepath.Join(hv.root, source), true)
	if res.Events > 0 {
		_ = AppendLog(hv.root, source, fmt.Sprintf("harvested %d job records (offset %s).", res.Events, res.Cursor))
	}
	counts, _ := hv.store.SessionCounts()
	if c, ok := counts[source]; ok {
		res.Sessions = int(c["sessions"])
	}
	st.Cursor = res.Cursor
	st.LastRun = nowRFC3339()
	st.Sessions = res.Sessions
	st.Records += res.Events
	st.Note = res.Err
	if err := hv.store.PutHarvestState(st); err != nil && res.Err == "" {
		res.Err = err.Error()
	}
	return res
}

// appendJob writes one JobRec into m's bundle: raw line appended to the shard data file, session card +
// index row refreshed, intent stub minted from the service id.
func (hv *Harvester) appendJob(m *Manifest, jr jobRec, rawLine []byte) error {
	source := m.ID
	id := safeID(jr.IX)
	started := time.UnixMilli(jr.StartMs).UTC()
	shard := started.Format("200601")
	if jr.StartMs == 0 {
		shard = time.Now().UTC().Format("200601")
	}

	dataRel := dataRelPath(shard, id)
	full := filepath.Join(hv.root, source, dataRel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	// History replays whole-file after rotation — skip identical re-appends.
	if prev, err := os.ReadFile(full); err == nil && bytes.Contains(prev, rawLine) {
		return nil
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(append([]byte{}, rawLine...), '\n')); err != nil {
		f.Close()
		return err
	}
	f.Close()

	intent := safeID(jr.Service)
	_ = EnsureIntentCard(hv.root, source, intent, "Service intent "+jr.Service+" of official agent "+m.Name+".")

	ended := ""
	if jr.EndMs > 0 {
		ended = time.UnixMilli(jr.EndMs).UTC().Format(time.RFC3339)
	}
	var stepsSummary []string
	for _, s := range jr.Steps {
		if s.Model != "" {
			stepsSummary = append(stepsSummary, fmt.Sprintf("%s(%s %dms)", s.ID, s.Model, s.Ms))
		}
	}
	extra := map[string]string{
		"job": fmt.Sprintf("{ service: %s, state: %s, dur_ms: %d, out_kind: %s, out_bytes: %d, model: %s, cost_milli: %d }",
			escYAML(jr.Service), escYAML(jr.State), jr.DurMs, escYAML(jr.OutKind), jr.OutBytes, escYAML(jr.Model), jr.CostMilli),
	}
	if len(stepsSummary) > 0 {
		extra["steps"] = escYAML(strings.Join(stepsSummary, ", "))
	}
	title := jr.Prompt
	// JSON-envelope tasks carry the whole request as "prompt" — the service id names them better.
	if title == "" || strings.HasPrefix(strings.TrimSpace(title), "{") {
		title = jr.Service + " " + id
	}
	cardRel, err := WriteSessionCard(hv.root, SessionCard{
		Bundle: source, ID: id, Shard: shard,
		Title:       title,
		Description: fmt.Sprintf("%s job via %s: %s (%.1fs).", m.Name, jr.Service, orDash(jr.State), float64(jr.DurMs)/1000),
		Tags:        []string{source, jr.Service},
		Intent:      intent,
		Provider:    m.AID, Requester: jr.Peer, Status: jr.State,
		StartedAt: started.Format(time.RFC3339), EndedAt: ended,
		Events: len(jr.Steps), Bytes: int64(jr.OutBytes),
		Extra: extra,
	})
	if err != nil {
		return err
	}
	_ = RegenIndex(filepath.Join(hv.root, source, "sessions", shard), false)
	return hv.store.PutSession(SessionRow{
		Source: source, SessionID: id,
		ProviderAID: m.AID, RequesterAID: jr.Peer,
		Intent: jr.Service, Goal: oneLine(jr.Prompt, 200), Status: jr.State,
		StartedAt: started.Format(time.RFC3339), EndedAt: ended,
		Events: len(jr.Steps), Bytes: int64(jr.OutBytes),
		CardPath: cardRel, DataPath: filepath.ToSlash(dataRel),
		UpdatedAt: nowRFC3339(),
	})
}

// ReadSessionData returns up to limit JSONL lines from a harvested session's data file.
func (hv *Harvester) ReadSessionData(source, sessionID string, limit int) ([]json.RawMessage, error) {
	row, err := hv.store.GetSession(source, sessionID)
	if err != nil {
		return nil, fmt.Errorf("admin: session not found")
	}
	full := filepath.Join(hv.root, source, row.DataPath)
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	var out []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() && len(out) < limit {
		out = append(out, json.RawMessage(append([]byte{}, sc.Bytes()...)))
	}
	return out, sc.Err()
}

// ReadSessionCard returns the rendered card markdown for a harvested session.
func (hv *Harvester) ReadSessionCard(source, sessionID string) (string, error) {
	row, err := hv.store.GetSession(source, sessionID)
	if err != nil {
		return "", fmt.Errorf("admin: session not found")
	}
	raw, err := os.ReadFile(filepath.Join(hv.root, source, row.CardPath))
	return string(raw), err
}
