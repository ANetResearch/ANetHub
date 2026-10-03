package wire3

import (
	"bytes"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// Refusal is one wire-3 error body (core G1):
//
//	{"reason": "<code>", "error": "<one English sentence>", …Extra}
//
// sent with the one HTTP status of the code, and with Retry-After when that
// status asks the caller to wait (Waits).
type Refusal struct {
	// Reason is the code. It must be one of the table (Known); Write
	// sends an unknown one as internal, because a code outside the
	// registered set must never reach a daemon.
	Reason Reason
	// Error replaces the code's default sentence. Leave it empty unless
	// the call site can say something more specific (which item, which
	// limit); a refusal whose bodies must be indistinguishable (core
	// SSR-H3) keeps the default.
	Error string
	// RetryAfter is sent as Retry-After, in whole seconds rounded up, at
	// least 1 and at most a day. A waiting status without it gets
	// DefaultRetryAfter, so the header is never missing.
	RetryAfter time.Duration
	// Extra holds the members the body carries besides reason and error
	// (ExtraMembers names those a code requires): floor, stored_seq,
	// max_bits, aid, challenge. "reason" and "error" are ignored here.
	Extra map[string]any
}

// DefaultRetryAfter is the Retry-After of a waiting refusal whose call site
// did not give one.
const DefaultRetryAfter = 60 * time.Second

// maxRetryAfter bounds Retry-After: a day, the longest any hub wait is
// (the registration quota resets at the next UTC midnight).
const maxRetryAfter = 24 * time.Hour

// Write sends rf.
func Write(w http.ResponseWriter, rf Refusal) {
	info, ok := reasons[rf.Reason]
	if !ok {
		log.Printf("hub: refusal with the unregistered reason %q sent as %s", rf.Reason, ReasonInternal)
		rf = Refusal{Reason: ReasonInternal}
		info = reasons[ReasonInternal]
	}
	body, err := Body(rf)
	if err != nil {
		log.Printf("hub: refusal %s: %v; sent as %s", rf.Reason, err, ReasonInternal)
		rf = Refusal{Reason: ReasonInternal}
		info = reasons[ReasonInternal]
		body, _ = Body(rf)
	}
	h := w.Header()
	h.Set(Header, versionText) // Contract stamps it too; a refusal states it wherever it is written
	h.Set("Content-Type", "application/json")
	h.Del("Content-Length")
	if Waits(info.status) {
		h.Set("Retry-After", RetryAfterSeconds(rf.RetryAfter))
	}
	w.WriteHeader(info.status)
	_, _ = w.Write(body)
}

// Refuse sends the code with its default sentence and no extra members.
func Refuse(w http.ResponseWriter, r Reason) { Write(w, Refusal{Reason: r}) }

// Internal logs err and sends 500 internal. The error text stays in the
// log: it describes this hub, not the request, and is nothing a caller can
// act on.
func Internal(w http.ResponseWriter, err error) {
	log.Printf("hub: internal error: %v", err)
	Refuse(w, ReasonInternal)
}

// RetryAfterSeconds formats d as a Retry-After value: whole seconds,
// rounded up, between 1 and a day; 0 or less is DefaultRetryAfter.
func RetryAfterSeconds(d time.Duration) string {
	if d <= 0 {
		d = DefaultRetryAfter
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	s := int64(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return strconv.FormatInt(s, 10)
}

// Body encodes rf: reason and error first, then the extra members in
// name order, then a newline. The same refusal is always the same bytes.
// wire_too_old always carries required_wire and required_anet.
func Body(rf Refusal) ([]byte, error) {
	info, ok := reasons[rf.Reason]
	if !ok {
		return nil, &json.UnsupportedValueError{Str: "unregistered hub reason " + strconv.Quote(string(rf.Reason))}
	}
	sentence := rf.Error
	if sentence == "" {
		sentence = info.sentence
	}
	extra := map[string]any{}
	for k, v := range rf.Extra {
		if k != "reason" && k != "error" {
			extra[k] = v
		}
	}
	if rf.Reason == ReasonWireTooOld {
		extra["required_wire"] = Version
		extra["required_anet"] = RequiredAnet
	}
	names := make([]string, 0, len(extra))
	for k := range extra {
		names = append(names, k)
	}
	sort.Strings(names)

	var b bytes.Buffer
	b.WriteString(`{"reason":`)
	if err := appendJSON(&b, string(rf.Reason)); err != nil {
		return nil, err
	}
	b.WriteString(`,"error":`)
	if err := appendJSON(&b, sentence); err != nil {
		return nil, err
	}
	for _, k := range names {
		b.WriteByte(',')
		if err := appendJSON(&b, k); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		if err := appendJSON(&b, extra[k]); err != nil {
			return nil, err
		}
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}

// appendJSON appends the JSON encoding of v (HTML-escaped, as every other
// hub response is).
func appendJSON(b *bytes.Buffer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.Write(raw)
	return nil
}
