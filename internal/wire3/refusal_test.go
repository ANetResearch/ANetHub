package wire3

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func write(rf Refusal) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Write(rec, rf)
	return rec
}

// G1: {"reason", "error", …} with the code's status, reason and error
// first, the extra members after them in name order, the same bytes every
// time.
func TestBodyShape(t *testing.T) {
	rec := write(Refusal{Reason: ReasonKeysRollback, Extra: map[string]any{"stored_seq": 7, "b": "x", "a": true}})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d", rec.Code)
	}
	want := `{"reason":"keys_rollback","error":` + mustJSON(t, Sentence(ReasonKeysRollback)) +
		`,"a":true,"b":"x","stored_seq":7}` + "\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body\n got %s\nwant %s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	if rec.Header().Get("Retry-After") != "" {
		t.Error("a 409 does not ask the caller to wait")
	}
	again := write(Refusal{Reason: ReasonKeysRollback, Extra: map[string]any{"a": true, "stored_seq": 7, "b": "x"}})
	if !bytes.Equal(again.Body.Bytes(), rec.Body.Bytes()) {
		t.Error("the same refusal must be the same bytes (SSR-H3 relies on it)")
	}
}

// A call site cannot overwrite reason or error through Extra.
func TestExtraCannotReplaceReasonOrError(t *testing.T) {
	rec := write(Refusal{Reason: ReasonNotFound, Extra: map[string]any{"reason": "ok", "error": "fine"}})
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b["reason"] != "not_found" || b["error"] != Sentence(ReasonNotFound) || len(b) != 2 {
		t.Fatalf("body %s", rec.Body)
	}
}

// wire_too_old always names the wire and the anet release (CORE-V1).
func TestWireTooOldNamesWhatToInstall(t *testing.T) {
	rec := write(Refusal{Reason: ReasonWireTooOld})
	if rec.Code != http.StatusUpgradeRequired {
		t.Fatalf("status %d", rec.Code)
	}
	var b map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b["required_wire"] != float64(3) || b["required_anet"] != "0.3.0" {
		t.Fatalf("body %s", rec.Body)
	}
}

// A specific sentence replaces the default; an empty one does not.
func TestSpecificSentence(t *testing.T) {
	rec := write(Refusal{Reason: ReasonBadAckItem, Error: "Item 3: handle and dack go together; fix it and send again."})
	if !strings.Contains(rec.Body.String(), "Item 3") {
		t.Fatalf("body %s", rec.Body)
	}
}

// A code outside the table never reaches a daemon: it goes out as internal.
func TestUnknownReasonIsInternal(t *testing.T) {
	rec := write(Refusal{Reason: "made_up", Error: "secret detail", Extra: map[string]any{"x": 1}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	want := `{"reason":"internal","error":` + mustJSON(t, Sentence(ReasonInternal)) + "}\n"
	if rec.Body.String() != want {
		t.Fatalf("body %s", rec.Body)
	}
	if _, err := Body(Refusal{Reason: "made_up"}); err == nil {
		t.Error("Body accepted an unregistered code")
	}
}

// An extra member that cannot be encoded is a bug at the call site; the
// caller still gets a well-formed body.
func TestUnencodableExtraIsInternal(t *testing.T) {
	rec := write(Refusal{Reason: ReasonTSStale, Extra: map[string]any{"floor": make(chan int)}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"reason":"internal"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// Internal keeps the error text in the log, not in the response.
func TestInternalDoesNotLeak(t *testing.T) {
	rec := httptest.NewRecorder()
	Internal(rec, errSecret("database file /var/lib/hub/hub.db is locked"))
	if strings.Contains(rec.Body.String(), "hub.db") {
		t.Fatalf("the internal error leaked: %s", rec.Body)
	}
}

type errSecret string

func (e errSecret) Error() string { return string(e) }

// Every waiting status carries Retry-After in whole seconds, rounded up,
// at least 1 and at most a day; without a value from the call site it is
// DefaultRetryAfter. Other statuses carry none.
func TestRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "60"}, {-time.Second, "60"}, {time.Millisecond, "1"}, {time.Second, "1"},
		{1500 * time.Millisecond, "2"}, {90 * time.Second, "90"}, {48 * time.Hour, "86400"},
	} {
		if got := RetryAfterSeconds(tc.d); got != tc.want {
			t.Errorf("RetryAfterSeconds(%s) = %s, want %s", tc.d, got, tc.want)
		}
	}
	for code, info := range reasons {
		rec := write(Refusal{Reason: code, RetryAfter: 5 * time.Second, Extra: sampleExtra(code)})
		got := rec.Header().Get("Retry-After")
		if Waits(info.status) && got != "5" {
			t.Errorf("%s (%d): Retry-After %q, want 5", code, info.status, got)
		}
		if !Waits(info.status) && got != "" {
			t.Errorf("%s (%d) asks the caller to wait (Retry-After %q)", code, info.status, got)
		}
	}
}

// sampleExtra gives the members a code requires.
func sampleExtra(code Reason) map[string]any {
	m := map[string]any{}
	for _, k := range reasons[code].extra {
		m[k] = 1
	}
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
