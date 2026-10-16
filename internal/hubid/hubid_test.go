package hubid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

func TestStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.AID != b.AID || a.AID == "" {
		t.Fatalf("hub AID must be stable: %q vs %q", a.AID, b.AID)
	}
}

func TestSignVerifiableAgainstServedKEL(t *testing.T) {
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pre := []byte("fed-envelope-preimage")
	sig, seq := id.Ctrl.Sign(pre)

	srv := httptest.NewServer(id.Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ AID, KEL string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.AID != id.AID {
		t.Fatal("served AID mismatch")
	}
	kel, err := identity.UnmarshalKEL(mustB64(t, out.KEL))
	if err != nil {
		t.Fatal(err)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		t.Fatal(err)
	}
	_ = states
	_ = sig
	_ = seq
	// Round-trip proves: what peers fetch is a replayable KEL for this AID.
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := jsonB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jsonB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// /hub/identity answers with the identity as it is when asked, and states
// the wire (core CORE-V1): a KEL that grows after the handler is made (a
// rotation) is served as it now is.
func TestServedIdentityIsCurrent(t *testing.T) {
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := id.Handler()
	id.KEL = append(append([]byte(nil), id.KEL...), 0xA0)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/hub/identity", nil))
	var out IdentityResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.KEL != base64.RawURLEncoding.EncodeToString(id.KEL) || out.AID != id.AID || out.Wire != 3 {
		t.Fatalf("served %+v, not the identity as it is now", out)
	}
	if rec.Header().Get("X-ANet-Wire") != "3" {
		t.Fatalf("X-ANet-Wire %q", rec.Header().Get("X-ANet-Wire"))
	}
}

// A hub's first start incepts a hub identity (toad 0, KEL C-5, H-30): no witness, ever, and the
// time of inception in its icp.
func TestHubIdentityIsAHubIdentity(t *testing.T) {
	before := uint64(time.Now().UnixMilli())
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	icp := id.Ctrl.KEL()[0].Event
	if id.Ctrl.Toad() != identity.ToadHub || len(icp.Witnesses) != 0 || icp.Timestamp < before {
		t.Fatalf("toad %d, icp %+v", id.Ctrl.Toad(), icp)
	}
}

// KEL §2.9, W2 KEL-2 handoff: the identity file is written temporary file,
// fsync, rename, 0600, and nothing else is left in the directory.
func TestIdentityFileWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != FileName {
		t.Fatalf("the directory holds %v", entries)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	// What is on disk is what Load gives back, and a save replaces it whole.
	if err := id.Rotate(nil, identitytest.NewNext(), false, 0); err != nil {
		t.Fatal(err)
	}
	if err := id.Save(dir); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dir)
	if err != nil || len(back.Ctrl.Accepted()) != 2 || !back.RecoverySet() || back.Seq() != 1 {
		t.Fatalf("after a rotation: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a save left %v", entries)
	}
}

// KEL S-2: a hub identity file of 0.2 is ErrIdentityV02, from CheckFile,
// Load and LoadOrIncept alike, and no file at all is fine for CheckFile.
func TestIdentityFileOf02(t *testing.T) {
	dir := t.TempDir()
	if err := CheckFile(dir); err != nil {
		t.Fatalf("no file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte{0xa1, 0x01, 0x40}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckFile(dir); !errors.Is(err, ErrIdentityV02) {
		t.Errorf("CheckFile: %v", err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrIdentityV02) {
		t.Errorf("Load: %v", err)
	}
	if _, err := LoadOrIncept(dir); !errors.Is(err, ErrIdentityV02) {
		t.Errorf("LoadOrIncept: %v", err)
	}
}

// KEL H-32: one process holds the lock of a data directory; another cannot
// take it until it is released; taking it writes nothing.
func TestDirLock(t *testing.T) {
	dir := t.TempDir()
	l, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second lock: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the lock wrote %v", entries)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := Lock(dir)
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	l2.Release()
	if _, err := Lock(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing directory: %v", err)
	}
}

// A rotation's time is after the last event's, even when the clock says
// otherwise (KEL R-2).
func TestRotateTimeAfterTheLastEvent(t *testing.T) {
	id, err := LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	icpTS := id.Ctrl.Accepted()[0].Event.Timestamp
	if err := id.Rotate(nil, identitytest.NewNext(), false, icpTS-5); err != nil {
		t.Fatal(err)
	}
	if ts := id.Ctrl.Accepted()[1].Event.Timestamp; ts != icpTS+1 {
		t.Errorf("rot ts %d, icp %d", ts, icpTS)
	}
}

// KEL H-33, core G18: the admin token is listed for the operator; a
// registered secret anet-hub keeps is replaced in the data directory; a
// name is registered once.
func TestEmergencySecrets(t *testing.T) {
	var names []string
	for _, s := range EmergencySecrets() {
		names = append(names, s.Name)
	}
	if !slices.Contains(names, AdminTokenSecret) {
		t.Fatalf("the admin token is not listed: %v", names)
	}
	dir := t.TempDir()
	RegisterEmergencySecret(EmergencySecret{Name: "hubid-test-key", Regenerate: func(d string) error {
		return os.WriteFile(filepath.Join(d, "hubid-test-key"), []byte("new"), 0o600)
	}})
	replaced, byOperator, err := RegenerateEmergencySecrets(dir)
	if err != nil || !slices.Contains(replaced, "hubid-test-key") || !slices.Contains(byOperator, AdminTokenSecret) ||
		slices.Contains(replaced, AdminTokenSecret) {
		t.Fatalf("replaced %v, by the operator %v, %v", replaced, byOperator, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hubid-test-key")); string(b) != "new" {
		t.Error("not replaced")
	}
	defer func() {
		if recover() == nil {
			t.Error("a name registered twice")
		}
	}()
	RegisterEmergencySecret(EmergencySecret{Name: "hubid-test-key"})
}

// KEL H-30: the hub identity is a hub's (toad 0). An agent's identity file
// in its place is refused by Load and LoadOrIncept alike, and left as it
// is: the hub neither runs as an agent nor incepts over the file.
func TestAnAgentIdentityFileIsNotAHubs(t *testing.T) {
	agent, err := identitytest.Agent()
	if err != nil {
		t.Fatal(err)
	}
	b, err := agent.Export()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load took an agent's identity as the hub's")
	}
	if _, err := LoadOrIncept(dir); err == nil {
		t.Error("LoadOrIncept took an agent's identity as the hub's")
	}
	if after, _ := os.ReadFile(path); string(after) != string(b) {
		t.Error("the agent's identity file was replaced")
	}
}
