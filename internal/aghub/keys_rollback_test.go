package aghub_test

// The prev_seq rule of key set publication (forward-secrecy FS-H4, core
// §2.12.2, hub-payment-privacy PAY-A1 steps 3 and 9).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// answers decodes the answers of key set publications for t: rollback a 409
// keys_rollback (its stored_seq), status a 200 (its keys_status); anything
// else fails the test.
func answers(t *testing.T) (rollback func(int, []byte) uint64, status func(int, []byte) string) {
	return func(code int, body []byte) uint64 { t.Helper(); return rollbackOf(t, code, body) },
		func(code int, body []byte) string { t.Helper(); return statusOf(t, code, body) }
}

// rollbackOf decodes a 409 keys_rollback, or fails the test.
func rollbackOf(t *testing.T, code int, body []byte) uint64 {
	t.Helper()
	var r struct {
		Reason    string  `json:"reason"`
		Error     string  `json:"error"`
		StoredSeq *uint64 `json:"stored_seq"`
	}
	if code != http.StatusConflict || json.Unmarshal(body, &r) != nil || r.Reason != "keys_rollback" ||
		r.Error == "" || r.StoredSeq == nil {
		t.Fatalf("%d %s, want 409 keys_rollback with stored_seq", code, body)
	}
	return *r.StoredSeq
}

// statusOf is the keys_status of a 200.
func statusOf(t *testing.T, code int, body []byte) string {
	t.Helper()
	var out aghub.KeysPublishResponse
	if code != http.StatusOK || json.Unmarshal(body, &out) != nil {
		t.Fatalf("%d %s, want 200", code, body)
	}
	return out.KeysStatus
}

// servedKeys is the key set srv serves for c.
func servedKeys(t *testing.T, srv string, c *identity.Controller) []byte {
	t.Helper()
	code, b := getJSON(t, srv+"/agents/"+c.AID()+"/keys")
	var v aghub.KeysView
	if code != http.StatusOK || json.Unmarshal(b, &v) != nil {
		t.Fatalf("get keys: %d %s", code, b)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v.Keys)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestPublishKeysRollback409 (FS-H4, mutation 20): POST /agents/{aid}/keys
// is a compare-and-swap on prev_seq. A hub holding a newer set than the one
// a publication follows refuses it 409 keys_rollback, naming the seq it
// holds, and keeps its set, even when the new set's own seq is higher (the
// publisher's data went back to an older state, or another copy of it runs);
// so does a set not above the stored one. A publication that follows the
// stored set, or a newer one (a hub that lost a set), is stored, and the
// stored set sent again is unchanged whatever its prev_seq.
func TestPublishKeysRollback409(t *testing.T) {
	srv := newHub(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	k100, _ := mintKeySet(t, c, 100)
	k200, _ := mintKeySet(t, c, 200)
	k150, _ := mintKeySet(t, c, 150)
	k300, _ := mintKeySet(t, c, 300)
	rollback, status := answers(t)

	if s := status(publishKeysPrev(t, srv, c, k100, 0)); s != aghub.KeysStatusOK {
		t.Fatalf("the first set: %s", s)
	}
	if got := rollback(publishKeysPrev(t, srv, c, k200, 50)); got != 100 {
		t.Errorf("stored_seq %d, want 100", got)
	}
	if !bytes.Equal(servedKeys(t, srv.URL, c), k100) {
		t.Fatal("a refused publication replaced the stored set")
	}
	if s := status(publishKeysPrev(t, srv, c, k200, 100)); s != aghub.KeysStatusOK {
		t.Fatalf("following the stored set: %s", s)
	}
	if s := status(publishKeysPrev(t, srv, c, k200, 100)); s != aghub.KeysStatusUnchanged {
		t.Errorf("the stored set again: %s, want unchanged", s)
	}
	if s := status(publishKeysPrev(t, srv, c, k200, 0)); s != aghub.KeysStatusUnchanged {
		t.Errorf("the stored set again with an old prev_seq: %s, want unchanged", s)
	}
	if got := rollback(publishKeysPrev(t, srv, c, k150, 200)); got != 200 {
		t.Errorf("a set below the stored one: stored_seq %d, want 200", got)
	}
	if s := status(publishKeysPrev(t, srv, c, k300, 250)); s != aghub.KeysStatusOK {
		t.Errorf("a prev_seq above the stored seq: %s, want ok", s)
	}
	if !bytes.Equal(servedKeys(t, srv.URL, c), k300) {
		t.Fatal("the hub does not serve the newest set")
	}
}

// TestRegisterRollback409 (FS-H4, PAY-A1 step 9): /register with a key
// set that does not follow the stored one is 409 keys_rollback with
// stored_seq, decided before anything is written: the registration's other
// fields are not applied either. The same registration following the stored
// set is registered; the stored set sent again is unchanged.
func TestRegisterRollback409(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, _ := twoAgents(t)
	register(t, srv, c, "Before", nil)
	k100, _ := mintKeySet(t, c, 100)
	k200, _ := mintKeySet(t, c, 200)
	rollback, status := answers(t)
	if s := status(publishKeysPrev(t, srv, c, k100, 0)); s != aghub.KeysStatusOK {
		t.Fatalf("the first set: %s", s)
	}
	reg := func(prev uint64) (int, []byte) {
		body := registerBody(t, c, "After", nil)
		body["enc_keys"], body["prev_seq"] = base64.RawURLEncoding.EncodeToString(k200), prev
		return registerFunded(t, srv, c, body)
	}
	if got := rollback(reg(50)); got != 100 {
		t.Errorf("stored_seq %d, want 100", got)
	}
	if av, _, err := store.GetAgent(c.AID()); err != nil || av.Name != "Before" {
		t.Errorf("the refused registration was written: name %q, %v", av.Name, err)
	}
	if !bytes.Equal(servedKeys(t, srv.URL, c), k100) {
		t.Fatal("the refused registration replaced the stored set")
	}
	code, b := reg(100)
	var out aghub.RegisterResponse
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.KeysStatus != aghub.KeysStatusOK {
		t.Fatalf("following the stored set: %d %s", code, b)
	}
	if av, _, _ := store.GetAgent(c.AID()); av.Name != "After" {
		t.Errorf("name %q after the registration", av.Name)
	}
	code, b = reg(0)
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil || out.KeysStatus != aghub.KeysStatusUnchanged {
		t.Fatalf("the stored set again: %d %s, want unchanged", code, b)
	}
}

// TestPublishKeysNeedsPrevSeq (FS-H4, PAY-A1 step 3): a publication, and a
// registration that carries a key set, without prev_seq are 400 bad_request
// and change nothing: a publisher that does not say which set it follows
// could overwrite a newer one. A new agent's registration refused for it
// leaves no agent behind.
func TestPublishKeysNeedsPrevSeq(t *testing.T) {
	srv, store := newHubWithStore(t)
	c, fresh := twoAgents(t)
	register(t, srv, c, "Agent", nil)
	k1, _ := mintKeySet(t, c, 1)
	code, b := signedDo(t, srv, c, relayauth.ActionKeys, http.MethodPost, "/agents/"+c.AID()+"/keys",
		map[string]any{"keys": base64.RawURLEncoding.EncodeToString(k1)})
	if code != http.StatusBadRequest || !bytes.Contains(b, []byte(`"bad_request"`)) || !bytes.Contains(b, []byte("prev_seq")) {
		t.Errorf("a publication without prev_seq: %d %s", code, b)
	}
	if code, _ := getJSON(t, srv.URL+"/agents/"+c.AID()+"/keys"); code != http.StatusNotFound {
		t.Errorf("a refused publication stored a set (%d)", code)
	}
	for _, who := range []*identity.Controller{c, fresh} {
		known := store.KnowsAgent(who.AID())
		k, _ := mintKeySet(t, who, 1)
		body := registerBody(t, who, "Agent", nil)
		body["enc_keys"] = base64.RawURLEncoding.EncodeToString(k)
		code, b := registerFunded(t, srv, who, body)
		if code != http.StatusBadRequest || !bytes.Contains(b, []byte("prev_seq")) {
			t.Errorf("/register with enc_keys and no prev_seq: %d %s", code, b)
		}
		if store.KnowsAgent(who.AID()) != known {
			t.Errorf("a refused registration changed whether the hub knows the agent")
		}
	}
}
