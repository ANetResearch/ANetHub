package relayauth

import (
	"strings"
	"testing"
)

// This file is a copy. That is the thing it exists to defend against.
//
// The daemon signs Preimage(...) and the hub rebuilds the identical bytes
// to verify. They are never exchanged, only recomputed independently — and
// the package doc says "shared here so the signer and verifier can never
// disagree", which is a claim about intent, not a mechanism. There are two
// copies of this file, in two repositories, with nothing holding them
// together.
//
// So both copies pin the same literal. A change to either side now fails a
// test in the repository where it was made, instead of appearing as every
// node in the network being unable to read its own mailbox, signing with a
// key the hub agrees is valid.
//
// The real fix is one copy in ANetCore, where the rest of the wire
// contract already lives. Until then, this.
func TestPreimageBytesArePinned(t *testing.T) {
	const aid = "bafyreihnnooeomsi5widaw5oc2xiisivmuipzalyxxb7mybqwu4uj7ipay"
	got := string(Preimage(ActionPoll, aid, 1767225600000))
	want := "anet-relay/poll/" + aid + "/1767225600000"
	if got != want {
		t.Fatalf("the verified bytes moved:\n got %s\nwant %s\n"+
			"The daemon still signs the other form. Every node is now locked out.", got, want)
	}
}

// A signature authorises one action, for one AID, at one time.
func TestASignatureAuthorisesOnlyWhatItSays(t *testing.T) {
	const alice = "did:anet:alice"
	base := string(Preimage(ActionPoll, alice, 1000))

	for _, action := range []string{ActionAck, ActionRegister, ActionProfile} {
		if string(Preimage(action, alice, 1000)) == base {
			t.Errorf("%q and %q share a challenge — one captured signature would authorise both",
				ActionPoll, action)
		}
	}
	if string(Preimage(ActionPoll, "did:anet:bob", 1000)) == base {
		t.Error("two AIDs share a challenge — Alice's signature would open Bob's mailbox")
	}
	if string(Preimage(ActionPoll, alice, 1001)) == base {
		t.Error("the timestamp is not in the challenge — a captured signature would never expire")
	}
}

// The window the hub actually enforces. Five minutes on one side and ten
// on the other is a wider replay window than either repository thinks it
// has.
func TestReplayWindowIsFiveMinutes(t *testing.T) {
	if MaxSkewMillis != 5*60*1000 {
		t.Fatalf("replay window = %dms, want 300000ms — the daemon assumes this number too",
			MaxSkewMillis)
	}
}

// The separator only separates because no field contains it.
func TestTheFormatIsUnambiguousOnlyForSlashFreeFields(t *testing.T) {
	for _, a := range []string{ActionPoll, ActionAck, ActionRegister, ActionProfile} {
		if strings.Contains(a, "/") {
			t.Errorf("action %q contains the separator: it can pose as a different action+aid pair", a)
		}
	}
	if string(Preimage("poll", "a/1", 2)) != string(Preimage("poll/a", "1", 2)) {
		t.Fatal("expected the documented ambiguity; the format changed, so re-derive the precondition")
	}
}
