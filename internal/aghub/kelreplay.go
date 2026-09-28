package aghub

import (
	"crypto/ed25519"
	"sync"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/identity"
)

// Checking a signature against a KEL replays the KEL, one Ed25519
// verification per event, up to seal.MaxKELEvents. This hub checks the
// KELs it holds on behalf of whoever asks: every signed request against
// its signer's stored KEL, and on unauthenticated routes a payment
// authorization against its payer's, a review against its two parties', a
// synced key set against its owner's, a card against its agent's. Capping
// the stored KEL at /register [redteam:F36] left each of those at the
// replay of up to the cap, per request: a request that named an agent with
// a long KEL and carried a signature of zeros cost the hub the whole replay
// before it was refused 401, tens of times what a one-event agent's costs.
//
// Two things bound it now.
//
//   - The process replays each KEL once: Open installs an
//     identity.ReplayCache, which answers every replay in ANetCore (and so
//     every Verify built on one) from what the same KEL replayed to before.
//   - A signature is checked against the key the KEL names before the KEL
//     is replayed (plausibleSignature), where the request says what was
//     signed. A request whose signature is no good costs one verification
//     however long the KEL it names, and cannot push the KELs in use out of
//     the cache by naming more long KELs than it holds.

// kelReplayCacheBytes bounds the process's identity.ReplayCache. A one-event
// KEL costs some hundreds of bytes there and one at the cap some 40 KiB, so
// this holds every agent of a large hub, or some 1,600 KELs at the cap.
const kelReplayCacheBytes = 64 << 20

var installReplayCache sync.Once

// useReplayCache installs the process's identity.ReplayCache, once. Open
// calls it: a process with a hub store verifies against the KELs in it.
func useReplayCache() {
	installReplayCache.Do(func() {
		if prev := identity.SetReplayCache(identity.NewReplayCache(kelReplayCacheBytes)); prev != nil {
			identity.SetReplayCache(prev) // somebody installed one already; keep it
		}
	})
}

// plausibleSignature checks sig over pre against the key kel names at
// key-state seq, without checking any event of kel: the key of the last icp
// or rot at or before seq. When kel replays, that is the key
// identity.VerifyObject checks the signature against, so a signature that
// fails here fails there, whatever the replay would find; the refusal is
// the one VerifyObject gives for it. A signature that passes here is still
// to be verified against the replayed KEL.
func plausibleSignature(kel []identity.SignedEvent, seq uint64, pre, sig []byte) *identity.VErr {
	if seq >= uint64(len(kel)) {
		return &identity.VErr{Reason: "KEY_STATE_DOWNGRADE", Detail: "declared key_state_seq beyond KEL"}
	}
	var key []byte
	for _, se := range kel[:seq+1] {
		if t := se.Event.Type; (t == identity.Inception || t == identity.Rotation) && len(se.Event.Keys) > 0 {
			key = se.Event.Keys[0]
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return &identity.VErr{Reason: "UNKNOWN_AID", Detail: "no current key at declared key_state_seq"}
	}
	if !ed25519.Verify(key, pre, sig) {
		return &identity.VErr{Reason: "INVALID_SIGNATURE", Detail: "signature does not verify under key at key_state_seq"}
	}
	return nil
}

// plausibleEnvelope is plausibleSignature for a signed object whose Verify
// checks its envelope first (present, well formed, signed by signer) and
// then the signature over preimage: nil when that Verify would refuse the
// object before its signature, which costs no replay.
func plausibleEnvelope(env *aobj.Envelope, signer string, kel []identity.SignedEvent,
	preimage func() ([]byte, error)) *identity.VErr {
	if env == nil || env.Validate() != nil || env.SignerAID != signer {
		return nil
	}
	pre, err := preimage()
	if err != nil {
		return nil
	}
	return plausibleSignature(kel, env.KeyStateSeq, pre, env.Sig)
}
