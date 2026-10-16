package aghub

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// plausibleSignature promises that a signature it refuses is refused by
// identity.VerifyObject too, for the same reason, whatever the object's
// time. KEL v2 moved the dip's own state ahead of the signature check
// (KEL C-10 step 3), so a signature declared at the dip's seq is
// REVOKED_KEY here as well, never INVALID_SIGNATURE.
func TestPlausibleSignatureRefusesAsVerifyObjectDoes(t *testing.T) {
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	pre := []byte("an object")
	s0, _ := c.Sign(pre)
	if err := identitytest.Rotate(c, 2000); err != nil {
		t.Fatal(err)
	}
	s1, _ := c.Sign(pre)
	if err := identitytest.Rotate(c, 3000); err != nil {
		t.Fatal(err)
	}
	s2, _ := c.Sign(pre)
	if err := identitytest.Deactivate(c, 4000); err != nil {
		t.Fatal(err)
	}
	kel := c.KEL()
	sigs := map[string][]byte{"zeros": make([]byte, ed25519.SignatureSize), "k0": s0, "k1": s1, "k2": s2}
	for seq := uint64(0); seq <= uint64(len(kel)); seq++ {
		for name, sig := range sigs {
			got := plausibleSignature(kel, seq, pre, sig)
			if seq == 3 && (got == nil || got.Reason != "REVOKED_KEY") {
				t.Errorf("seq 3 (the dip), sig %s: %v, want REVOKED_KEY", name, got)
			}
			if got == nil {
				continue
			}
			for _, msgTime := range []uint64{0, 1, 2500, 1 << 50} {
				var ve *identity.VErr
				err := identity.VerifyObject(kel, c.AID(), seq, msgTime, pre, sig)
				if !errors.As(err, &ve) || ve.Reason != got.Reason {
					t.Errorf("seq %d, sig %s, msgTime %d: plausibleSignature %s, VerifyObject %v",
						seq, name, msgTime, got.Reason, err)
				}
			}
		}
	}
}
