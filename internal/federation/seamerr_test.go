package federation

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ANetResearch/ANetHub/internal/seamerr"
)

// The kernel tests the errors its federation hooks return against the
// internal/seamerr sentinels, not against this package's, so that a
// no_federation build links no federation symbol. These sentinels must
// therefore match the seamerr ones under errors.Is, wrapped or not, and
// must not match the other one.
func TestFederationSentinelsMatchTheKernelSeam(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err, kernel error
		other       error
	}{
		{"mailbox full", ErrMailboxFull, seamerr.ErrMailboxFull, seamerr.ErrNoKeys},
		{"no keys", ErrNoKeys, seamerr.ErrNoKeys, seamerr.ErrMailboxFull},
	} {
		wrapped := fmt.Errorf("peer answered 507: %w", tc.err)
		for _, e := range []error{tc.err, wrapped} {
			if !errors.Is(e, tc.kernel) {
				t.Errorf("%s: %v does not match the kernel sentinel", tc.name, e)
			}
			if !errors.Is(e, tc.err) {
				t.Errorf("%s: %v no longer matches its own sentinel", tc.name, e)
			}
			if errors.Is(e, tc.other) {
				t.Errorf("%s: %v matches the other kernel sentinel", tc.name, e)
			}
		}
	}
}
