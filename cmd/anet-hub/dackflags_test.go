package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// TestNoDeliveryConfirmationFlags (p2p-receipts DLV-H-10, T51 the hub's
// part): the status checks' rates, the confirmations' time and the bound of
// relay_dack are constants; anet-hub -h has no flag for them.
func TestNoDeliveryConfirmationFlags(t *testing.T) {
	fs := flag.NewFlagSet("anet-hub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defineFlags(fs)
	var help strings.Builder
	fs.SetOutput(&help)
	fs.PrintDefaults()
	fs.VisitAll(func(f *flag.Flag) {
		for _, w := range []string{"status", "dack", "ack", "confirm", "receipt", "handle", "stash", "held"} {
			if strings.Contains(f.Name, w) {
				t.Errorf("-%s looks like a delivery confirmation setting; those are constants (DLV-H-10)", f.Name)
			}
		}
	})
	for _, w := range []string{"status check", "delivery confirmation", "relay_dack", "relay/status"} {
		if strings.Contains(strings.ToLower(help.String()), w) {
			t.Errorf("anet-hub -h mentions %q", w)
		}
	}
}
