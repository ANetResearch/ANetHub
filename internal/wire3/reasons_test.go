package wire3

import (
	"net/http"
	"strings"
	"testing"
	"unicode"

	"github.com/ANetResearch/ANetCore/wire"
)

// The table is the registry's reasons.hub, code for code and status for
// status (core §2.15.1). TestWireRegistry checks the codes through the
// //anet:wire annotations; this checks the statuses too, which the scan
// cannot see.
func TestReasonTableIsTheRegistry(t *testing.T) {
	reg, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	inRegistry := map[Reason]int{}
	for _, r := range reg.Reasons.Hub {
		inRegistry[Reason(r.Code)] = r.Status
	}
	for code, st := range inRegistry {
		info, ok := reasons[code]
		if !ok {
			t.Errorf("registry hub reason %s is missing from the table", code)
			continue
		}
		if info.status != st {
			t.Errorf("%s: the table sends %d, the registry says %d", code, info.status, st)
		}
	}
	for code := range reasons {
		if _, ok := inRegistry[code]; !ok {
			t.Errorf("table code %s is not a registered hub reason", code)
		}
	}
	if reg.HubAPI.Wire != Version {
		t.Errorf("registry hub wire %d, this package speaks %d", reg.HubAPI.Wire, Version)
	}
	for _, r := range reg.Reasons.Retired {
		if Known(Reason(r.Code)) {
			t.Errorf("retired code %s is in the table (CORE-F3)", r.Code)
		}
	}
}

// The extra members a code carries are the ones core §2.12.2 and §2.15.1
// name for it.
func TestReasonExtraMembers(t *testing.T) {
	want := map[Reason][]string{
		ReasonWireTooOld:        {"required_wire", "required_anet"},
		ReasonTSStale:           {"floor"},
		ReasonKeysRollback:      {"stored_seq"},
		ReasonBucketTooNarrow:   {"max_bits"},
		ReasonAdmissionRequired: {"aid"},
		ReasonPowRequired:       {"challenge"},
	}
	for code, info := range reasons {
		if strings.Join(info.extra, ",") != strings.Join(want[code], ",") {
			t.Errorf("%s carries %v, want %v", code, info.extra, want[code])
		}
	}
}

// Every default sentence says what happened and what to do, in one
// English sentence that a person can read in a terminal: printable ASCII,
// one line, at most 240 characters (ux UX-G7), capitalised, ending in a
// full stop, with "; " before the next step, and no placeholder.
func TestReasonSentences(t *testing.T) {
	for code, info := range reasons {
		s := info.sentence
		switch {
		case s == "":
			t.Errorf("%s has no sentence", code)
			continue
		case len(s) > 240:
			t.Errorf("%s: %d characters, at most 240", code, len(s))
		case !unicode.IsUpper(rune(s[0])):
			t.Errorf("%s: %q does not start with a capital", code, s)
		case !strings.HasSuffix(s, "."):
			t.Errorf("%s: %q does not end with a full stop", code, s)
		case !strings.Contains(s, "; "):
			t.Errorf("%s: %q has no \"; \" before its next step", code, s)
		case strings.ContainsAny(s, "{}\n\t"):
			t.Errorf("%s: %q has a placeholder or a control character", code, s)
		}
		for _, r := range s {
			if r < 0x20 || r > 0x7e {
				t.Errorf("%s: %q is not printable ASCII", code, s)
				break
			}
		}
	}
}

// The status says whether the caller waits: 429, 502, 503 and the 507 of a
// full mailbox carry Retry-After, nothing else does.
func TestWaits(t *testing.T) {
	for st, want := range map[int]bool{
		http.StatusTooManyRequests: true, http.StatusBadGateway: true, http.StatusServiceUnavailable: true,
		http.StatusInsufficientStorage: true, http.StatusBadRequest: false, http.StatusUpgradeRequired: false,
		http.StatusForbidden: false, http.StatusInternalServerError: false, http.StatusConflict: false,
	} {
		if Waits(st) != want {
			t.Errorf("Waits(%d) = %v", st, !want)
		}
	}
}
