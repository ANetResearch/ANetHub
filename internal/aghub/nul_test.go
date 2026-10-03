package aghub_test

import (
	"testing"

	"github.com/ANetResearch/ANetCore/wire"
)

// TestPreimageRejectsNUL (core CORE-E9, ANetHub). The hub computes two inputs that separate
// variable-length text fields with 0x00 (CORE-L1): the review tag (L31) and the settlement guard
// (L33). A field holding U+0000 could move the boundary, so each function refuses one, as a second
// line behind the decode points (wire3.CheckRequest, wire3.DecodeStrict, wire3.CheckText; their
// cases are in testdata/wire3/nul.json).
//
// One row per registered guard of this repository (registry nul_guard). A row's function puts
// field into each 0x00-separated text position it has and returns the function's error. The
// work item that implements a function fills in its row and deletes the skip.
func TestPreimageRejectsNUL(t *testing.T) {
	rows := map[string]struct {
		fn   func(field string) error
		todo string
	}{
		"L31": {nil, "v030-todo(PAY-6)"}, // review tag: reviewer_aid, subject_aid
		"L33": {nil, "v030-todo(PAY-4)"}, // settlement guard: payer, pay_bind
	}
	r, err := wire.Load()
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, g := range r.NUL {
		if g.Repo != "ANetHub" {
			continue
		}
		listed[g.Label] = true
		row, ok := rows[g.Label]
		if !ok {
			t.Errorf("registry nul_guard %s (%s) has no row here", g.Label, g.What)
			continue
		}
		t.Run(g.Label+" "+g.What, func(t *testing.T) {
			if row.fn == nil {
				t.Skip(row.todo)
			}
			for _, f := range []string{"\x00", "a\x00", "\x00b", "a\x00b"} {
				if err := row.fn(f); err == nil {
					t.Errorf("%q accepted", f)
				}
			}
			if err := row.fn("ab"); err != nil {
				t.Errorf("a field without U+0000 refused: %v", err)
			}
		})
	}
	for label := range rows {
		if !listed[label] {
			t.Errorf("row %s is not a registered ANetHub nul_guard", label)
		}
	}
}
