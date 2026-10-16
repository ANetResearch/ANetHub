package aghub

import (
	"os"
	"strings"
	"testing"
)

// An agent controls its name and summary; one unbroken string must not widen the page.
func TestResearchCardsBreakLongWords(t *testing.T) {
	b, err := os.ReadFile("web/research.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, ".card{") {
			if !strings.Contains(l, "overflow-wrap:anywhere") || !strings.Contains(l, "min-width:0") {
				t.Fatalf(".card must wrap long words: %s", l)
			}
			return
		}
	}
	t.Fatal("no .card rule")
}
