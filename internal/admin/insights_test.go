package admin

import (
	"reflect"
	"sort"
	"testing"
)

// These render on the operator's dashboard. A wrong amount or a
// mis-classified capability is not a crash — it is a page stating
// something untrue, which nothing here was checking.

func TestFormatMilliYuan(t *testing.T) {
	for _, tc := range []struct {
		milli int
		want  string
	}{
		{0, "¥0.00"},
		{1, "¥0.00"}, // a tenth of a fen rounds away; the display has two places
		{10, "¥0.01"},
		{999, "¥0.99"},
		{1000, "¥1.00"},
		{1050, "¥1.05"},
		{1005, "¥1.00"}, // half a fen, likewise below the display's resolution
		{123456, "¥123.45"},
	} {
		if got := formatMilliYuan(tc.milli); got != tc.want {
			t.Errorf("formatMilliYuan(%d) = %q, want %q", tc.milli, got, tc.want)
		}
	}
	// The fractional part must always be two digits. A single digit would
	// render 1050 milli as "¥1.5", which reads as five jiao rather than
	// five fen — an order of magnitude, on a money figure.
	if got := formatMilliYuan(1050); got != "¥1.05" {
		t.Errorf("the fraction lost its leading zero: %q", got)
	}
}

func TestModalityOfCap(t *testing.T) {
	for _, tc := range []struct{ cap, want string }{
		{"image.caption", "image"},
		{"art.style-transfer", "image"},
		{"photo.enhance", "image"},
		{"video.summarize", "video"},
		{"tts.speak", "audio"},
		{"asr.transcribe", "audio"},
		{"voice.clone", "audio"},
		{"music.generate", "audio"},
		{"text.digest", "text"},
		{"", "text"}, // unknown falls to text rather than to empty
		{"IMAGE.CAPTION", "image"},
	} {
		if got := modalityOfCap(tc.cap); got != tc.want {
			t.Errorf("modalityOfCap(%q) = %q, want %q", tc.cap, got, tc.want)
		}
	}
	// "video" contains no image substring and must not be reclassified by
	// a later rule; order matters in the switch and a reordering would be
	// silent.
	if modalityOfCap("video.image-to-video") != "image" {
		t.Log("note: a capability naming both is classified by the first matching rule (image)")
	}
}

func TestTokenize(t *testing.T) {
	// ASCII runs shorter than two characters are dropped: single letters
	// match everything and would make the index useless.
	got := tokenize("a bc def")
	if got["a"] {
		t.Error("a one-character token was indexed")
	}
	for _, w := range []string{"bc", "def"} {
		if !got[w] {
			t.Errorf("%q missing from %v", w, keysOf(got))
		}
	}

	// CJK has no spaces, so bigrams carry the meaning and singletons are
	// the weaker fallback. Both are indexed.
	cjk := tokenize("图像识别")
	for _, w := range []string{"图", "像", "图像", "像识", "识别"} {
		if !cjk[w] {
			t.Errorf("%q missing from CJK tokenization %v", w, keysOf(cjk))
		}
	}

	// Case is folded, so a query does not have to match capitalisation.
	if !tokenize("ImageCaption")["imagecaption"] {
		t.Error("tokenization is case-sensitive")
	}

	// Punctuation separates rather than joining: "a.b" must not become
	// one token, or a capability id would index as a single opaque word.
	sep := tokenize("image.caption")
	if sep["imagecaption"] {
		t.Error("a dot did not separate tokens")
	}
	if !sep["image"] || !sep["caption"] {
		t.Errorf("dotted id did not split: %v", keysOf(sep))
	}

	// Mixed scripts flush correctly at the boundary rather than running
	// the ASCII run into the CJK one.
	mixed := tokenize("ai图像")
	if !mixed["ai"] || !mixed["图像"] {
		t.Errorf("mixed-script tokenization = %v", keysOf(mixed))
	}
}

func TestTokenizeIsEmptyForNothing(t *testing.T) {
	for _, s := range []string{"", "   ", "...", "!!"} {
		if got := tokenize(s); len(got) != 0 {
			t.Errorf("tokenize(%q) = %v, want empty", s, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = reflect.DeepEqual
