package private

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFileCreatesAndNarrows(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	p := filepath.Join(dir, "x.db")
	if err := File(p); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode %v", fi.Mode().Perm())
	}
	q := filepath.Join(dir, "y.db")
	if err := os.WriteFile(q, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := File(q); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(q); fi.Mode().Perm() != 0o600 {
		t.Fatalf("existing file mode %v", fi.Mode().Perm())
	}
}
