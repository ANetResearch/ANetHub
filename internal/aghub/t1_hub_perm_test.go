package aghub

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHubDatabaseFilesAreOwnerOnlyUnderUmask022(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ents, _ := filepath.Glob(filepath.Join(dir, "hub.db*"))
	if len(ents) == 0 {
		t.Fatal("no database files")
	}
	for _, f := range ents {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %v", filepath.Base(f), fi.Mode().Perm())
		}
	}
}
