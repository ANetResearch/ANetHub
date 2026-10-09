//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A restore needs the hub stopped (KEL H-23): while another process holds
// the data directory's lock, as the hub does while it serves, anet-hub
// restore refuses and changes nothing.
func TestRestoreRefusesWhileTheHubRuns(t *testing.T) {
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dir := hubDir(t)
			a, _ := newAID(t)
			registerIn(t, dir, a)
			good := filepath.Join(t.TempDir(), "hub-backup-20261004.db")
			backupInto(t, dir, good)
			f, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal(err)
			}
			before := dirFiles(t, dir)
			expectErr(t, cli(t, lang, "-data", dir, "restore", good), 1, sentenceOf(lang, "restore.hub_running", nil))
			if !sameFiles(before, dirFiles(t, dir)) {
				t.Error("the data directory changed")
			}
		})
	}
}
