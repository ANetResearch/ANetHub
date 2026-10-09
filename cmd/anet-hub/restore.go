package main

// anet-hub restore (core G12; KEL §4.2 H-20, H-23):
//
//	anet-hub restore [--data DIR] <backup file, or the directory that holds it>
//
// The one way to bring a hub's database back from a backup. The hub must be
// stopped. The backup becomes hub.db, and the hub signs no key confirmation
// for an agent until its node sends a newer key history, or signs a request
// with its current key 30 minutes after the hub is back (aghub.Restore). A
// directory is taken for the newest backup in it, by the date in the name
// deploy/hub-db-roll.sh gives a backup (hub-backup-YYYYMMDD.db), which is the
// form an operator finds them in.

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// hubIdentityFile is the hub identity in its data directory (internal/hubid).
// A database restored beside no identity would be served under a new one, and
// its ledger, kept on the hub's own account, would no longer be this hub's.
const hubIdentityFile = "hub_identity.kel"

// backupName is the name deploy/hub-db-roll.sh gives a backup.
var backupName = regexp.MustCompile(`^hub-backup-[0-9]{8}\.db$`)

func runRestore(c *console, data string, args []string) int {
	const use = "anet-hub restore [--data DIR] <backup file, or the directory holding hub-backup-YYYYMMDD.db>"
	fs, dataDir := newSubFlags("restore", data)
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 1 {
		return c.usage(use)
	}
	backup, ok := findBackup(pos[0])
	if !ok {
		return c.say("restore.no_backup", map[string]string{"path": pos[0]})
	}
	dir := *dataDir
	if st, err := os.Stat(filepath.Join(dir, hubIdentityFile)); err != nil || !st.Mode().IsRegular() {
		return c.say("restore.no_identity", map[string]string{"path": dir})
	}
	res, err := aghub.Restore(dir, backup, c.now())
	switch {
	case errors.Is(err, aghub.ErrHubRunning):
		return c.say("restore.hub_running", nil)
	case errors.Is(err, aghub.ErrNotABackup):
		return c.say("restore.bad_backup", map[string]string{"path": backup})
	case errors.Is(err, aghub.ErrBackupTooNew):
		return c.say("restore.backup_too_new", map[string]string{"path": backup})
	case err != nil:
		return c.fail(err)
	}
	return c.say("restore.ok", map[string]string{"path": backup, "n": num(res.Agents)})
}

// findBackup is the backup file arg names: arg itself when it is a file, the
// newest backup in it (by the date in its name) when it is a directory.
func findBackup(arg string) (string, bool) {
	st, err := os.Stat(arg)
	if err != nil {
		return "", false
	}
	if st.Mode().IsRegular() {
		return arg, true
	}
	if !st.IsDir() {
		return "", false
	}
	entries, err := os.ReadDir(arg)
	if err != nil {
		return "", false
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && backupName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", false
	}
	sort.Strings(names) // the same width, so the newest date sorts last
	return filepath.Join(arg, names[len(names)-1]), true
}
