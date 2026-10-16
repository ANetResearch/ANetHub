// Package private keeps the hub's database files readable by their owner only.
package private

import (
	"os"
)

// File makes sure path exists and is mode 0600. SQLite gives the -wal and -shm files of a database the
// mode of the database file, so creating the database this way covers all three. A file that already
// exists with wider permissions is narrowed; registrations, the ledger and the audit log are not for
// other local users, whatever the process umask was.
func File(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
