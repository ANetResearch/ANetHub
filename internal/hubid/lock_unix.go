//go:build unix

package hubid

import (
	"errors"
	"os"
	"syscall"
)

// ErrLocked is Lock's error when another process holds the lock of the hub
// data directory: a hub serving from it, or an identity operation on it.
var ErrLocked = errors.New("hubid: another anet-hub process holds the hub data directory")

// DirLock is the lock of a hub data directory: an exclusive flock(2) on the
// directory itself, so taking it writes nothing into the directory. The
// kernel releases it when the process ends, however it ends.
type DirLock struct{ f *os.File }

// Lock takes the lock of the hub data directory dir without waiting
// (KEL H-32). The hub holds it for as long as it serves; `anet-hub identity
// setup-recovery` and `rotate` hold it while they change the hub identity,
// and refuse (hub_running) when they cannot have it. A directory that does
// not exist is os.ErrNotExist; one whose lock another process holds is
// ErrLocked.
func Lock(dir string) (*DirLock, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &DirLock{f: f}, nil
}

// Release gives the lock up. Releasing a nil lock is a no-op.
func (l *DirLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close() // closing the descriptor drops the flock
	l.f = nil
	return err
}
