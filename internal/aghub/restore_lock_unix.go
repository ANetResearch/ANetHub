//go:build unix

package aghub

import (
	"errors"
	"os"
	"syscall"
)

// lockDataDir takes the lock of the hub data directory dir without waiting:
// an exclusive flock(2) on the directory itself, the lock the hub process
// holds for as long as it serves (and anet-hub identity's operations while
// they change the identity). ErrHubRunning when another process holds it.
// The kernel drops it when the process ends, however it ends.
func lockDataDir(dir string) (release func(), err error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrHubRunning
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
