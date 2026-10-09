//go:build !unix

package hubid

import "errors"

// ErrLocked is Lock's error when another process holds the lock of the hub
// data directory.
var ErrLocked = errors.New("hubid: another anet-hub process holds the hub data directory")

// DirLock is the lock of a hub data directory.
type DirLock struct{}

// Lock is not available on this platform: anet-hub runs on Unix only, and
// an identity operation that cannot tell whether the hub is running does
// not start.
func Lock(string) (*DirLock, error) {
	return nil, errors.New("hubid: locking the hub data directory needs a Unix system")
}

// Release is a no-op.
func (l *DirLock) Release() error { return nil }
