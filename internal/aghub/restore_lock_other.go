//go:build !unix

package aghub

import "errors"

// lockDataDir is not available here: anet-hub runs on Unix only, and a
// restore that cannot tell whether the hub is running does not start.
func lockDataDir(string) (func(), error) {
	return nil, errors.New("hub: locking the hub data directory needs a Unix system")
}
