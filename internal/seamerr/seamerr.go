// Package seamerr holds the sentinel errors that cross the seam between
// the hub kernel (internal/aghub) and the federation module
// (internal/federation).
//
// The federation module returns these from the hooks the kernel calls
// (the forwarder and the federated key lookup), and the kernel tests for
// them to choose an HTTP status. They lived in internal/federation, so the
// kernel referenced that package from code every build links, and a hub
// built with -tags no_federation still carried federation symbols
// (federation.ErrMailboxFull, federation.ErrNoKeys). Found by the symbol
// count check CI runs for each subtractive tag (A2A-DESIGN §16).
//
// The kernel tests for these values; federation.ErrMailboxFull and
// federation.ErrNoKeys match them under errors.Is (see seamError in
// internal/federation), so neither side has to refer to the other's
// variables in code a no_federation build links.
package seamerr

import "errors"

// ErrMailboxFull: the destination's undelivered quota is exhausted (the
// peer hub answered 507). The kernel answers 507 too.
var ErrMailboxFull = errors.New("federation: destination mailbox full")

// ErrNoKeys: no key set is held for the AID, locally or at any peer that
// was asked. The kernel answers 404.
var ErrNoKeys = errors.New("federation: no key set for this AID")
