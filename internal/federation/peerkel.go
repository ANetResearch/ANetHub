package federation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

// The federation hub KEL set (KEL H-15, H-16, SI-43).
//
// A peer hub's key history is pinned the first time this hub needs it
// (peerKEL), and from then on it only grows: a peer that rotates serves a
// longer history, which is pinned when it extends the pinned one
// (identity.ExtendsKEL) and its new events are not from the future (R-9).
// Nothing a peer serves afterwards replaces the pin: a strict prefix of it
// (the history as it was before a rotation) is never used, and one that
// contradicts it (a fork) is not taken; the pin stays, the fork is logged
// and kept for the operator (PeerKELForks). Otherwise whoever served the
// shorter history (the peer's old key, or someone in the middle of an
// http:// endpoint) would bring back a key the peer had retired, and every
// object that key signs (a notice, a receipt, a request) would verify again.
//
// The pins are refreshed every peerKELSyncEvery, and at most once per
// peerKELRetry per peer when a use needs a key state past the pin (a peer
// that rotated signs with its new key at once; RefreshPeerKEL).

// peerKELSyncEvery is how often each peer's /hub/identity is read for a
// longer key history (KEL H-15). A code constant, not configuration.
const peerKELSyncEvery = 10 * time.Minute

// PeerKELFork is a peer whose /hub/identity served a key history that
// contradicts the one pinned for it (KEL H-15). The pin is kept.
type PeerKELFork struct {
	AID    string
	Since  time.Time // when it was first seen
	Detail string
}

// PeerKELForks is every peer whose served key history contradicted its pin
// since this process started, by AID. The operator's surface shows it
// (KEL H-15: a warning in the admin status); the pin is unchanged.
func (s *Service) PeerKELForks() []PeerKELFork {
	s.kelFetchesMu.Lock()
	defer s.kelFetchesMu.Unlock()
	out := make([]PeerKELFork, 0, len(s.forks))
	for _, f := range s.forks {
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b PeerKELFork) int {
		switch {
		case a.AID < b.AID:
			return -1
		case a.AID > b.AID:
			return 1
		}
		return 0
	})
	return out
}

// noteFork records that peer aid served a key history that contradicts its
// pin, and logs it the first time.
func (s *Service) noteFork(aid string, err error) {
	s.kelFetchesMu.Lock()
	_, seen := s.forks[aid]
	if !seen {
		s.forks[aid] = PeerKELFork{AID: aid, Since: s.now(), Detail: err.Error()}
	}
	s.kelFetchesMu.Unlock()
	if !seen {
		log.Printf("hub: federation: peer %s serves a key history that contradicts the one pinned for it (%v); "+
			"the pinned one is kept: ask the peer's operator which is theirs", aid, err)
	}
}

// pinPeerKEL pins next, the key history peer aid served (whose blob is
// blob; it replays to aid as a hub's, provenPeerKEL), when nothing is
// pinned for aid, and otherwise extends the pin to it when it extends the
// pin. It returns the key history pinned afterwards:
//
//   - nothing pinned: next, once its events are not from the future (R-9);
//   - next extends the pin: next, once its new events are not from the
//     future; otherwise the pin, with the error;
//   - next is the pin: the pin;
//   - next is a strict prefix of the pin: the pin (SI-43: a prefix is
//     never used);
//   - next contradicts the pin: the pin, and the fork is noted.
//
// The caller holds the peer's fetch lock, so two pins of one peer are not
// interleaved.
func (s *Service) pinPeerKEL(aid string, next []identity.SignedEvent, blob []byte) ([]identity.SignedEvent, error) {
	now := uint64(s.now().UnixMilli())
	old, err := s.pinnedPeerKEL(aid)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := identity.CheckNewEvents(nil, next, now, nil); err != nil {
			return nil, fmt.Errorf("peer %s served a key history with an event from the future; not pinned: %w", aid, err)
		}
		if err := s.storePin(aid, blob); err != nil {
			return nil, err
		}
		return next, nil
	case err != nil:
		// A pin that does not decode was written by nothing this hub
		// runs; it is not replaced from the network either.
		return nil, err
	}
	if err := identity.ExtendsKEL(old, next); err != nil {
		switch {
		case errors.Is(err, identity.ErrKELRollback):
			return old, nil
		case errors.Is(err, identity.ErrKELFork):
			s.noteFork(aid, err)
			return old, nil
		}
		return old, fmt.Errorf("peer %s served a key history that does not extend the pinned one: %w", aid, err)
	}
	if len(next) == len(old) {
		return old, nil
	}
	if err := identity.CheckNewEvents(old, next, now, nil); err != nil {
		return old, fmt.Errorf("peer %s served a longer key history with an event from the future; the pinned one is kept: %w", aid, err)
	}
	if err := s.storePin(aid, blob); err != nil {
		return old, err
	}
	log.Printf("hub: federation: the key history pinned for peer %s now ends at seq %d", aid, next[len(next)-1].Event.Seq)
	return next, nil
}

// storePin writes the pin of peer aid.
func (s *Service) storePin(aid string, blob []byte) error {
	_, err := s.db.Exec(`INSERT INTO fed_peer_kel (aid, kel, fetched_at) VALUES (?,?,?)
	    ON CONFLICT(aid) DO UPDATE SET kel=excluded.kel, fetched_at=excluded.fetched_at`,
		aid, blob, s.now().UnixMilli())
	return err
}

// RefreshPeerKEL fetches peer aid's key history again and extends its pin
// (KEL H-15, H-34), for a use that needs a key state past the pinned one: a
// request, a notice or a receipt the peer signed after it rotated. At most
// one fetch per peer in peerKELRetry is made on behalf of such uses, since
// the key state a request names is anyone's to write; any other call gets
// the pin as it is. It returns the key history pinned afterwards.
func (s *Service) RefreshPeerKEL(peerAID string) ([]identity.SignedEvent, error) {
	p := s.peer(peerAID)
	if p == nil {
		return nil, fmt.Errorf("hub %s is not a peer of this one", peerAID)
	}
	f := s.peerKELFetchOf(p.AID)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.now()
	if !f.asked.IsZero() && now.Sub(f.asked) < peerKELRetry {
		return s.pinnedOrNone(p.AID)
	}
	f.asked = now
	kel, err := s.fetchPeerKEL(p)
	f.ended, f.err = time.Now(), err
	if err != nil {
		if errors.Is(err, errUnprovenPeerKEL) {
			f.refused = f.ended
		}
		if kel != nil {
			return kel, nil // the pin, kept
		}
		if pinned, perr := s.pinnedOrNone(p.AID); perr == nil {
			return pinned, nil
		}
		return nil, err
	}
	f.refused = time.Time{}
	return kel, nil
}

// pinnedOrNone is the pin of aid, or an error that says there is none.
func (s *Service) pinnedOrNone(aid string) ([]identity.SignedEvent, error) {
	kel, err := s.pinnedPeerKEL(aid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no key history is pinned for peer %s yet", aid)
	}
	return kel, err
}

// SyncPeerKELs reads every peer's /hub/identity once and extends its pin,
// or pins it when none is (KEL H-15). A peer that is down, or serves a
// history that does not extend its pin, keeps its pin; the others go on.
// It returns how many pins grew.
func (s *Service) SyncPeerKELs(ctx context.Context) (extended int) {
	for i := range s.cfg.Peers {
		if ctx.Err() != nil {
			return extended
		}
		p := &s.cfg.Peers[i]
		f := s.peerKELFetchOf(p.AID)
		f.mu.Lock()
		before, _ := s.pinnedPeerKEL(p.AID)
		kel, err := s.fetchPeerKEL(p)
		f.ended, f.err = time.Now(), err
		switch {
		case err == nil:
			f.refused = time.Time{}
		case errors.Is(err, errUnprovenPeerKEL):
			f.refused = f.ended
		}
		f.mu.Unlock()
		if err != nil {
			log.Printf("hub: federation: reading the key history of peer %s: %v", p.AID, err)
			continue
		}
		if len(kel) > len(before) {
			extended++
		}
	}
	return extended
}

// RunPeerKELSync runs SyncPeerKELs at once and then every peerKELSyncEvery
// until ctx ends.
func (s *Service) RunPeerKELSync(ctx context.Context) {
	t := time.NewTicker(peerKELSyncEvery)
	defer t.Stop()
	for {
		s.SyncPeerKELs(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// PinnedHubKEL is one peer hub's key history as pinned here: the marshaled
// KEL (identity.MarshalKEL), for GET /hub/kels (KEL H-16).
type PinnedHubKEL struct {
	AID string
	KEL []byte
}

// PinnedHubKELs is the key history pinned for every hub of the peer table,
// in the order of AIDs (KEL H-16). A peer whose key history is not pinned
// yet is left out.
func (s *Service) PinnedHubKELs() ([]PinnedHubKEL, error) {
	rows, err := s.db.Query(`SELECT aid, kel FROM fed_peer_kel ORDER BY aid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PinnedHubKEL
	for rows.Next() {
		var k PinnedHubKEL
		if err := rows.Scan(&k.AID, &k.KEL); err != nil {
			return nil, err
		}
		if s.peer(k.AID) == nil {
			continue // a peer no longer in the table
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
