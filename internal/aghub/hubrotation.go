package aghub

import (
	"fmt"

	"github.com/ANetResearch/ANetCore/identity"
)

// After the hub identity rotated (KEL H-35).
//
// `anet-hub identity rotate` runs while the hub is stopped (H-32), and the
// rotation takes effect at the next start. The notices cached before it were
// signed with the key the hub has rotated away from: after an emergency
// rotation every node that has the hub's new key history refuses them, and
// after a planned one they stop being good an hour after the rotation. So
// before the hub takes its first request, every cached notice not signed
// under the hub's current key state is dropped, with the directory entry
// that carried it; the next request, or the refresher, signs a new one with
// the new key. A hub whose key did not change drops nothing.

// ForgetNoticesOfAnotherKey drops every cached witness notice that this
// hub's identity (SetHubKey) did not sign under its current key state, and
// recomputes the directory entry of each AID it dropped one for, in one
// transaction. It returns how many it dropped. The hub process calls it
// once, before it serves.
func (s *Store) ForgetNoticesOfAnotherKey() (int, error) {
	if s.hubKey == nil {
		return 0, nil
	}
	seq, err := identity.SeqOf(identity.SnapshotOf(s.hubKey))
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT aid, blob FROM notice_cache ORDER BY aid`)
	if err != nil {
		return 0, err
	}
	var stale []string
	for rows.Next() {
		var aid string
		var blob []byte
		if err := rows.Scan(&aid, &blob); err != nil {
			rows.Close()
			return 0, err
		}
		if _, env, derr := identity.DecodeNotice(blob); derr != nil || env.SignerAID != s.hubAID || env.KeyStateSeq != seq {
			stale = append(stale, aid)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, aid := range stale {
		if err := forgetNoticeTx(tx, aid); err != nil {
			return 0, err
		}
		if err := s.refreshDirTx(tx, aid); err != nil {
			return 0, fmt.Errorf("hub: the directory entry of %s after the hub's rotation: %w", aid, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(stale), nil
}
