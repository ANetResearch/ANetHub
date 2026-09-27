package aghub

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// putA2ACard stores the A2A AgentCard an agent submitted at registration,
// as the exact bytes it sent, and returns the per-field status /register
// reports.
//
// Nothing is verified or indexed here (A2A-DESIGN §10.3 admission is a
// separate step), and nothing reads this table into a listing, so the
// status says "unverified": the card was kept, and no statement about it
// has been checked. A value that is not a JSON object, or is larger than
// maxA2ACardBytes, is not stored.
func (s *Store) putA2ACard(aid string, raw json.RawMessage) (status, detail string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return CardStatusInvalid, "a2a_card must be a JSON object"
	}
	if len(raw) > maxA2ACardBytes {
		return CardStatusInvalid, fmt.Sprintf("a2a_card is %d bytes, at most %d are accepted",
			len(raw), maxA2ACardBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(
		`INSERT INTO agent_a2a_card(aid, card, stored_at) VALUES(?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET card=excluded.card, stored_at=excluded.stored_at`,
		aid, []byte(raw), nowStamp()); err != nil {
		return CardStatusInvalid, "not stored: " + err.Error()
	}
	return CardStatusUnverified, ""
}
