package aghub

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
)

// Peer-to-peer rendezvous: the hub as a directory of dialable addresses.
//
// The p2p transport can carry traffic between two machines, and could not
// find a peer on one. Discovery was a shared filesystem directory, which
// two hosts do not have — so a transport built to avoid the hub could
// only be used by nodes sitting on the same box, which is the one case
// that does not need it.
//
// The hub already knows who exists and holds their key histories, so it
// is the smallest thing that can answer "where do I dial this AID". What
// it gains is a list of addresses, which is a real cost and the reason
// publishing is opt-in and separately signed: a node that wants the hub
// for delivery and not as a directory publishes nothing and is not
// listed. Nothing here is inferred from a connection — the hub cannot
// record an address an agent did not sign.
//
// This does not make the p2p path hub-free. It makes it hub-free *after
// introduction*, which is what the transport was for: the payload, the
// evidence and the result never cross the hub, and the hub learns that
// two peers looked each other up and nothing about what they then did.

// MaxP2PAddr bounds a published address. Long enough for a hostname and
// port or a socket path, short enough that the directory cannot be used
// as storage.
const MaxP2PAddr = 256

// SetP2PAddr publishes where an agent can be dialled directly.
//
// An empty address withdraws the entry, which is how a node stops being
// listed without deregistering: the two are different decisions and a
// node that wants delivery but not direct connections should be able to
// say so.
func (s *Store) SetP2PAddr(aid, addr string) error {
	addr = strings.TrimSpace(addr)
	if len(addr) > MaxP2PAddr {
		return fmt.Errorf("address is longer than %d bytes", MaxP2PAddr)
	}
	if addr == "" {
		_, err := s.db.Exec(`DELETE FROM p2p_addr WHERE aid=?`, aid)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO p2p_addr(aid, addr, at) VALUES(?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET addr=excluded.addr, at=excluded.at`,
		aid, addr, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// P2PAddr reads a published address back. The second result distinguishes
// "this agent published nothing" from "this agent published an empty
// address", which the caller must not merge: one means fall back to the
// hub, the other cannot happen because an empty publish withdraws.
func (s *Store) P2PAddr(aid string) (addr, at string, ok bool) {
	err := s.db.QueryRow(`SELECT addr, at FROM p2p_addr WHERE aid=?`, aid).Scan(&addr, &at)
	if err != nil {
		return "", "", false
	}
	return addr, at, true
}

// P2PDirectory lists every published address.
//
// Published because the cost of this feature should be visible to the
// people paying it: an operator, and an agent deciding whether to list
// itself, can both see exactly what the hub now knows.
func (s *Store) P2PDirectory() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT aid, addr FROM p2p_addr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var aid, addr string
		if err := rows.Scan(&aid, &addr); err != nil {
			return nil, err
		}
		out[aid] = addr
	}
	return out, rows.Err()
}

// hP2PPublish records where an agent says it can be reached.
//
// Signed with the same challenge every other self-description uses: an
// address is a statement about oneself, and the hub must not be able to
// list an agent that did not ask to be listed.
func (s *Server) hP2PPublish(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	var req struct {
		Addr        string `json:"addr"`
		TS          uint64 `json:"ts"`
		KeyStateSeq uint64 `json:"key_state_seq"`
		Sig         string `json:"sig"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	kelBytes, err := s.store.AgentKEL(aid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := verifyChallenge(kel, relayauth.ActionProfile, aid, req.TS, req.KeyStateSeq, req.Sig); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	if err := s.store.SetP2PAddr(aid, req.Addr); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	status := "published"
	if strings.TrimSpace(req.Addr) == "" {
		status = "withdrawn"
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": aid, "status": status, "addr": req.Addr})
}

// hP2PLookup answers "where do I dial this AID".
//
// 404 rather than an empty address when nothing was published, so a
// caller cannot mistake "not listed" for "listed at nowhere". The two
// lead to different behaviour: fall back to the hub, or fail.
func (s *Server) hP2PLookup(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	addr, at, ok := s.store.P2PAddr(aid)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "this agent has not published a direct address"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"aid": aid, "addr": addr, "at": at})
}

// hP2PDirectory lists what the hub has been told.
func (s *Server) hP2PDirectory(w http.ResponseWriter, _ *http.Request) {
	dir, err := s.store.P2PDirectory()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": dir, "count": len(dir)})
}

// MoveBalanceWithoutEntryForTest reproduces the shape the settlement path
// left before it wrote ledger entries: a balance that moved with nothing
// behind it. Tests only.
func (s *Store) MoveBalanceWithoutEntryForTest(aid string, delta int64) error {
	_, err := s.db.Exec(
		`INSERT INTO credit_balance(aid, credits) VALUES(?,?)
		 ON CONFLICT(aid) DO UPDATE SET credits = credits + ?`, aid, delta, delta)
	return err
}
