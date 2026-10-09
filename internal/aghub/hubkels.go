package aghub

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// GET /hub/kels (KEL H-16, core §2.12.2): the key history of this hub and
// of every federation peer hub it has pinned, so a node checks what any of
// them signed (a notice, a receipt) against what its own hub holds. The
// peers' are the federation module's pins, which only grow (KEL H-15). It is
// public and changes rarely: a node reads it every 10 minutes (HubKELSync),
// and Cache-Control lets a proxy keep it 5 minutes.

// HubKEL is one hub's key history as /hub/kels serves it: the marshaled KEL.
type HubKEL struct {
	AID string
	KEL []byte
}

// HubKELsView is the GET /hub/kels response.
type HubKELsView struct {
	Hubs []HubKELEntry `json:"hubs"`
}

// HubKELEntry is one hub of it; the KEL is base64url (core CORE-E5).
type HubKELEntry struct {
	AID string `json:"aid"`
	KEL string `json:"kel"`
}

// errNoHubIdentity is a hub serving without its identity, which main never
// starts.
var errNoHubIdentity = errors.New("this hub holds no identity")

// hubKELsMaxAge is the Cache-Control max-age of /hub/kels, in seconds.
const hubKELsMaxAge = "300"

// SetHubKELSet installs the federation hook that lists the peer hubs' key
// histories this hub has pinned. Without it (a build without federation, a
// hub with no peers) /hub/kels serves this hub's own only.
func (s *Server) SetHubKELSet(f func() ([]HubKEL, error)) { s.hubKELSet = f }

// hHubKELs serves GET /hub/kels: this hub's own key history first, then the
// pinned peers' in the order of their AIDs.
func (s *Server) hHubKELs(w http.ResponseWriter, _ *http.Request) {
	own := s.store.hubKey
	if own == nil {
		wire3.Internal(w, errNoHubIdentity)
		return
	}
	ownKEL, err := identity.MarshalKEL(own.KEL())
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	out := HubKELsView{Hubs: []HubKELEntry{{AID: own.AID(), KEL: wire3.EncodeB64URL(ownKEL)}}}
	if s.hubKELSet != nil {
		peers, err := s.hubKELSet()
		if err != nil {
			wire3.Internal(w, err)
			return
		}
		slices.SortFunc(peers, func(a, b HubKEL) int { return strings.Compare(a.AID, b.AID) })
		for _, p := range peers {
			if p.AID == own.AID() {
				continue
			}
			out.Hubs = append(out.Hubs, HubKELEntry{AID: p.AID, KEL: wire3.EncodeB64URL(p.KEL)})
		}
	}
	w.Header().Set("Cache-Control", "max-age="+hubKELsMaxAge)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, out)
}
