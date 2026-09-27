package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// The A2A card stream: GET /fed/v2/cards (A2A-DESIGN §10.6).
//
// /fed/v1/cards carries ADP cards; this stream carries the agents' signed
// A2A AgentCards that passed admission on their home hub (§10.3), each
// with the KEL it verifies against and the agent's encryption key set
// (§3.9). It is a separate stream with its own cursor rather than a new
// entry shape on v1, because a v1 peer admits every entry as an ADP card
// and would refuse (and skip past) entries it cannot read. v1 is served
// and pulled alongside until every peer has moved to v2.
//
// Each entry names its format, and the pulling hub dispatches admission on
// it. The format is the publishing hub's statement about the entry, not
// part of anything an agent signed, so an agent cannot make its card read
// as a withdrawal (the problem parseWithdrawal has to solve on v1). An
// entry in a format this build does not know is skipped and the cursor
// moves past it: a peer that starts publishing a new format must not
// stall the stream of a hub that has not been upgraded to read it.

// Formats of a /fed/v2/cards entry.
const (
	// FormatA2ACard: card is the agent's signed A2A AgentCard as the bytes
	// it registered, kel its KEL, keys its encryption key set (optional).
	FormatA2ACard = "a2a-card/1"
	// FormatWithdrawal: the home hub has stopped publishing the agent's
	// card (the agent left, narrowed its visibility, or its card stopped
	// verifying). card is {"action":"withdraw","agent_id":...,"reason":...,
	// "at":...}; there is no kel or keys. An extension of §10.6, which
	// names only a2a-card/1: without it a peer past the card's cursor
	// keeps publishing an agent its home hub no longer publishes.
	FormatWithdrawal = "withdrawal/1"
)

// FedA2ACardView is one entry of the A2A card stream as the kernel hands
// it over and receives it. KEL is identity.MarshalKEL; Keys is the
// seal.SignedEncKeySet encoding, or nil.
type FedA2ACardView struct {
	Format string
	Card   []byte
	KEL    []byte
	Keys   []byte
	Home   string
	FedSeq int64
}

// FedA2ACardEntry is one /fed/v2/cards entry on the wire.
type FedA2ACardEntry struct {
	Format string          `json:"format"`
	Card   json.RawMessage `json:"card"`
	KEL    string          `json:"kel,omitempty"`  // base64 (std) of identity.MarshalKEL
	Keys   string          `json:"keys,omitempty"` // base64 (std) of the seal.SignedEncKeySet encoding
	Home   string          `json:"home"`
	FedSeq int64           `json:"fed_seq"`
}

// FedA2ACardPage is the GET /fed/v2/cards response. Cursor is the fed_seq
// to ask after next.
type FedA2ACardPage struct {
	Cursor int64             `json:"cursor"`
	Cards  []FedA2ACardEntry `json:"cards"`
}

// A2A card stream paging. An A2A card may be 64 KiB and a KEL as large, so
// a page is bounded by bytes as well as by entries: a page the pulling hub
// cannot read in full is a page it asks for again, for ever.
const (
	a2aCardsPageEntries = 100
	a2aCardsPageBytes   = 4 << 20
	a2aCardsReadLimit   = 16 << 20
)

// hA2ACards serves GET /fed/v2/cards?cursor=<c>.
//
// Unauthenticated for the reason /fed/v1/cards is: every card is an
// agent's own signed statement, published by an agent that opted in.
func (s *Service) hA2ACards(w http.ResponseWriter, r *http.Request) {
	if !s.DiscoveryEnabled() || s.dir == nil {
		fedErr(w, http.StatusForbidden, "POLICY_REFUSED", "discovery federation disabled")
		return
	}
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	cards, next, err := s.dir.A2ACardsSince(cursor, a2aCardsPageEntries, s.cfg.Home)
	if err != nil {
		fedErr(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	page := FedA2ACardPage{Cursor: next, Cards: make([]FedA2ACardEntry, 0, len(cards))}
	size := 0
	for _, c := range cards {
		e := FedA2ACardEntry{Format: c.Format, Card: json.RawMessage(c.Card), Home: c.Home, FedSeq: c.FedSeq}
		if len(c.KEL) > 0 {
			e.KEL = base64.StdEncoding.EncodeToString(c.KEL)
		}
		if len(c.Keys) > 0 {
			e.Keys = base64.StdEncoding.EncodeToString(c.Keys)
		}
		n := len(e.Card) + len(e.KEL) + len(e.Keys) + len(e.Home) + 96
		if len(page.Cards) > 0 && size+n > a2aCardsPageBytes {
			// The rest is the next page; the cursor stops at the last
			// entry served.
			page.Cursor = page.Cards[len(page.Cards)-1].FedSeq
			break
		}
		size += n
		page.Cards = append(page.Cards, e)
	}
	w.Header().Set("Content-Type", "application/json")
	// No HTML escaping, so each card goes out as close to the bytes its
	// agent signed as JSON allows (the signature covers a canonical form,
	// which escaping does not change, but a reader comparing bytes would
	// see a difference).
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(page)
}

// syncA2ACards pulls each peer's A2A card stream forward by one page, with
// the same per-peer, stall-on-refused-for-now rules as the v1 stream in
// SyncOnce. full re-reads from the beginning.
//
// A peer that answers 404 has not been upgraded to serve the stream. That
// is not a refusal and nothing is counted; its v1 stream still carries its
// ADP cards.
func (s *Service) syncA2ACards(ctx context.Context, full bool) (admitted, refused int) {
	for i := range s.cfg.Peers {
		p := &s.cfg.Peers[i]
		cursor := s.peerA2ACursor(p.AID)
		if full {
			cursor = 0
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("%s/fed/v2/cards?cursor=%d", strings.TrimSuffix(p.Endpoint, "/"), cursor), nil)
		if err != nil {
			continue
		}
		resp, err := s.http.Do(req)
		if err != nil {
			log.Printf("hub: federation A2A card sync %s: %v", p.AID, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			resp.Body.Close()
			s.noteA2AStream(p.AID, resp.StatusCode, strings.TrimSpace(string(detail)))
			continue
		}
		s.noteA2AStream(p.AID, http.StatusOK, "")
		var page FedA2ACardPage
		derr := json.NewDecoder(io.LimitReader(resp.Body, a2aCardsReadLimit)).Decode(&page)
		resp.Body.Close()
		if derr != nil {
			log.Printf("hub: federation A2A card sync %s: %v", p.AID, derr)
			continue
		}
		var stall int64
		for _, e := range page.Cards {
			if e.Format != FormatA2ACard && e.Format != FormatWithdrawal {
				// Skipped, not refused: the cursor moves past it.
				continue
			}
			view := FedA2ACardView{Format: e.Format, Card: e.Card, Home: e.Home, FedSeq: e.FedSeq}
			if !hubHomeURL(view.Home) {
				// As on v1, the peer's own endpoint is the honest
				// fallback for a home it does not name; also for one
				// that is not a hub URL, since the home is served as
				// homeHub wherever the card has no relay interface.
				view.Home = p.Endpoint
			}
			if e.KEL != "" {
				kel, kerr := base64.StdEncoding.DecodeString(e.KEL)
				if kerr != nil {
					log.Printf("hub: federation A2A card from %s refused: kel not base64", p.AID)
					refused++
					continue
				}
				view.KEL = kel
			}
			// The key set is advisory, as on v1: one that does not decode
			// is passed as absent and the card is still admitted.
			if e.Keys != "" {
				if k, kerr := base64.StdEncoding.DecodeString(e.Keys); kerr == nil {
					view.Keys = k
				}
			}
			if err := s.dir.AdmitFedA2ACard(p.AID, view); err != nil {
				log.Printf("hub: federation A2A card from %s refused: %v", p.AID, err)
				refused++
				if errors.Is(err, ErrRefusedForNow) {
					stall = e.FedSeq
					break
				}
				continue
			}
			admitted++
		}
		// On a full pass cursor is 0 here, so a pass that admitted
		// everything leaves the cursor where the peer says the page ends,
		// and one that stalled moves it back to the stalled entry.
		switch {
		case stall > cursor:
			s.setPeerA2ACursor(p.AID, stall-1)
		case stall > 0:
			// An entry at or before the cursor was refused for now; the
			// cursor stays rather than passing it.
		case page.Cursor > cursor:
			s.setPeerA2ACursor(p.AID, page.Cursor)
		}
	}
	return admitted, refused
}

// maxHomeURL bounds the home an entry may name.
const maxHomeURL = 2048

// hubHomeURL reports whether an entry's home is usable as a hub URL: an
// absolute http(s) URL with a host, no credentials, of bounded length.
func hubHomeURL(s string) bool {
	if s == "" || len(s) > maxHomeURL {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

// noteA2AStream logs a peer's answer to /fed/v2/cards when it differs
// from the previous one, so that a peer not yet upgraded (404) or with
// discovery off (403) is reported once rather than every round.
func (s *Service) noteA2AStream(peerAID string, status int, detail string) {
	if s.a2aStreamStatus[peerAID] == status {
		return
	}
	s.a2aStreamStatus[peerAID] = status
	switch status {
	case http.StatusOK:
		log.Printf("hub: federation peer %s serves /fed/v2/cards", peerAID)
	case http.StatusNotFound:
		log.Printf("hub: federation peer %s serves no /fed/v2/cards yet; its ADP cards still arrive on v1", peerAID)
	default:
		log.Printf("hub: federation A2A card sync %s: HTTP %d: %s", peerAID, status, detail)
	}
}

func (s *Service) peerA2ACursor(aid string) int64 {
	var c int64
	_ = s.db.QueryRow(`SELECT cursor FROM fed_cursor_v2 WHERE peer_aid=?`, aid).Scan(&c)
	return c
}

func (s *Service) setPeerA2ACursor(aid string, c int64) {
	_, _ = s.db.Exec(
		`INSERT INTO fed_cursor_v2(peer_aid, cursor) VALUES(?,?)
		 ON CONFLICT(peer_aid) DO UPDATE SET cursor=excluded.cursor`, aid, c)
}
