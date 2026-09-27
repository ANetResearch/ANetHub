package aghub

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/a2acard"
	"github.com/ANetResearch/ANetCore/identity"
)

// The A2A registry (A2A-DESIGN §10.5).
//
//	GET /a2a/v1/agents?skill=&tag=&q=&cursor=&limit=   verified cards, one entry per agent
//	GET /a2a/v1/agents/{aid}/card                       one card, as the agent's bytes
//	GET /agents/{aid}/jwks.json                         the jku of those cards, from the KEL
//
// An entry wraps the agent's card in what the hub states about it: that
// the card verified and when, where the agent lives, whether it is still
// collecting its mail, and the reviews stored here. The card inside is the
// agent's own signed statement, as the bytes it sent; the wrapper is the
// hub's, and a consumer that needs more than the hub's word verifies the
// card against the agent's KEL itself.
//
// Agents registered here appear with a card that passed admission
// (a2acard.go) while AgentView.Browsable lists them. Every query joins the
// agent table, so a card whose agent row an operator deleted is not
// served. On a hub whose discovery federation is on, the listed A2A cards
// learned from peers (/fed/v2/cards, fed_a2acard.go) appear too, with the
// home hub they live on, unless the agent is registered here: an agent
// registered here speaks for itself.
//
// The paths sit outside /relay/, so wireContract does not ask external
// A2A clients for X-ANet-Wire.

// A2AAgentEntry is one entry of GET /a2a/v1/agents. Card is the agent's
// card as it sent it; the other members are the hub's statements.
type A2AAgentEntry struct {
	AID  string          `json:"aid"`
	Card json.RawMessage `json:"card"`
	// CardVerification is always CardVerificationOK: nothing else is
	// listed.
	CardVerification string `json:"cardVerification"`
	// VerifiedAt is when the card last verified against the agent's KEL
	// (RFC 3339): at admission, or at the agent's latest registration.
	VerifiedAt string `json:"verifiedAt"`
	// HomeHub is the hub the agent is registered at: the one answering
	// (its configured public base URL, else the request's origin), or for
	// a card learned from a peer the hub its card's relay interface names
	// (else the peer's statement of it).
	HomeHub string `json:"homeHub"`
	// LastSeen and Quiet are the liveness of AgentView (liveness.go).
	LastSeen    string  `json:"lastSeen,omitempty"`
	Quiet       bool    `json:"quiet"`
	ReviewCount int     `json:"reviewCount"`
	AvgRating   float64 `json:"avgRating"`
}

// A2AAgentList is the GET /a2a/v1/agents response. NextCursor is set when
// more entries follow; pass it back as cursor.
type A2AAgentList struct {
	Agents     []A2AAgentEntry `json:"agents"`
	NextCursor string          `json:"nextCursor,omitempty"`
}

// Registry page size: the default, and the most one request may ask for.
const (
	defaultRegistryLimit = 50
	maxRegistryLimit     = 200
)

// maxRegistryQBytes bounds q. Every q request is a substring search
// through each listed card's search text (up to a card's size), which
// costs up to the product of the two lengths per card; a search box needs
// nowhere near this.
const maxRegistryQBytes = 256

// registryCacheSeconds is the Cache-Control max-age of a card and a JWKS.
// Five minutes: a card changes when its agent re-registers, and a JWKS
// when the agent rotates, and a verifier that holds a stale copy fails
// closed (the card's kid is missing from it) rather than open.
const registryCacheSeconds = 300

// RegistryQuery selects registry entries. Skill and Tag match exactly;
// Q is a case-insensitive substring of the card's name, description or a
// skill name. After is the AID the previous page ended with. Federated
// includes the A2A cards learned from peers.
type RegistryQuery struct {
	Skill, Tag, Q string
	After         string
	Limit         int
	Federated     bool
}

// A2ARegistry returns up to q.Limit entries in AID order after q.After,
// and whether more follow. HomeHub is set on entries learned from peers
// and left empty on local ones for the caller, which knows the origin it
// answers under.
func (s *Store) A2ARegistry(q RegistryQuery) ([]A2AAgentEntry, bool, error) {
	if q.Limit < 1 {
		q.Limit = defaultRegistryLimit
	}
	var args []any
	// arm is one source of entries with the filters applied against its
	// own indexes: the local tables, or the federated ones.
	arm := func(sel, from, aidCol, skillTable, tagTable, searchCol string) string {
		query := sel + ` FROM ` + from + ` AND ` + aidCol + ` > ?`
		args = append(args, q.After)
		if q.Skill != "" {
			query += ` AND EXISTS (SELECT 1 FROM ` + skillTable + ` s WHERE s.aid = ` + aidCol + ` AND s.skill_id = ?)`
			args = append(args, q.Skill)
		}
		if q.Tag != "" {
			query += ` AND EXISTS (SELECT 1 FROM ` + tagTable + ` t WHERE t.aid = ` + aidCol + ` AND t.tag = ?)`
			args = append(args, q.Tag)
		}
		if q.Q != "" {
			// instr rather than LIKE: no pattern language to escape.
			// search is lowercased at admission with the same function
			// as here.
			query += ` AND instr(` + searchCol + `, ?) > 0`
			args = append(args, strings.ToLower(q.Q))
		}
		return query
	}
	union := arm(`SELECT a.aid AS aid, c.card AS card, c.verified_at AS verified_at,
	                     a.registered_at AS registered_at, a.last_seen_at AS last_seen_at, '' AS home`,
		`agent_a2a_card c JOIN agent a ON a.aid = c.aid WHERE c.verified_at IS NOT NULL`,
		"a.aid", "agent_skill", "agent_tag", "c.search")
	if q.Federated {
		union += ` UNION ALL ` + arm(`SELECT f.aid, f.card, f.verified_at, '', NULL, f.home`,
			`fed_a2a_card f WHERE f.verified_at IS NOT NULL
			   AND NOT EXISTS (SELECT 1 FROM agent a WHERE a.aid = f.aid)`,
			"f.aid", "fed_a2a_skill", "fed_a2a_tag", "f.search")
	}
	query := `SELECT u.aid, u.card, u.verified_at, u.registered_at, u.last_seen_at, u.home,
	                 (SELECT COUNT(*) FROM review r WHERE r.subject_aid = u.aid),
	                 (SELECT COALESCE(AVG(r.rating),0) FROM review r WHERE r.subject_aid = u.aid)
	            FROM (` + union + `) u ORDER BY u.aid`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	now := time.Now()
	out := []A2AAgentEntry{}
	for rows.Next() {
		var e A2AAgentEntry
		var card []byte
		var registeredAt string
		var lastSeen sql.NullString
		if err := rows.Scan(&e.AID, &card, &e.VerifiedAt, &registeredAt, &lastSeen, &e.HomeHub,
			&e.ReviewCount, &e.AvgRating); err != nil {
			return nil, false, err
		}
		live := livenessFrom(lastSeen.String, now)
		// Browsable is applied here, row by row, rather than restated in
		// SQL: it is the one rule every listing uses (aghub.go). The
		// rows stream in AID order, so filtering does not cost a page its
		// size.
		if !(AgentView{LastSeen: live.LastSeen, RegisteredAt: registeredAt}).Browsable() {
			continue
		}
		if len(out) == q.Limit {
			return out, true, nil
		}
		e.Card = json.RawMessage(card)
		e.CardVerification = CardVerificationOK
		e.LastSeen, e.Quiet = live.LastSeen, live.Quiet
		out = append(out, e)
	}
	return out, false, rows.Err()
}

// VerifiedA2ACard returns the stored bytes of aid's card, or nil when aid
// is not registered here or has no card that verified. With federated,
// an agent not registered here is answered from the listed A2A card
// learned from a peer, as A2ARegistry lists it.
func (s *Store) VerifiedA2ACard(aid string, federated bool) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRow(
		`SELECT c.card FROM agent_a2a_card c JOIN agent a ON a.aid = c.aid
		  WHERE c.aid = ? AND c.verified_at IS NOT NULL`, aid).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) && federated {
		err = s.db.QueryRow(
			`SELECT f.card FROM fed_a2a_card f
			  WHERE f.aid = ? AND f.verified_at IS NOT NULL
			    AND NOT EXISTS (SELECT 1 FROM agent a WHERE a.aid = f.aid)`, aid).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

// hA2AAgents serves GET /a2a/v1/agents.
//
// skill and tag are what a daemon asks with: it matches free text against
// the returned cards itself, so what an operator searches for does not
// reach the hub. q is for the hub's web UI. As on /agents?cap=, a
// parameter that is present but empty is refused rather than read as "no
// filter", which would answer a question the caller did not ask.
func (s *Server) hA2AAgents(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var q RegistryQuery
	for _, p := range []struct {
		name string
		dst  *string
	}{{"skill", &q.Skill}, {"tag", &q.Tag}} {
		if !query.Has(p.name) {
			continue
		}
		*p.dst = strings.TrimSpace(query.Get(p.name))
		if *p.dst == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": p.name + " must not be empty; omit the parameter to list every agent"})
			return
		}
	}
	q.Q = strings.TrimSpace(query.Get("q"))
	if len(q.Q) > maxRegistryQBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "q is longer than " + strconv.Itoa(maxRegistryQBytes) + " bytes"})
		return
	}
	q.Limit = defaultRegistryLimit
	if query.Has("limit") {
		n, err := strconv.Atoi(query.Get("limit"))
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		q.Limit = min(n, maxRegistryLimit)
	}
	if c := query.Get("cursor"); c != "" {
		after, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(after) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cursor is not one this hub issued"})
			return
		}
		q.After = string(after)
	}
	// Peer-learned cards are listed where the federated directory is,
	// that is when the discovery federation wired it (SetFederatedDirectory).
	q.Federated = s.federated != nil
	entries, more, err := s.store.A2ARegistry(q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	home := s.origin(r)
	for i := range entries {
		if entries[i].HomeHub == "" {
			entries[i].HomeHub = home
		}
	}
	out := A2AAgentList{Agents: entries}
	if more {
		// Opaque to the caller: the AID the page ended with.
		out.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(entries[len(entries)-1].AID))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// No HTML escaping, so each card is embedded as close to the bytes
	// the agent sent as JSON allows (insignificant whitespace is dropped).
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}

// hA2ACard serves GET /a2a/v1/agents/{aid}/card: the card as the agent
// sent it, byte for byte, which is what its signature covers.
func (s *Server) hA2ACard(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	raw, err := s.store.VerifiedA2ACard(aid, s.federated != nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no verified A2A card for " + aid + " on this hub"})
		return
	}
	serveCacheable(w, r, "application/json", raw)
}

// hJWKS serves GET /agents/{aid}/jwks.json, the jku named in the
// signature header of aid's A2A card (A2A-DESIGN §10.3).
//
// It is derived from the KEL on every request (a2acard.JWKS) and lists
// exactly the key states a2acard.Verify accepts: those after the last
// rotation, none after a deactivation. It is this hub's statement about
// the KEL, weaker than the KEL itself, which /agents/{aid}/kel serves.
func (s *Server) hJWKS(w http.ResponseWriter, r *http.Request) {
	aid := r.PathValue("aid")
	_, kelBytes, registered, err := s.store.LocalKeys(aid)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !registered {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": aid + " is not registered here"})
		return
	}
	kel, err := identity.UnmarshalKEL(kelBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stored KEL undecodable: " + err.Error()})
		return
	}
	jwks, err := a2acard.JWKS(kel)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	serveCacheable(w, r, "application/jwk-set+json", jwks)
}

// serveCacheable writes body with a strong ETag over its bytes and a
// five-minute max-age, and answers 304 when If-None-Match names that ETag.
func serveCacheable(w http.ResponseWriter, r *http.Request, contentType string, body []byte) {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(registryCacheSeconds))
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// etagMatches applies If-None-Match's weak comparison (RFC 9110 §13.1.2):
// "*" matches, and a W/ prefix on a listed tag is ignored.
func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimSpace(part)
		if p == "*" || strings.TrimPrefix(p, "W/") == etag {
			return true
		}
	}
	return false
}
