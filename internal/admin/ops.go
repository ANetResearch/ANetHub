package admin

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/ANetResearch/ANetCore/regpow"
	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// The operator views added for the console's admission, delivery and
// federation pages. All of them read hub.db counters and settings; none
// reads a message, a dack, a ledger row or a per-agent mailbox figure
// (PAY-O5, SSR-H19, DLV-H-6).

// AdmissionState is the hub's admission mode, its sign-up window and the
// accounts by how they came in.
type AdmissionState struct {
	Mode   string `json:"mode"`
	Window *struct {
		OpensAt  string `json:"opens_at"`
		ClosesAt string `json:"closes_at"`
		Max      int    `json:"max"`
		Used     int    `json:"used"`
		Label    string `json:"label,omitempty"`
		Active   bool   `json:"active"`
	} `json:"window,omitempty"`
	AdmissionList int            `json:"admission_list"`
	Accounts      map[string]int `json:"accounts_by_route"`
	Trial         map[string]int `json:"accounts_by_trial"`
	OnProbation   int            `json:"on_probation"`
	QuotaRaised   []QuotaRaise   `json:"quota_raised"`
	Rules         AdmissionRules `json:"rules"`
}

// QuotaRaise is one recipient whose first-contact quota the operator raised.
type QuotaRaise struct {
	AID                 string `json:"aid"`
	FirstContactsPerMin int64  `json:"first_contacts_per_min"`
	NonContactMsgs      int64  `json:"non_contact_msgs"`
	NonContactBytes     int64  `json:"non_contact_bytes"`
}

// AdmissionRules are the fixed constants of the hub, stated beside the live
// figures so that the console never holds a copy of them.
type AdmissionRules struct {
	PowBits                int                  `json:"pow_bits"`
	ProbationHours         int                  `json:"probation_hours"`
	TrialCredits           int64                `json:"trial_credits"`
	InactiveDays           int                  `json:"inactive_days"`
	TrialBudgetHub         int                  `json:"trial_budget_hub_per_day"`
	SignupPerDay           []aghub.NetLimitView `json:"signup_per_day"`
	TrialPerDay            []aghub.NetLimitView `json:"trial_per_day"`
	DefaultFirstContacts   int                  `json:"default_first_contacts_per_min"`
	DefaultNonContactMsgs  int                  `json:"default_non_contact_msgs"`
	DefaultNonContactBytes int64                `json:"default_non_contact_bytes"`
}

func unixMs(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339) }

// Admission reads the admission state.
func (h *HubDB) Admission() (AdmissionState, error) {
	st := AdmissionState{Mode: aghub.AdmissionClosed, Accounts: map[string]int{}, Trial: map[string]int{},
		QuotaRaised: []QuotaRaise{}}
	var mode string
	switch err := h.db.QueryRow(`SELECT value FROM hub_meta WHERE key = 'admission_mode'`).Scan(&mode); {
	case err == nil && mode == aghub.AdmissionOpen:
		st.Mode = aghub.AdmissionOpen
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return st, err
	}
	var opens, closes int64
	var w struct {
		max, used int
		label     string
	}
	err := h.db.QueryRow(`SELECT opens_at, closes_at, max, used, label FROM admission_window
		ORDER BY id DESC LIMIT 1`).Scan(&opens, &closes, &w.max, &w.used, &w.label)
	if err == nil {
		now := time.Now().UnixMilli()
		o, c := opens, closes
		st.Window = &struct {
			OpensAt  string `json:"opens_at"`
			ClosesAt string `json:"closes_at"`
			Max      int    `json:"max"`
			Used     int    `json:"used"`
			Label    string `json:"label,omitempty"`
			Active   bool   `json:"active"`
		}{unixMs(opens), unixMs(closes), w.max, w.used, w.label, now >= o && now < c && w.used < w.max}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM admitted`).Scan(&st.AdmissionList); err != nil {
		return st, err
	}
	if err := h.groupCount(`SELECT admitted_via, COUNT(*) FROM agent GROUP BY admitted_via`, st.Accounts); err != nil {
		return st, err
	}
	if err := h.groupCount(`SELECT trial, COUNT(*) FROM agent GROUP BY trial`, st.Trial); err != nil {
		return st, err
	}
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM agent WHERE probation_until IS NOT NULL AND probation_until > ?`,
		time.Now().UnixMilli()).Scan(&st.OnProbation); err != nil {
		return st, err
	}
	rows, err := h.db.Query(`SELECT aid, first_contacts_per_min, non_contact_msgs, non_contact_bytes
		FROM quota_override ORDER BY aid LIMIT 200`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var q QuotaRaise
		if err := rows.Scan(&q.AID, &q.FirstContactsPerMin, &q.NonContactMsgs, &q.NonContactBytes); err != nil {
			return st, err
		}
		st.QuotaRaised = append(st.QuotaRaised, q)
	}
	st.Rules = AdmissionRules{
		PowBits:        regpow.Bits,
		ProbationHours: int(aghub.ProbationPeriod / time.Hour), TrialCredits: aghub.TrialCredits,
		InactiveDays: int(aghub.InactiveAfter / (24 * time.Hour)), TrialBudgetHub: aghub.TrialBudgetHub,
		SignupPerDay: aghub.SignupQuotaTable(), TrialPerDay: aghub.TrialBudgetTable(),
		DefaultFirstContacts: aghub.DefaultFirstContactsPerMin, DefaultNonContactMsgs: aghub.DefaultNonContactMsgs,
		DefaultNonContactBytes: aghub.DefaultNonContactBytes,
	}
	return st, rows.Err()
}

func (h *HubDB) groupCount(q string, into map[string]int) error {
	rows, err := h.db.Query(q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		into[k] = n
	}
	return rows.Err()
}

// DeliveryState is the hub-wide figures of the relay and of stored delivery
// confirmations: counts only (DLV §2.8).
type DeliveryState struct {
	MailboxQueued     int   `json:"mailbox_queued"`
	ConfirmationsHeld int   `json:"confirmations_held"`
	RedeliveryTracked int   `json:"redelivery_tracked"`
	ConfirmationTTLH  int   `json:"confirmation_ttl_hours"`
	FetchedTTLMin     int   `json:"confirmation_fetched_ttl_minutes"`
	MaxConfirmations  int64 `json:"confirmation_capacity"`
}

// Delivery reads the delivery figures.
func (h *HubDB) Delivery() (DeliveryState, error) {
	d := DeliveryState{ConfirmationTTLH: int(aghub.DAckTTL / time.Hour),
		FetchedTTLMin: int(aghub.DAckFetchedTTL / time.Minute), MaxConfirmations: aghub.MaxDAckRows}
	for q, p := range map[string]*int{
		`SELECT COUNT(*) FROM relay_message`:    &d.MailboxQueued,
		`SELECT COUNT(*) FROM relay_dack`:       &d.ConfirmationsHeld,
		`SELECT COUNT(*) FROM relay_redelivery`: &d.RedeliveryTracked,
	} {
		if err := h.db.QueryRow(q).Scan(p); err != nil {
			return d, err
		}
	}
	return d, nil
}

// FederationPeer is a peer hub as hub.db knows it: the agents it taught this
// hub and the net of what the two hubs owe each other.
type FederationPeer struct {
	PeerAID   string `json:"peer_aid"`
	Agents    int    `json:"agents"`
	Withdrawn int    `json:"withdrawn"`
	LastSeen  string `json:"last_stored_at,omitempty"`
	Owed      int64  `json:"owed_to_us"`
	Due       int64  `json:"owed_by_us"`
}

// Federation lists the peers this hub has learned agents from or settles with.
func (h *HubDB) Federation() ([]FederationPeer, error) {
	byPeer := map[string]*FederationPeer{}
	get := func(p string) *FederationPeer {
		if byPeer[p] == nil {
			byPeer[p] = &FederationPeer{PeerAID: p}
		}
		return byPeer[p]
	}
	rows, err := h.db.Query(`SELECT peer_aid, COUNT(*), SUM(CASE WHEN verified_at IS NULL THEN 1 ELSE 0 END),
		MAX(stored_at) FROM fed_a2a_card GROUP BY peer_aid`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p, last string
		var n int
		var wd sql.NullInt64
		if err := rows.Scan(&p, &n, &wd, &last); err != nil {
			rows.Close()
			return nil, err
		}
		x := get(p)
		x.Agents, x.Withdrawn, x.LastSeen = n-int(wd.Int64), int(wd.Int64), last
	}
	rows.Close()
	for q, set := range map[string]func(*FederationPeer, int64){
		`SELECT peer_aid, amount FROM hub_owed`: func(p *FederationPeer, v int64) { p.Owed = v },
		`SELECT peer_aid, amount FROM hub_due`:  func(p *FederationPeer, v int64) { p.Due = v },
	} {
		rs, err := h.db.Query(q)
		if err != nil {
			return nil, err
		}
		for rs.Next() {
			var p string
			var v int64
			if err := rs.Scan(&p, &v); err != nil {
				rs.Close()
				return nil, err
			}
			set(get(p), v)
		}
		rs.Close()
	}
	out := make([]FederationPeer, 0, len(byPeer))
	for _, p := range byPeer {
		out = append(out, *p)
	}
	return out, nil
}

func (s *Server) hAdmission(w http.ResponseWriter, r *http.Request) {
	st, err := s.hub.Admission()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) hDelivery(w http.ResponseWriter, r *http.Request) {
	d, err := s.hub.Delivery()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) hFederation(w http.ResponseWriter, r *http.Request) {
	peers, err := s.hub.Federation()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}
