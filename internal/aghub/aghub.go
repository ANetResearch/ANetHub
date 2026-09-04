// Package aghub is the v0.1 centralized Agent Hub — the single official service the whole network runs
// through. It is three things over one SQLite store:
//
//	registry — agents register their AgentCard + KEL. The Hub derives the AID from the KEL and checks it
//	           matches, so a registration cannot claim someone else's AID.
//	relay    — a store-and-forward message broker addressed by recipient AID. It is how one agent
//	           delegates a task to another and how the deliverable comes back: agents POST a message for
//	           a recipient (/relay/send) and the recipient PULLS its mailbox (/relay/poll, KEL-signed).
//	           The relayed payloads (a signed TaskDoc, a provider-signed receipt) are end-to-end
//	           verifiable, so the Hub only moves bytes — it cannot forge an interaction.
//	reviews  — a requester uploads {provider-signed receipt, requester-signed review}. The Hub verifies
//	           BOTH signatures against the registered KELs and checks they interlock (same interaction,
//	           reviewer == receipt.requester, subject == receipt.provider, review→receipt CID). Neither
//	           party can forge the other's signature, so a stored rating provably came from a real
//	           counterparty of a real interaction. interaction_id is the uniqueness key (one review each).
//
// v0.1 is deliberately centralized: there is no P2P. Aggregation is intentionally simple (mean + count);
// richer reputation and a decentralized transport are later versions.
package aghub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ANetResearch/ANetCore/adp"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	_ "modernc.org/sqlite" // pure-Go driver (K207 A3: no cgo in distributed runtime)
)

// AgentView is an agent's public registry entry plus its aggregate rating. Agents are addressed purely
// by AID (v0.1 has no P2P endpoint) — all traffic flows through the Hub relay. The profile fields
// (summary/readme/pricing) are AGENT-authored self-description (set via `anet profile set`); pricing is
// display-only text in v0.1 (no settlement).
type AgentView struct {
	AID          string   `json:"aid"`
	Name         string   `json:"name"`
	Caps         []string `json:"caps"`
	Summary      string   `json:"summary,omitempty"` // one-line self-description
	Readme       string   `json:"readme,omitempty"`  // longer markdown self-description
	Pricing      string   `json:"pricing,omitempty"` // free-form pricing text (display-only in v0.1)
	Listed       bool     `json:"listed"`            // true if it advertises a service (caps or profile) — only listed agents appear in the starfield/find
	GuestQuota   int      `json:"guest_quota"`       // guest-mode trial messages a visitor may send this agent (0 = opts out of guest traffic)
	AvgRating    float64  `json:"avg_rating"`
	ReviewCount  int      `json:"review_count"`
	RegisteredAt string   `json:"registered_at"`
	// HomeHub is set only on an agent learned from a peer hub: which hub
	// it lives on, and so where work for it must be sent. Empty means
	// this hub.
	HomeHub string `json:"home_hub,omitempty"`
	// Departed is true on the view returned for an AID that has
	// deregistered but still has evidence recorded against it. Leaving a
	// hub removes the routing and keeps the evidence; without this the
	// evidence had no HTTP surface at all, because every read of it hung
	// off the registration row that deregistering deletes.
	//
	// It is NOT a route: a departed agent is not deliverable, and
	// nothing here puts it back in a listing.
	Departed bool `json:"departed,omitempty"`
	// Registered is false on a graph node reconstructed from a review
	// whose subject or reviewer is no longer in the registry.
	//
	// Leaving a hub removes the routing and keeps the evidence, which is
	// the right trade — reviews record things that happened. The
	// consequence lands here: the graph had edges naming agents with no
	// node, and a renderer either drops them silently or fails. Saying
	// "this agent is no longer registered here" keeps the graph
	// self-consistent and keeps what happened visible.
	Registered bool `json:"registered"`
	// LastSeen and Quiet report whether this agent is still collecting
	// its mail. A directory that lists agents without saying which of
	// them have stopped answering is a directory that sends people to
	// wait on the dead.
	LastSeen string `json:"last_seen,omitempty"`
	Quiet    bool   `json:"quiet,omitempty"`
}

// ReviewView is one stored, verified review. Beyond the rating it carries the VERIFIED interaction
// content: the goal (re-derived from the request TaskDoc whose bytes hash to the receipt's request_cid)
// and the deliverable (whose bytes hash to the receipt's result_cid). So a viewer sees what was actually
// asked and delivered — not just a star + comment — and both are cryptographically bound to the receipt.
type ReviewView struct {
	InteractionID string `json:"interaction_id"`
	SubjectAID    string `json:"subject_aid"`
	ReviewerAID   string `json:"reviewer_aid"`
	Rating        int    `json:"rating"`
	Comment       string `json:"comment,omitempty"`
	ReceiptCID    string `json:"receipt_cid"`
	Goal          string `json:"goal"`         // what the requester asked (verified via request_cid)
	Deliverable   string `json:"deliverable"`  // what the provider returned (verified via result_cid)
	RequestCID    string `json:"request_cid"`  // content anchor of the request
	ResultCID     string `json:"result_cid"`   // content anchor of the deliverable
	CompletedAt   uint64 `json:"completed_at"` // provider's receipt time (unix millis)
	CreatedAt     uint64 `json:"created_at"`   // review time (unix millis)
}

// ReviewDetail is the verified interaction content the Hub stores alongside a review (extracted + checked
// by the server before this is called).
type ReviewDetail struct {
	Goal        string
	Deliverable string
	RequestCID  string
	ResultCID   string
	CompletedAt uint64
}

// RelayMessage is one store-and-forward message queued for a recipient AID.
type RelayMessage struct {
	ID            int64  `json:"id"`
	ToAID         string `json:"to_aid"`
	FromAID       string `json:"from_aid"`
	Kind          string `json:"kind"` // "delegate" | "message" | "result"
	InteractionID string `json:"interaction_id"`
	Payload       []byte `json:"-"` // opaque, end-to-end verifiable (base64 on the wire)
	CreatedAt     string `json:"created_at"`
}

// Relay message kinds.
const (
	RelayKindDelegate = "delegate" // a signed delegation (delegation.DelegateReq bytes)
	RelayKindResult   = "result"   // a completion (delegation.ResultResp bytes: transcript + provider receipt)
	RelayKindMessage  = "message"  // a conversation message (delegation.ChatMsg bytes: text / end negotiation)
)

// Store is the Hub's durable registry + relay + review store (SQLite).
type Store struct {
	// hubKey signs settlement receipts. Nil until the application wires
	// it, and a store without one settles without signing rather than
	// refusing — an unsigned settlement is weaker, not broken.
	hubKey *identity.Controller
	// peerSettle forwards a payment on another hub'''s ledger to that hub.
	peerSettle PeerSettler
	clearable  func() []string
	// hubAID is the row credit is issued from and redeemed into, so the
	// ledger sums to zero and the hub's liability is countable.
	hubAID string
	// issuance serialises appends to the supply chain. A gap or a
	// duplicate sequence number would make the chain unverifiable, and
	// two concurrent grants are an ordinary thing to have.
	issuance issuanceChain
	db       *sql.DB
	mu       sync.Mutex
}

// Open opens (creating if needed) a Hub store at dir (SQLite at dir/hub.db).
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("hub: dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("hub: mkdir: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, fmt.Errorf("hub: open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrateInvites(); err != nil {
		return nil, err
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// An upgraded hub already holds agents whose capabilities were only
	// ever a JSON blob; index them before serving.
	if err := s.backfillCaps(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the db handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS agent (
		   aid TEXT PRIMARY KEY,
		   name TEXT NOT NULL DEFAULT '',
		   caps TEXT NOT NULL DEFAULT '[]',
		   summary TEXT NOT NULL DEFAULT '',
		   readme TEXT NOT NULL DEFAULT '',
		   pricing TEXT NOT NULL DEFAULT '',
		   guest_quota INTEGER NOT NULL DEFAULT 5,
		   kel BLOB NOT NULL,
		   registered_at TEXT NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS review (
		   interaction_id TEXT PRIMARY KEY,
		   subject_aid TEXT NOT NULL,
		   reviewer_aid TEXT NOT NULL,
		   rating INTEGER NOT NULL,
		   comment TEXT NOT NULL DEFAULT '',
		   receipt_cid TEXT NOT NULL,
		   goal TEXT NOT NULL DEFAULT '',
		   deliverable TEXT NOT NULL DEFAULT '',
		   request_cid TEXT NOT NULL DEFAULT '',
		   result_cid TEXT NOT NULL DEFAULT '',
		   completed_at INTEGER NOT NULL DEFAULT 0,
		   created_at INTEGER NOT NULL,
		   stored_at TEXT NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_review_subject ON review(subject_aid)`,
		// A capability id is precise, structured and machine-resolvable —
		// "cas.put", "ptz.absolute@onvif/camera-006" — and discovery could
		// only match it as a substring inside a JSON blob, alongside the
		// agent's prose. So "who serves cas.put" was a question the network
		// could not be asked, though C1 had been answering it in every
		// invocation. A row per capability makes it answerable, and makes
		// prefix search ("ptz.*") mean what it says.
		`CREATE TABLE IF NOT EXISTS agent_cap (
		   aid TEXT NOT NULL,
		   cap TEXT NOT NULL,
		   PRIMARY KEY (aid, cap)
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_agent_cap ON agent_cap(cap)`,
		// The agent's own signed statement of what it offers. Stored
		// verbatim, because the signature covers these exact bytes and a
		// re-encoding would break it for everyone downstream.
		`CREATE TABLE IF NOT EXISTS agent_card (
		   aid TEXT PRIMARY KEY,
		   seq INTEGER NOT NULL,
		   card BLOB NOT NULL,
		   stored_at TEXT NOT NULL,
		   -- fed_seq orders cards for federation sync: a peer asks for
		   -- everything after the cursor it holds. It advances on every
		   -- store, including an update, or a peer that already synced an
		   -- agent would never see that agent change.
		   fed_seq INTEGER NOT NULL DEFAULT 0
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_card_fedseq ON agent_card(fed_seq)`,
		// Cards learned from a peer hub, kept apart from cards published
		// here. Which hub an agent actually lives on decides where its
		// work is delivered, and a directory that forgot the difference
		// would answer with agents it cannot reach.
		// The credit ledger. Balances live here, which is exactly what
		// makes this hub their custodian — see facilitator.go.
		`CREATE TABLE IF NOT EXISTS credit_balance (
		   aid TEXT PRIMARY KEY,
		   credits INTEGER NOT NULL DEFAULT 0
		 )`,
		// Every movement, so a balance can be explained rather than just
		// asserted.
		`CREATE TABLE IF NOT EXISTS credit_entry (
		   seq INTEGER PRIMARY KEY AUTOINCREMENT,
		   aid TEXT NOT NULL,
		   delta INTEGER NOT NULL,
		   reason TEXT NOT NULL DEFAULT '',
		   at TEXT NOT NULL
		 )`,
		// One row per settled authorization: the idempotency key and the
		// replay guard in one. Inserted before the balance moves, so a
		// concurrent second settle loses on the primary key rather than
		// on a check it raced.
		`CREATE TABLE IF NOT EXISTS credit_settled (
		   auth_id TEXT PRIMARY KEY,
		   payer TEXT NOT NULL,
		   pay_to TEXT NOT NULL,
		   amount INTEGER NOT NULL,
		   interaction_id TEXT NOT NULL DEFAULT '',
		   at TEXT NOT NULL
		 )`,
		// Foreign authorizations already cleared here, so a peer
		// repeating a receipt cannot credit our user twice.
		`CREATE TABLE IF NOT EXISTS credit_cleared (
		   auth_id TEXT PRIMARY KEY,
		   peer_aid TEXT NOT NULL,
		   pay_to TEXT NOT NULL,
		   amount INTEGER NOT NULL,
		   at TEXT NOT NULL
		 )`,
		// What each peer hub owes this one. A claim on another hub, kept
		// apart from credit here — the two must not be allowed to look
		// alike.
		// Credit taken back out of circulation, one row per authorization
		// the agent signed away. The reference is what the hub agreed to
		// settle against outside this system; opaque here on purpose.
		// The exact bytes a review was verified from. Kept because a hub
		// that stored the conclusion and discarded the evidence can only
		// pass on its own say-so, and federating reputation on say-so is
		// the thing this design exists to avoid.
		`CREATE TABLE IF NOT EXISTS review_blob (
			interaction_id  TEXT PRIMARY KEY,
			receipt_raw     BLOB NOT NULL,
			review_raw      BLOB NOT NULL,
			request_doc_raw BLOB NOT NULL,
			deliverable_raw BLOB NOT NULL
		)`,
		// Reviews learned from a peer hub, kept apart from local ones so
		// the arithmetic can stay per source.
		`CREATE TABLE IF NOT EXISTS fed_review (
			interaction_id TEXT PRIMARY KEY,
			subject_aid    TEXT NOT NULL,
			reviewer_aid   TEXT NOT NULL,
			rating         INTEGER NOT NULL,
			comment        TEXT NOT NULL DEFAULT '',
			receipt_cid    TEXT NOT NULL DEFAULT '',
			peer_aid       TEXT NOT NULL,
			created_at     INTEGER NOT NULL DEFAULT 0,
			stored_at      TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_fed_review_subject ON fed_review(subject_aid)`,
		// Every change to the total supply, in order, signed. The record
		// column holds the ael.EventRecord that actually verifies; the
		// parsed columns beside it are for querying and are not what a
		// reader should check.
		// Attestations: what somebody signed about a chain's head at a
		// moment. Both directions live here — what others said about
		// this hub, and what this hub said about its peers.
		`CREATE TABLE IF NOT EXISTS head_attestation (
			id          TEXT PRIMARY KEY,
			chain_did   TEXT NOT NULL,
			witness_aid TEXT NOT NULL,
			seq         INTEGER NOT NULL,
			head_id     TEXT NOT NULL,
			observed_at INTEGER NOT NULL,
			blob        BLOB NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attestation_chain ON head_attestation(chain_did, seq)`,
		`CREATE TABLE IF NOT EXISTS credit_issuance (
			seq     INTEGER PRIMARY KEY,
			id      TEXT NOT NULL UNIQUE,
			prev_id TEXT NOT NULL,
			kind    TEXT NOT NULL,
			aid     TEXT NOT NULL,
			amount  INTEGER NOT NULL,
			reason  TEXT NOT NULL DEFAULT '',
			at      INTEGER NOT NULL,
			record  BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS credit_redemption (
			auth_id   TEXT PRIMARY KEY,
			aid       TEXT NOT NULL,
			amount    INTEGER NOT NULL,
			reference TEXT NOT NULL DEFAULT '',
			at        TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_redemption_aid ON credit_redemption(aid)`,
		// A peer hub's signed discharge of what it owed us. Keyed on the
		// statement id so a replayed discharge clears the debt once.
		`CREATE TABLE IF NOT EXISTS hub_cleared (
			auth_id  TEXT PRIMARY KEY,
			peer_aid TEXT NOT NULL,
			amount   INTEGER NOT NULL,
			at       TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS hub_owed (
		   peer_aid TEXT PRIMARY KEY,
		   amount INTEGER NOT NULL DEFAULT 0
		 )`,
		// The debtor side of the same relationship, keyed by payee rather
		// than by hub: this hub settled a payment to an agent that banks
		// elsewhere, so the credit left this ledger and is owed to
		// whichever hub holds that agent. Keyed by payee because that is
		// what the authorization names — which hub holds it is a fact this
		// hub may not have.
		`CREATE TABLE IF NOT EXISTS p2p_addr (
		   aid  TEXT PRIMARY KEY,
		   addr TEXT NOT NULL,
		   at   TEXT NOT NULL
		 )`,
		// Key histories of agents that have left. Routing goes when an
		// agent deregisters; proof does not. Without this the receipts
		// and reviews the hub still serves became uncheckable against
		// any key the hub could produce.
		`CREATE TABLE IF NOT EXISTS departed_kel (
		   aid TEXT PRIMARY KEY,
		   kel BLOB NOT NULL,
		   at  TEXT NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS hub_due (
		   payee_aid TEXT PRIMARY KEY,
		   amount INTEGER NOT NULL DEFAULT 0
		 )`,
		`CREATE TABLE IF NOT EXISTS fed_card (
		   aid TEXT PRIMARY KEY,
		   seq INTEGER NOT NULL,
		   card BLOB NOT NULL,
		   kel BLOB NOT NULL,
		   home TEXT NOT NULL,
		   peer_aid TEXT NOT NULL,
		   stored_at TEXT NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS relay_message (
		   id INTEGER PRIMARY KEY AUTOINCREMENT,
		   to_aid TEXT NOT NULL,
		   from_aid TEXT NOT NULL DEFAULT '',
		   kind TEXT NOT NULL,
		   interaction_id TEXT NOT NULL DEFAULT '',
		   payload BLOB NOT NULL,
		   created_at TEXT NOT NULL,
		   delivered_at TEXT
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_relay_mailbox ON relay_message(to_aid, delivered_at, id)`,
		// completed_task counts interactions that reached a DELIVERED result (a provider relayed a
		// "result" back to its requester). This is the network's "work done" metric: reviews are a
		// voluntary subset of these (most completed tasks are never reviewed). One row per interaction.
		`CREATE TABLE IF NOT EXISTS completed_task (
		   interaction_id TEXT PRIMARY KEY,
		   provider_aid TEXT NOT NULL DEFAULT '',
		   requester_aid TEXT NOT NULL DEFAULT '',
		   completed_at TEXT NOT NULL
		 )`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("hub: migrate: %w", err)
		}
	}
	// Additive upgrade for pre-existing DBs: add the profile columns if they are missing. ADD COLUMN
	// errors with "duplicate column name" when they already exist (fresh DBs from the CREATE above) —
	// that is expected and ignored, so migrate stays idempotent.
	for _, q := range []string{
		`ALTER TABLE agent ADD COLUMN summary TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent ADD COLUMN readme TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent ADD COLUMN pricing TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE agent ADD COLUMN guest_quota INTEGER NOT NULL DEFAULT 5`,
		// Visibility is the agent's answer to "may this hub tell other
		// hubs about me". Three tiers, hub-local by default — the
		// conservative default is deliberate (K208 §5.2): a directory
		// that federated by default would publish, once and for everyone
		// who never thought about it.
		`ALTER TABLE agent ADD COLUMN visibility TEXT NOT NULL DEFAULT 'hub-local'`,
		// When this agent last collected its mail. NULL for rows that
		// predate the column, which must read as "unknown" and never as
		// "dead" — see liveness.go.
		`ALTER TABLE agent ADD COLUMN last_seen_at TEXT`,
		`ALTER TABLE agent_card ADD COLUMN fed_seq INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(q); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("hub: migrate profile: %w", err)
		}
	}
	return nil
}

// PutAgent registers or updates an agent (upsert on AID). The caller has already verified the KEL
// derives this AID. anet models no availability class — an agent may always be offline (the relay is
// store-and-forward), so nothing about "resident vs intermittent" is recorded. guestQuota is how many
// guest-mode trial messages a visitor may send this agent (0 = opt out of guest traffic).
func (s *Store) PutAgent(aid, name string, caps []string, guestQuota int, kel []byte) error {
	// The bound is enforced here as well as at the HTTP boundary, because
	// this is where the index is written and it is the invariant the index
	// depends on. The handler checks first so a caller gets 400 with the
	// offending id named rather than 500.
	if err := validateCaps(caps); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	capsJSON, _ := json.Marshal(caps)
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO agent(aid,name,caps,guest_quota,kel,registered_at) VALUES(?,?,?,?,?,?)
		 ON CONFLICT(aid) DO UPDATE SET name=excluded.name, caps=excluded.caps,
		   guest_quota=excluded.guest_quota, kel=excluded.kel`,
		aid, name, string(capsJSON), guestQuota, kel, now); err != nil {
		return err
	}
	// Re-registering replaces the capability set rather than adding to it:
	// a node that dropped a capability has stopped offering it, and a
	// directory that kept answering yes would be sending work to a
	// provider that will refuse it.
	if _, err := tx.Exec(`DELETE FROM agent_cap WHERE aid=?`, aid); err != nil {
		return err
	}
	for _, c := range caps {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO agent_cap(aid,cap) VALUES(?,?)`, aid, c); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Bounds on what one registration may put into the capability index.
//
// Neither the length of a capability id nor the number an agent may
// declare was limited. One anonymous POST /register carried 200,000 ids
// (a 4.2 MB body), which produced a 55.5 MB hub.db, a 4.0 MB response to
// every subsequent anonymous GET /agents, and 4.0 MB of work on every
// directory query. Registering costs a locally generated key pair and
// nothing else, so any caller could do this repeatedly. Found by writing
// such a registration against a test hub and measuring what it left
// behind.
//
// The numbers are far above any real id (a structured
// family.action@vendor/device string) and any real agent's catalogue, so
// they bound the abuse without constraining use. Bytes rather than
// characters for the id, because bytes are what is stored and served.
//
// Over the bound the whole registration is refused, naming what was over
// it. Truncating instead would publish an id the node never claimed, or
// drop one it does serve, and a directory that answers for capabilities
// nobody offers is exactly what this index exists to prevent. The cost of
// refusing: an agent with a genuinely larger catalogue cannot register at
// all, and its operator has to split it or raise these constants.
const (
	maxCapIDLen     = 256
	maxCapsPerAgent = 256
)

// validateCaps checks a declared capability set against those bounds.
func validateCaps(caps []string) error {
	if len(caps) > maxCapsPerAgent {
		return fmt.Errorf("hub: %d capabilities declared, at most %d are accepted",
			len(caps), maxCapsPerAgent)
	}
	for _, c := range caps {
		if len(c) > maxCapIDLen {
			return fmt.Errorf("hub: capability id is %d bytes, at most %d are accepted: %q",
				len(c), maxCapIDLen, excerpt(c))
		}
	}
	return nil
}

// excerpt shortens an id for an error message without splitting a rune,
// so the refusal can quote what was refused without echoing all of it.
func excerpt(s string) string {
	const runes = 32
	r := []rune(s)
	if len(r) <= runes {
		return s
	}
	return string(r[:runes]) + "\u2026"
}

// FindByCapability returns agents offering a capability id.
//
// Exact by default, prefix when the query ends in "*". A capability id is
// structured — family, action, and often a device or vendor after "@" —
// so "ptz.*" is a real question ("who can move a camera") and not a
// convenience: the alternative is asking for prose and hoping the
// provider described itself the way the caller thought to search.
func (s *Store) FindByCapability(cap string) ([]AgentView, error) {
	var preds []string
	var args []any
	for _, term := range strings.Split(cap, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		if strings.HasSuffix(term, "*") {
			// Prefix by substring comparison, not LIKE. SQLite's LIKE is
			// ASCII case-insensitive while "=" is not, so one query string
			// got two answers depending on the trailing "*": an agent
			// registered under "Text.Digest" was absent from
			// ?cap=text.digest and present in ?cap=text.*. A capability id
			// is a structured identifier that a provider dispatches on, not
			// prose — "Text.Digest" and "text.digest" name two different
			// capabilities, and only one of them will be answered — so both
			// forms compare bytes. This also matches cardServes(), which is
			// how the same question is answered for a peer-learned agent.
			//
			// substr has no pattern language of its own, so the escaping
			// LIKE needed for "%" and "_" goes away with it. The cost is
			// unchanged: neither form can use idx_agent_cap (SQLite's LIKE
			// range optimisation needs a NOCASE column, which this is not),
			// so both scan.
			stem := strings.TrimSuffix(term, "*")
			preds = append(preds, "substr(c.cap,1,length(?)) = ?")
			args = append(args, stem, stem)
			continue
		}
		// Exact, bytes included — see the prefix branch for why.
		preds = append(preds, "c.cap = ?")
		args = append(args, term)
	}
	if len(preds) == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.guest_quota, a.registered_at, a.last_seen_at,
		        COALESCE(AVG(r.rating),0), COUNT(r.interaction_id)
		 FROM agent a
		 JOIN agent_cap c ON c.aid = a.aid
		 LEFT JOIN review r ON r.subject_aid = a.aid
		 WHERE `+strings.Join(preds, " OR ")+`
		 GROUP BY a.aid
		 ORDER BY AVG(r.rating) DESC, COUNT(r.interaction_id) DESC, a.registered_at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentView
	for rows.Next() {
		av, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		if !av.Browsable() {
			continue
		}
		out = append(out, av)
	}
	return out, rows.Err()
}

// backfillCaps populates agent_cap for rows registered before the table
// existed. Without it an upgraded hub answers "nobody serves that" for
// every agent already registered — a directory that silently forgets its
// contents on upgrade is worse than one that never had an index.
func (s *Store) backfillCaps() error {
	rows, err := s.db.Query(
		`SELECT aid, caps FROM agent WHERE aid NOT IN (SELECT DISTINCT aid FROM agent_cap)`)
	if err != nil {
		return err
	}
	type row struct {
		aid, caps string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.aid, &r.caps); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range pending {
		var caps []string
		if json.Unmarshal([]byte(r.caps), &caps) != nil {
			continue
		}
		for _, c := range caps {
			if c = strings.TrimSpace(c); c != "" {
				if _, err := s.db.Exec(`INSERT OR IGNORE INTO agent_cap(aid,cap) VALUES(?,?)`, r.aid, c); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// PutProfile updates an agent's self-authored profile (summary/readme/pricing). The agent must already
// be registered (its identity is proven at registration + on this call's signed challenge). Profile is
// kept separate from PutAgent so a plain re-registration never wipes it.
func (s *Store) PutProfile(aid, summary, readme, pricing string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE agent SET summary=?, readme=?, pricing=? WHERE aid=?`,
		summary, readme, pricing, aid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("hub: agent %s not registered", aid)
	}
	return nil
}

// AgentKEL returns the stored KEL bytes for aid (used to verify uploaded evidence + relay auth).
func (s *Store) AgentKEL(aid string) ([]byte, error) {
	var kel []byte
	err := s.db.QueryRow(`SELECT kel FROM agent WHERE aid=?`, aid).Scan(&kel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("hub: agent %s not registered", aid)
	}
	return kel, err
}

// AnyKEL resolves a key history for an agent registered here OR learned
// from a peer hub.
//
// Needed because a cross-hub interaction could not be reviewed at all.
// The reviewer has an account here and the provider has one somewhere
// else, so "are both parties registered here" — the question the local
// upload path asks — is false for every interaction that crossed a
// boundary, and federation therefore produced work nobody could rate.
//
// Widening it is safe for the reason the whole evidence model rests on:
// the interlock is checked against these key histories, and a review is
// only admitted if the provider's own signature anchors it. A hub that
// supplied the wrong history for a foreign agent would fail that check,
// not pass it — the KEL is what the arithmetic is done against, not a
// permission to skip the arithmetic.
func (s *Store) AnyKEL(aid string) ([]byte, error) {
	if kel, err := s.AgentKEL(aid); err == nil {
		return kel, nil
	}
	var kel []byte
	err := s.db.QueryRow(`SELECT kel FROM fed_card WHERE aid=?`, aid).Scan(&kel)
	if err == nil {
		return kel, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	// An agent that left. Its routing is gone and its proof is not.
	if derr := s.db.QueryRow(`SELECT kel FROM departed_kel WHERE aid=?`, aid).Scan(&kel); derr == nil {
		return kel, nil
	}
	return nil, fmt.Errorf(
		"hub: %s is neither registered here, known from a peer, nor a former registrant", aid)
}

// HasInteraction reports whether a review for interactionID already exists (one-review-per-interaction).
func (s *Store) HasInteraction(interactionID string) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM review WHERE interaction_id=?`, interactionID).Scan(&one)
	return err == nil
}

// PutReview stores a verified review + its verified interaction content (interaction_id is the unique key).
func (s *Store) PutReview(rv *evidence.Review, d ReviewDetail) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`INSERT INTO review(interaction_id,subject_aid,reviewer_aid,rating,comment,receipt_cid,
		   goal,deliverable,request_cid,result_cid,completed_at,created_at,stored_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rv.InteractionID, rv.SubjectAID, rv.ReviewerAID, rv.Rating, rv.Comment, rv.ReceiptCID,
		d.Goal, d.Deliverable, d.RequestCID, d.ResultCID, d.CompletedAt, rv.CreatedAt, now)
	return err
}

// ListAgents returns LISTED agents (those advertising a service — caps or a profile) with their
// aggregate rating, best-rated first. A non-empty query filters to agents whose AID, name, caps or
// profile contain it (case-insensitive) — the `find` backend. Pure requesters (registered but with no
// caps/profile) are intentionally omitted so they do not clutter the starfield.
func (s *Store) ListAgents(query string) ([]AgentView, error) {
	q := `SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.guest_quota, a.registered_at, a.last_seen_at,
	             COALESCE(AVG(r.rating),0), COUNT(r.interaction_id)
	      FROM agent a LEFT JOIN review r ON r.subject_aid = a.aid`
	var args []any
	if query != "" {
		like := "%" + query + "%"
		q += ` WHERE a.aid LIKE ? OR a.name LIKE ? OR a.caps LIKE ? OR a.summary LIKE ? OR a.readme LIKE ?`
		args = append(args, like, like, like, like, like)
	}
	q += ` GROUP BY a.aid ORDER BY AVG(r.rating) DESC, COUNT(r.interaction_id) DESC, a.registered_at`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentView
	for rows.Next() {
		av, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		if !av.Listed || !av.Browsable() {
			continue
		}
		out = append(out, av)
	}
	return out, rows.Err()
}

// Browsable reports whether this agent belongs in a listing somebody is
// reading.
//
// A method on the view rather than a filter at each query, because there
// is more than one way to reach a listing — by name, by capability id —
// and the first version of this put the rule in one of them. The
// capability search then went on serving an agent that had been gone for
// forty days, which is precisely the shape of bug this whole file exists
// to close.
//
// Out of the listing is NOT out of the hub: the row, the reviews and the
// balance all stay, and one poll puts it back.
//
// An agent with no recorded poll falls back to its registration time.
// This used to return true unconditionally, so that "registered and
// never once collected mail" was a permanent exemption from the thirty
// day rule — the one shape of row most likely to be abandoned was the
// one shape that could never be delisted. The original reason for the
// exemption (rows predating the last_seen_at column would all vanish on
// upgrade) was real when the column was added and no longer applies:
// those rows have since either polled or passed AbandonedAfter on their
// registration date, which is the same judgement this now makes.
//
// The fallback deliberately keeps a just-registered agent visible: a
// node that has registered but not yet polled is unknown, not dead, and
// AbandonedAfter is the window it gets to prove otherwise. An
// unparseable or absent timestamp also stays visible, because a
// timestamp we cannot read says nothing about whether the agent is
// answering.
func (av AgentView) Browsable() bool {
	stamp := av.LastSeen
	if stamp == "" {
		stamp = av.RegisteredAt
	}
	if stamp == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return true
	}
	return time.Since(t) <= AbandonedAfter
}

// departedView builds the view for an AID with no registration row but
// with reviews recorded against it. Returns nil when the AID has no
// evidence here either — that is an AID this hub has never seen, not a
// departure.
//
// Name and profile are deliberately absent: those were self-description
// carried on the registration row, and that row is gone. What survives
// is what somebody else attested to.
func (s *Store) departedView(aid string) (*AgentView, error) {
	var count int
	var avg float64
	if err := s.db.QueryRow(
		`SELECT COUNT(interaction_id), COALESCE(AVG(rating),0) FROM review WHERE subject_aid=?`,
		aid).Scan(&count, &avg); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	// If a peer hub now carries this AID, say so. Without this the
	// departed view would be strictly less informative than the
	// peer-lookup branch it now takes precedence over in hAgent: a node
	// that left this hub for another one would lose its forwarding
	// address at the same moment its evidence gained a surface.
	return &AgentView{
		AID:         aid,
		Departed:    true,
		Registered:  false,
		Listed:      false,
		AvgRating:   avg,
		ReviewCount: count,
		HomeHub:     s.HomeHubOf(aid),
	}, nil
}

// GetAgent returns one agent's entry + aggregate and its reviews (newest first).
func (s *Store) GetAgent(aid string) (*AgentView, []ReviewView, error) {
	row := s.db.QueryRow(
		`SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.guest_quota, a.registered_at, a.last_seen_at,
		        COALESCE(AVG(r.rating),0), COUNT(r.interaction_id)
		 FROM agent a LEFT JOIN review r ON r.subject_aid = a.aid
		 WHERE a.aid=? GROUP BY a.aid`, aid)
	av, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		// No registration row. If evidence was recorded against this
		// AID it outlives the routing by design, so answer with a view
		// marked departed instead of 404 — otherwise the reviews, the
		// receipts they anchor and the departed KEL are all still in
		// the database with no way for a third party to read them, and
		// "removes the routing, keeps the evidence" is true in storage
		// but false over HTTP.
		//
		// An AID with no row and no evidence is genuinely unknown here
		// and still 404s.
		dv, derr := s.departedView(aid)
		if derr != nil {
			return nil, nil, derr
		}
		if dv == nil {
			return nil, nil, fmt.Errorf("hub: agent %s not found", aid)
		}
		av = *dv
	} else if err != nil {
		return nil, nil, err
	}
	rrows, err := s.db.Query(
		`SELECT interaction_id, subject_aid, reviewer_aid, rating, comment, receipt_cid,
		        goal, deliverable, request_cid, result_cid, completed_at, created_at
		 FROM review WHERE subject_aid=? ORDER BY created_at DESC`, aid)
	if err != nil {
		return nil, nil, err
	}
	defer rrows.Close()
	var reviews []ReviewView
	for rrows.Next() {
		var rv ReviewView
		if err := rrows.Scan(&rv.InteractionID, &rv.SubjectAID, &rv.ReviewerAID, &rv.Rating, &rv.Comment, &rv.ReceiptCID,
			&rv.Goal, &rv.Deliverable, &rv.RequestCID, &rv.ResultCID, &rv.CompletedAt, &rv.CreatedAt); err != nil {
			return nil, nil, err
		}
		reviews = append(reviews, rv)
	}
	return &av, reviews, rrows.Err()
}

// --- relay broker: store-and-forward mailboxes keyed by recipient AID ---

// RelayEnqueue queues a message for toAID and returns its id. Payload is opaque bytes (the Hub does not
// interpret it — a delegation or a result is end-to-end verifiable by the recipient).
func (s *Store) RelayEnqueue(toAID, fromAID, kind, interactionID string, payload []byte) (int64, error) {
	if toAID == "" || kind == "" || len(payload) == 0 {
		return 0, fmt.Errorf("hub: relay enqueue needs to_aid, kind and payload")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`INSERT INTO relay_message(to_aid,from_aid,kind,interaction_id,payload,created_at)
		 VALUES(?,?,?,?,?,?)`, toAID, fromAID, kind, interactionID, payload, now)
	if err != nil {
		return 0, err
	}
	// A relayed "result" is a provider delivering the final deliverable to its requester — i.e. a task
	// reached completion. Record it once per interaction (guest trials use "message", not "result", so
	// they are naturally excluded). This underpins the network's "completed tasks" stat.
	if kind == RelayKindResult && interactionID != "" {
		_, _ = s.db.Exec(
			`INSERT OR IGNORE INTO completed_task(interaction_id,provider_aid,requester_aid,completed_at)
			 VALUES(?,?,?,?)`, interactionID, fromAID, toAID, now)
	}
	return res.LastInsertId()
}

// HubStats are the headline metrics shown on the public landing page.
type HubStats struct {
	Agents         int     `json:"agents"`          // listed providers (advertise a service)
	TasksCompleted int     `json:"tasks_completed"` // interactions that reached a delivered result
	Reviews        int     `json:"reviews"`         // verified reviews (a voluntary subset of completed)
	AvgRating      float64 `json:"avg_rating"`      // mean rating over all reviews (0 if none)
}

// Stats computes the landing metrics in one pass.
func (s *Store) Stats() (HubStats, error) {
	var out HubStats
	agents, err := s.ListAgents("")
	if err != nil {
		return out, err
	}
	for _, a := range agents {
		if a.Listed {
			out.Agents++
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM completed_task`).Scan(&out.TasksCompleted); err != nil {
		return out, err
	}
	var avg sql.NullFloat64
	if err := s.db.QueryRow(`SELECT COUNT(*), AVG(rating) FROM review`).Scan(&out.Reviews, &avg); err != nil {
		return out, err
	}
	if avg.Valid {
		out.AvgRating = avg.Float64
	}
	return out, nil
}

// relayPollByteBudget caps the cumulative raw payload returned by one RelayPoll so a poll response stays
// well under the daemon's response cap even with inline attachments; base64 on the wire inflates this ~4/3
// (48 MiB → ~64 MiB JSON), comfortably below maxHubResponse.
const relayPollByteBudget = 48 << 20 // 48 MiB

// RelayPoll returns undelivered messages for toAID, oldest first (limit ≤ 0 → 100).
func (s *Store) RelayPoll(toAID string, limit int) ([]RelayMessage, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id,to_aid,from_aid,kind,interaction_id,payload,created_at
		 FROM relay_message WHERE to_aid=? AND delivered_at IS NULL ORDER BY id LIMIT ?`, toAID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayMessage
	var acc int64
	for rows.Next() {
		var m RelayMessage
		if err := rows.Scan(&m.ID, &m.ToAID, &m.FromAID, &m.Kind, &m.InteractionID, &m.Payload, &m.CreatedAt); err != nil {
			return nil, err
		}
		// Bound the cumulative payload of one poll response so a backlog of large ATTACHMENT-bearing
		// messages can't produce a body that overflows the poller's response cap (which would truncate
		// and wedge the mailbox). Always return the first message — even if it alone exceeds the budget —
		// so a single big message is still deliverable; then stop before adding one that would blow it.
		if len(out) > 0 && acc+int64(len(m.Payload)) > relayPollByteBudget {
			break
		}
		acc += int64(len(m.Payload))
		out = append(out, m)
	}
	return out, rows.Err()
}

// RelayAck marks messages delivered, scoped to toAID so a caller can only ack its own mailbox. Returns
// how many rows were marked.
func (s *Store) RelayAck(toAID string, ids []int64) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	total := 0
	for _, id := range ids {
		res, err := s.db.Exec(
			`UPDATE relay_message SET delivered_at=? WHERE id=? AND to_aid=? AND delivered_at IS NULL`,
			now, id, toAID)
		if err != nil {
			return total, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			total++
		}
	}
	return total, nil
}

// PurgeGuestRelay deletes ALREADY-DELIVERED relay rows to or from a guest-broker AID. Guest-mode traffic
// is transient by design ("data not stored"): once a message has been delivered (the handler pulled the
// task, or the broker pulled the reply), the row is no longer needed, so this keeps guest chatter from
// accumulating in the store. Undelivered rows are left intact so nothing in flight is lost.
func (s *Store) PurgeGuestRelay(guestAID string) (int, error) {
	if guestAID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`DELETE FROM relay_message WHERE (to_aid=? OR from_aid=?) AND delivered_at IS NOT NULL`,
		guestAID, guestAID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// PurgeStaleGuestRelay deletes ALL relay rows to or from the guest broker created before cutoff, whether
// or not they were delivered. It backstops PurgeGuestRelay: a visitor who abandons the tab (or whose
// message went to an offline handler that never pulled it) leaves rows that never get "delivered" and so
// are never purged on poll. Guest sessions are ephemeral (dropped after guestSessionTTL), so once a row
// is older than that its session is dead and the row can go — nothing in flight is lost. created_at is
// RFC3339Nano text; lexicographic comparison is correct to well below the minute-scale cutoff used here.
func (s *Store) PurgeStaleGuestRelay(guestAID string, cutoff time.Time) (int, error) {
	if guestAID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`DELETE FROM relay_message WHERE (to_aid=? OR from_aid=?) AND created_at < ?`,
		guestAID, guestAID, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Edge is a verified review relationship: the reviewer rated the subject. It is the real, cryptographically
// backed collaboration signal the starfield draws (reviewer → subject).
type Edge struct {
	Source string `json:"source"` // reviewer AID
	Target string `json:"target"` // subject (provider) AID
	Rating int    `json:"rating"`
}

// ReviewEdges returns one edge per stored review (reviewer → subject).
func (s *Store) ReviewEdges() ([]Edge, error) {
	rows, err := s.db.Query(`SELECT reviewer_aid, subject_aid, rating FROM review`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Edge
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.Source, &e.Target, &e.Rating); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanAgent(sc scanner) (AgentView, error) {
	var av AgentView
	var capsJSON string
	var lastSeen sql.NullString
	if err := sc.Scan(&av.AID, &av.Name, &capsJSON, &av.Summary, &av.Readme, &av.Pricing,
		&av.GuestQuota, &av.RegisteredAt, &lastSeen, &av.AvgRating, &av.ReviewCount); err != nil {
		return av, err
	}
	// Every listing surface runs through this one function, so all of
	// them agree about who is still collecting. Three copies of the same
	// arithmetic would be three copies that drift.
	live := livenessFrom(lastSeen.String, time.Now())
	av.LastSeen, av.Quiet = live.LastSeen, live.Quiet
	_ = json.Unmarshal([]byte(capsJSON), &av.Caps)
	// An agent is "listed" (shown as a provider) once it advertises a service: any capability or any
	// profile text. A pure requester has none of these and stays out of the public listing.
	av.Listed = len(av.Caps) > 0 || av.Summary != "" || av.Readme != "" || av.Pricing != ""
	av.Registered = true // it came out of the agent table
	return av, nil
}

// aidFromKEL derives the self-certifying AID from a KEL's inception→final state.
func aidFromKEL(kel []identity.SignedEvent) (string, error) {
	states, err := identity.Replay(kel)
	if err != nil {
		return "", err
	}
	if len(states) == 0 {
		return "", errors.New("hub: empty KEL")
	}
	return states[len(states)-1].AID, nil
}

// GraphNodeFor builds a node for an AID that appears in an edge but not
// in the listing.
//
// It looks the agent up first: an agent that is registered but merely
// unlisted or quiet has a name and capabilities worth showing, and only
// one that has actually left has nothing. Falling straight to a bare node
// would throw away information the hub still holds.
func (s *Store) GraphNodeFor(aid string) AgentView {
	row := s.db.QueryRow(
		`SELECT a.aid, a.name, a.caps, a.summary, a.readme, a.pricing, a.guest_quota,
		        a.registered_at, a.last_seen_at,
		        COALESCE(AVG(r.rating),0), COUNT(r.interaction_id)
		   FROM agent a LEFT JOIN review r ON r.subject_aid = a.aid
		  WHERE a.aid=? GROUP BY a.aid`, aid)
	if av, err := scanAgent(row); err == nil {
		return av
	}
	// Not in the registry at all: it left, or it never banked here and is
	// only known through a review that crossed from a peer.
	var fedName string
	var raw []byte
	if err := s.db.QueryRow(`SELECT card FROM fed_card WHERE aid=?`, aid).Scan(&raw); err == nil {
		var card adp.AgentCard
		if json.Unmarshal(raw, &card) == nil {
			fedName = card.Name
		}
	}
	return AgentView{AID: aid, Name: fedName, Caps: []string{}, Registered: false}
}
