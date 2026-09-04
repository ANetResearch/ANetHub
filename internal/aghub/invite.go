package aghub

// invite.go — admission control for registration.
//
// The hub verifies that a registration's key history derives the AID it
// claims and that the caller can sign a challenge. That proves the caller
// controls the identity; it says nothing about whether this hub wanted
// them. Until now there was nothing more to say: anybody could register.
//
// Open registration is still the DEFAULT and stays that way. A hub that
// never configures this behaves exactly as before, because turning
// admission on for everyone by accident would lock out every node already
// registered on every deployment that upgrades.
//
// What admission gates is deliberately narrow: the FIRST registration of
// an AID this hub does not know. An AID already in the registry
// re-registers without an invite — it re-registers on every restart and
// whenever its capability list changes, and requiring a token there would
// mean an operator who turns admission on has just broken every node they
// already admitted. The consequence, stated plainly: turning admission on
// does not retroactively remove anybody. It decides who may arrive next.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// InvitePrefix marks a string as an invite so a human can recognise one
// in a chat log or a terminal and not paste it somewhere public.
const InvitePrefix = "anetinv_"

// Errors a caller can tell apart. The registration handler turns each
// into a message that says what to do next: "ask for an invite" and "this
// invite is used up" send an operator to two different places.
var (
	ErrInviteRequired = errors.New("this hub admits new agents by invite only")
	ErrInviteUnknown  = errors.New("no such invite")
	ErrInviteRevoked  = errors.New("this invite has been revoked")
	ErrInviteExpired  = errors.New("this invite has expired")
	ErrInviteUsedUp   = errors.New("this invite has no uses left")
	// ErrInviteAlreadyRevoked separates "there is no such invite" from
	// "that invite is already closed". They call for different actions:
	// the first says the id is wrong and the gate is still open, the
	// second says the gate is shut and there is nothing to do. Reporting
	// both as ErrInviteUnknown meant a mistyped id and a repeated
	// revocation produced the same output, so an operator who had just
	// been told an invite leaked could not tell whether they had closed
	// it or typed it wrong.
	ErrInviteAlreadyRevoked = errors.New("this invite was already revoked")
)

// InviteView is an invite as an operator reads it back.
//
// It carries no token. The token exists in plaintext exactly once, in the
// output of the call that minted it; the hub keeps only its digest, so a
// copy of hub.db is not a bag of working invitations.
type InviteView struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	MaxUses   int    `json:"max_uses"` // 0 = unlimited
	Uses      int    `json:"uses"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds, 0 = never
	RevokedAt int64  `json:"revoked_at"` // unix seconds, 0 = live
	CreatedAt int64  `json:"created_at"`
	// Redeemers is who used it, newest first. An invite that was shared
	// more widely than intended is visible here before it is visible in
	// the agent list.
	Redeemers []InviteUse `json:"redeemers,omitempty"`
}

type InviteUse struct {
	AID string `json:"aid"`
	At  int64  `json:"at"`
}

func (s *Store) migrateInvites() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS invite (
		   id TEXT PRIMARY KEY,
		   token_sha256 TEXT NOT NULL UNIQUE,
		   label TEXT NOT NULL DEFAULT '',
		   max_uses INTEGER NOT NULL DEFAULT 0,
		   uses INTEGER NOT NULL DEFAULT 0,
		   expires_at INTEGER NOT NULL DEFAULT 0,
		   revoked_at INTEGER NOT NULL DEFAULT 0,
		   created_at INTEGER NOT NULL
		 )`,
		// Who came in on which invite. Kept separately from the counter
		// because "it has been used 4 times" and "these four agents came
		// in on it" answer different questions, and only the second one
		// is any use when an invite has leaked.
		`CREATE TABLE IF NOT EXISTS invite_use (
		   invite_id TEXT NOT NULL,
		   aid TEXT NOT NULL,
		   at INTEGER NOT NULL,
		   PRIMARY KEY (invite_id, aid)
		 )`,
		`CREATE TABLE IF NOT EXISTS hub_setting (
		   k TEXT PRIMARY KEY,
		   v TEXT NOT NULL
		 )`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate invites: %w", err)
		}
	}
	return nil
}

// InviteRequired reports whether new agents need an invite.
//
// Absent means false. A hub that has never been told behaves the way it
// behaved before this file existed, which is what makes upgrading safe.
func (s *Store) InviteRequired() bool {
	var v string
	err := s.db.QueryRow(`SELECT v FROM hub_setting WHERE k='require_invite'`).Scan(&v)
	if err != nil {
		return false
	}
	return v == "1"
}

// SetInviteRequired turns admission on or off.
func (s *Store) SetInviteRequired(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	_, err := s.db.Exec(
		`INSERT INTO hub_setting(k,v) VALUES('require_invite',?)
		 ON CONFLICT(k) DO UPDATE SET v=excluded.v`, v)
	return err
}

// NewInvite mints one and returns the token, which is the only time the
// token exists outside the caller's hands.
//
// maxUses 0 means unlimited and ttl 0 means no expiry. Both are allowed
// because both are sometimes what an operator wants — a standing invite
// for a team, a one-shot for a single board — and refusing the open-ended
// case would just push them to mint a fresh unlimited one every week.
func (s *Store) NewInvite(label string, maxUses int, ttl time.Duration) (token string, v InviteView, err error) {
	if maxUses < 0 {
		return "", InviteView{}, fmt.Errorf("max_uses cannot be negative")
	}
	// A negative ttl is a typo, and the tempting reading of it — "not a
	// positive duration, so no expiry" — turns that typo into an invite
	// that never expires. Refused instead.
	if ttl < 0 {
		return "", InviteView{}, fmt.Errorf("ttl cannot be negative (0 means no expiry)")
	}
	idb := make([]byte, 5)
	secret := make([]byte, 20)
	if _, err = rand.Read(idb); err != nil {
		return "", InviteView{}, err
	}
	if _, err = rand.Read(secret); err != nil {
		return "", InviteView{}, err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	id := strings.ToLower(enc.EncodeToString(idb))
	token = InvitePrefix + strings.ToLower(enc.EncodeToString(secret))

	now := time.Now().Unix()
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	if _, err = s.db.Exec(
		`INSERT INTO invite(id,token_sha256,label,max_uses,uses,expires_at,revoked_at,created_at)
		 VALUES(?,?,?,?,0,?,0,?)`,
		id, hashInvite(token), label, maxUses, exp, now); err != nil {
		return "", InviteView{}, err
	}
	return token, InviteView{
		ID: id, Label: label, MaxUses: maxUses, ExpiresAt: exp, CreatedAt: now,
	}, nil
}

// RevokeInvite stops an invite being redeemed again. Agents already
// admitted on it stay — this is a gate, not a membership list.
//
// Revoking an already-revoked invite reports ErrInviteAlreadyRevoked and
// leaves the first revocation timestamp alone. That timestamp is the only
// record of when the gate closed, and an operator re-running the command
// must not be able to move it forward past the moment somebody was let
// in.
func (s *Store) RevokeInvite(id string) error {
	// The WHERE clause excludes rows that are already revoked, which is
	// what keeps the timestamp stable — and is also why zero rows
	// affected has two possible causes.
	res, err := s.db.Exec(
		`UPDATE invite SET revoked_at=? WHERE id=? AND revoked_at=0`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// Second read to tell the two causes apart. The cost is one extra
	// query, paid only on the path that changed nothing; the happy path
	// is still a single statement. A row here is necessarily a revoked
	// row, because the UPDATE above would have taken a live one.
	var revokedAt int64
	err = s.db.QueryRow(`SELECT revoked_at FROM invite WHERE id=?`, id).Scan(&revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInviteUnknown
	}
	if err != nil {
		return err
	}
	return ErrInviteAlreadyRevoked
}

// Invites lists them, newest first, each with who redeemed it.
func (s *Store) Invites() ([]InviteView, error) {
	rows, err := s.db.Query(
		`SELECT id,label,max_uses,uses,expires_at,revoked_at,created_at
		   FROM invite ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InviteView
	for rows.Next() {
		var v InviteView
		if err := rows.Scan(&v.ID, &v.Label, &v.MaxUses, &v.Uses,
			&v.ExpiresAt, &v.RevokedAt, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		ur, err := s.db.Query(`SELECT aid,at FROM invite_use WHERE invite_id=? ORDER BY at DESC`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for ur.Next() {
			var u InviteUse
			if err := ur.Scan(&u.AID, &u.At); err != nil {
				ur.Close()
				return nil, err
			}
			out[i].Redeemers = append(out[i].Redeemers, u)
		}
		ur.Close()
	}
	return out, nil
}

// RedeemInvite consumes one use for aid, or explains why it cannot.
//
// The whole check and the increment happen in one transaction, so two
// registrations racing for the last use of an invite cannot both win. An
// invite with max_uses 1 admits one agent.
//
// Redeeming the same invite twice for the SAME aid is not a second use:
// a node that registers, is deleted by an operator and registers again
// should not need a fresh token, and a retried request that lost its
// response should not burn a use. The use row is keyed on
// (invite, aid) and the counter follows it.
func (s *Store) RedeemInvite(token, aid string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInviteRequired
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var id string
	var maxUses, uses int
	var expiresAt, revokedAt int64
	err = tx.QueryRow(
		`SELECT id,max_uses,uses,expires_at,revoked_at FROM invite WHERE token_sha256=?`,
		hashInvite(token)).Scan(&id, &maxUses, &uses, &expiresAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInviteUnknown
	}
	if err != nil {
		return err
	}
	if revokedAt != 0 {
		return ErrInviteRevoked
	}
	now := time.Now().Unix()
	if expiresAt != 0 && now > expiresAt {
		return ErrInviteExpired
	}

	var already int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM invite_use WHERE invite_id=? AND aid=?`, id, aid).Scan(&already); err != nil {
		return err
	}
	if already == 0 {
		if maxUses > 0 && uses >= maxUses {
			return ErrInviteUsedUp
		}
		if _, err := tx.Exec(
			`INSERT INTO invite_use(invite_id,aid,at) VALUES(?,?,?)`, id, aid, now); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE invite SET uses=uses+1 WHERE id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func hashInvite(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}
