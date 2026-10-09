package aghub

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/seal"
)

// Witness notices (KEL §2.5, H-10 to H-14; core §2.6, L18).
//
// An agent's KEL names, in the key 9 of its last rot, the hub that is its
// witness: the hub it registered at. That hub states, for each agent it
// witnesses, which event its key history ends at: a notice, signed with the
// hub's identity (identity.SignNotice), that says "the KEL I hold for aid
// ends at seq, event head, as I observed it at observed_at". A sender
// carries its latest notice in every message, and a recipient takes the
// message only when the notice is fresh (identity.NoticeMaxAge) and about
// the tip of the KEL the message carries. A thief of an old key therefore
// speaks for the agent only while a notice signed before the rotation is
// fresh. Users read it as "key confirmation".
//
// This hub signs a notice for an AID only when all of these hold (H-10):
//
//  1. the AID is registered here (not only a tombstone in departed_kel);
//  2. it is admitted, and its admission is not revoked. Here that is the
//     same as 1: an AID registers only once admitted, and revoking an
//     admission deregisters it (hub-payment-privacy PAY-O1);
//  3. the tip of the KEL this hub holds is an agent's (toad 1) and names
//     this hub as its witness;
//  4. that tip is not a dip;
//  5. the AID is not in quarantine after a restore from backup (H-20).
//
// and never for this hub's own AID (H-14). The seq and head are those of
// the KEL this hub holds, whatever a request says. When it signs none, an
// answer that would carry the notice carries key_state_notice_error
// instead (H-13): not_admitted (1, 2), not_witness (3, 4) or quarantine (5).
//
// A notice is kept in notice_cache under the AID with the seq and head it
// states, and reused while it is at most NoticeReissue old, whoever asks
// (H-11): the agent's poll and registration, the directory, the registry
// and the federation card stream all carry the same one. A KEL change, a
// deregistration and (KEL-6) a quarantine invalidate it in the transaction
// that makes them (core §2.16, KEL S-3). The table is left out of every
// backup (core §2.16): a restored hub signs afresh.
//
// The hub process keeps the notice of every agent that has a key set (and
// so a directory entry and a place in the registry) at most NoticeReissue
// old (RunNoticeRefresher), so a sender who meets an agent for the first
// time finds a fresh notice whether or not the agent itself polled lately
// (KEL D-26); a notice that changes changes the agent's directory entry in
// the same transaction (sealed-sender SSR-H17).

// NoticeReissue is how long a notice this hub signed is served again before
// it signs a new one (KEL §2.12). A code constant, not configuration.
const NoticeReissue = 10 * time.Minute

// The values of key_state_notice_error (KEL H-13; core §2.15.5): why an
// answer carries no notice.
const (
	NoticeErrQuarantine  = "quarantine"   // H-10 5: restored from backup, not yet released
	NoticeErrNotAdmitted = "not_admitted" // H-10 1, 2
	NoticeErrNotWitness  = "not_witness"  // H-10 3, 4; and this hub's own AID (H-14)
)

// noticeRefreshEvery is how often the hub process looks for notices that
// RunNoticeRefresher renews.
const noticeRefreshEvery = time.Minute

// noticeSchema is the notice cache (KEL S-3, core §2.16): one row per AID,
// the notice (NoticeWire bytes) and the seq, head and observed_at (unix ms)
// it states.
func noticeSchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS notice_cache (
		   aid TEXT PRIMARY KEY,
		   seq INTEGER NOT NULL,
		   head TEXT NOT NULL,
		   observed_at INTEGER NOT NULL,
		   blob BLOB NOT NULL
		 )`,
	}
}

// noticeJudgement is what this hub may state about an AID now: why it signs
// no notice (one of the NoticeErr values), or the tip it would state and the
// cached notice when that is still to be served.
type noticeJudgement struct {
	why   string
	tip   identity.KeyState
	fresh []byte // the cached notice of tip, at most NoticeReissue old
}

// judgeNotice applies H-10 and H-11 to aid at now, reading through q.
func (s *Store) judgeNotice(q rowQuerier, aid string, now time.Time) (noticeJudgement, error) {
	if s.hubKey == nil || aid == s.hubAID {
		// A hub without an identity witnesses nobody, and a hub does not
		// witness itself (H-14).
		return noticeJudgement{why: NoticeErrNotWitness}, nil
	}
	var kelBytes, blob []byte
	var seq, observed sql.NullInt64
	var head sql.NullString
	err := q.QueryRow(`SELECT a.kel, n.seq, n.head, n.observed_at, n.blob
	    FROM agent a LEFT JOIN notice_cache n ON n.aid = a.aid WHERE a.aid = ?`, aid).
		Scan(&kelBytes, &seq, &head, &observed, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return noticeJudgement{why: NoticeErrNotAdmitted}, nil
	}
	if err != nil {
		return noticeJudgement{}, err
	}
	// v030-todo(KEL-6): H-10 5, an AID in quarantine after a restore
	// (restore_state) is answered NoticeErrQuarantine here.
	kel, err := seal.ParseKEL(kelBytes)
	if err != nil {
		// Stored before /register capped KELs: no sender accepts it, and
		// this hub states nothing about it.
		return noticeJudgement{why: NoticeErrNotWitness}, nil
	}
	states, err := identity.Replay(kel)
	if err != nil {
		return noticeJudgement{}, fmt.Errorf("hub: the stored key history of %s does not replay: %w", aid, err)
	}
	tip := states[len(states)-1]
	if tip.AID != aid || tip.Toad != identity.ToadAgent || tip.Witness != s.hubAID ||
		tip.Status == identity.StatusDeactivated {
		return noticeJudgement{why: NoticeErrNotWitness}, nil
	}
	j := noticeJudgement{tip: tip}
	if blob != nil && seq.Int64 == int64(tip.KeyStateSeq) && head.String == tip.LastEventID {
		// A notice observed after now (the clock stepped back) is not
		// served: a reader would take it for one from the future.
		if age := now.UnixMilli() - observed.Int64; age >= 0 && age <= NoticeReissue.Milliseconds() {
			j.fresh = blob
		}
	}
	return j, nil
}

// NoticeFor is the witness notice this hub states now about aid's key
// history (NoticeWire bytes), or, when it states none, why: one of the
// NoticeErr values. A notice cached for the tip and at most NoticeReissue old
// is served again; otherwise a new one is signed, cached, and the agent's
// directory entry, which carries it, is recomputed in the same transaction.
func (s *Store) NoticeFor(aid string) (notice []byte, why string, err error) {
	now := s.now()
	j, err := s.judgeNotice(s.db, aid, now)
	if err != nil || j.why != "" || j.fresh != nil {
		return j.fresh, j.why, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	notice, why, issued, err := s.issueNoticeTx(tx, aid, now)
	if err != nil || !issued {
		return notice, why, err
	}
	if err := s.refreshDirTx(tx, aid); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return notice, "", nil
}

// issueNoticeTx is NoticeFor's write: judged again inside tx (a KEL change
// or a deregistration may have committed since the caller looked), then, if
// no cached notice is fresh, a new one signed at now and cached. issued
// reports a new notice.
func (s *Store) issueNoticeTx(tx *sql.Tx, aid string, now time.Time) (notice []byte, why string, issued bool, err error) {
	j, err := s.judgeNotice(tx, aid, now)
	if err != nil || j.why != "" || j.fresh != nil {
		return j.fresh, j.why, false, err
	}
	at := now.UnixMilli()
	notice, err = identity.SignNotice(s.hubKey, identity.NoticeBody{
		AID: aid, Seq: j.tip.KeyStateSeq, Head: j.tip.LastEventID, ObservedAt: uint64(at)})
	if err != nil {
		return nil, "", false, fmt.Errorf("hub: signing the witness notice of %s: %w", aid, err)
	}
	if _, err := tx.Exec(`INSERT INTO notice_cache(aid, seq, head, observed_at, blob) VALUES(?,?,?,?,?)
	    ON CONFLICT(aid) DO UPDATE SET seq=excluded.seq, head=excluded.head,
	      observed_at=excluded.observed_at, blob=excluded.blob`,
		aid, int64(j.tip.KeyStateSeq), j.tip.LastEventID, at, notice); err != nil {
		return nil, "", false, err
	}
	return notice, "", true, nil
}

// forgetNoticeTx drops aid's cached notice in tx: its KEL changed (H-2), or
// whether this hub may state it changed (KEL S-3). The next request signs a
// new one, or answers why it cannot.
func forgetNoticeTx(tx *sql.Tx, aid string) error {
	_, err := tx.Exec(`DELETE FROM notice_cache WHERE aid = ?`, aid)
	return err
}

// cachedNoticeOf is the notice cached for aid when it states the tip of
// kel (the key history the caller holds for aid, as stored), else nil. It
// signs nothing: it is what the directory entry, the registry and the
// federation card stream carry (NoticeFor and RunNoticeRefresher keep it
// fresh).
func cachedNoticeOf(q rowQuerier, aid string, kel []byte) ([]byte, error) {
	var seq int64
	var head string
	var blob []byte
	err := q.QueryRow(`SELECT seq, head, blob FROM notice_cache WHERE aid = ?`, aid).Scan(&seq, &head, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if tseq, thead, ok := kelTip(kel); !ok || tseq != uint64(seq) || thead != head {
		// Written for another tip: a KEL change that did not drop it
		// (forgetNoticeTx) is a bug, and a reader would refuse the notice
		// anyway (witness-mismatch).
		return nil, nil
	}
	return blob, nil
}

// noticeOfTip is notice when it is a notice about the tip of kel (both as
// a listing holds them), else nil: what a registry entry may carry.
func noticeOfTip(kel, notice []byte) []byte {
	if len(notice) == 0 {
		return nil
	}
	body, _, err := identity.DecodeNotice(notice)
	if err != nil {
		return nil
	}
	if seq, head, ok := kelTip(kel); !ok || body.Seq != seq || body.Head != head {
		return nil
	}
	return notice
}

// kelTip is the seq and event id of the last event of the stored key
// history kel, read without replaying it (it was verified when stored).
func kelTip(kel []byte) (seq uint64, head string, ok bool) {
	events, err := identity.UnmarshalKEL(kel)
	if err != nil || len(events) == 0 {
		return 0, "", false
	}
	last := events[len(events)-1]
	return last.Event.Seq, last.EventID, true
}

// RunNoticeRefresher renews, once at start and then every minute until ctx
// ends, the notice of every agent registered here that has a key set, when
// its cached notice is missing or more than NoticeReissue old
// (RefreshNotices). Only the hub process runs it.
func (s *Store) RunNoticeRefresher(ctx context.Context) {
	t := time.NewTicker(noticeRefreshEvery)
	defer t.Stop()
	for {
		if _, err := s.RefreshNotices(ctx); err != nil {
			log.Printf("hub: renewing witness notices: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshNotices signs a new notice (NoticeFor) for every agent registered
// here with a key set whose cached notice is missing or more than
// NoticeReissue old, and returns how many it signed. An agent this hub is
// not the witness of is looked at and left without one.
//
// The agents with a key set are those a sender can find in the directory
// and the registry: what they carry is then at most NoticeReissue and a
// minute old, whether or not the agent polled lately.
func (s *Store) RefreshNotices(ctx context.Context) (int, error) {
	now := s.now()
	rows, err := s.db.Query(`SELECT a.aid FROM agent a
	    JOIN agent_keys k ON k.aid = a.aid
	    LEFT JOIN notice_cache n ON n.aid = a.aid
	   WHERE n.aid IS NULL OR n.observed_at < ? OR n.observed_at > ?`,
		now.Add(-NoticeReissue).UnixMilli(), now.UnixMilli())
	if err != nil {
		return 0, err
	}
	var due []string
	for rows.Next() {
		var aid string
		if err := rows.Scan(&aid); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, aid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	signed := 0
	for _, aid := range due {
		if ctx.Err() != nil {
			return signed, nil
		}
		before, _ := cachedNoticeRow(s.db, aid)
		notice, _, err := s.NoticeFor(aid)
		if err != nil {
			return signed, err
		}
		if notice != nil && !bytes.Equal(notice, before) {
			signed++
		}
	}
	return signed, nil
}

// cachedNoticeRow is the notice cached for aid, whatever tip it states.
func cachedNoticeRow(q rowQuerier, aid string) ([]byte, error) {
	var blob []byte
	err := q.QueryRow(`SELECT blob FROM notice_cache WHERE aid = ?`, aid).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return blob, err
}
