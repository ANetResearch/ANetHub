package aghub

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// Delivery confirmations at the hub (p2p-receipts §2.4, §2.5, §3.2, §4.2;
// core §2.12.2, §2.16).
//
// A recipient that took an envelope from its mailbox and made its final
// decision about it hands the hub, with the ack of that row, the delivery
// confirmation its sender will ask for: a 16-byte handle and an 80-byte dack
// that only the two ends can compute or read. The hub keeps the pair in
// relay_dack for DAckTTL, keyed by the handle and holding nothing else: no
// recipient, no rid, no sender, no other time (DLV-ST-3, SI-2, SI-23). It
// never looks into a dack beyond its length (DLV-H-9).
//
// The sender asks, anonymously, with the rid this hub gave it when the
// envelope was queued and the handle (/relay/status): queued while the
// mailbox row is there, done with the dack once it is not and the handle is
// stored, unknown otherwise. An answer done shortens what is left of the
// row's time to DAckFetchedTTL. A sender whose envelope was queued at a peer
// hub (via_hub) asks this hub, and this hub asks that peer
// (/fed/v3/relay-status), signed as itself and carrying nothing of the
// sender (DLV-H-8).
//
// Nothing here is written to a log: no handle, no dack, no rid next to a
// recipient (DLV-H-6). What the operator sees is counters (DLV §2.8).

// The delivery confirmation constants of the hub (DLV-H-10, core Q-DLV-6).
// None of them is a flag.
const (
	// DAckTTL is how long a stored delivery confirmation is kept.
	DAckTTL = 7 * 24 * time.Hour
	// DAckFetchedTTL is the most a stored confirmation is kept once a
	// status check has answered it done.
	DAckFetchedTTL = 10 * time.Minute
	// MaxDAckRows bounds relay_dack: past it the rows that expire first
	// are evicted.
	MaxDAckRows = 2_000_000
	// MaxAckItems is the most items one /relay/ack takes: as many as one
	// /relay/poll page holds.
	MaxAckItems = MaxPollLimit
	// MaxStatusItems is the most items one status check takes.
	MaxStatusItems = 64
	// StatusBodyLimit bounds a status check's body.
	StatusBodyLimit = 16 << 10
	// StatusPeerTimeout bounds the status check this hub makes at a peer
	// hub for a sender (DLV-W-18).
	StatusPeerTimeout = 5 * time.Second
	// StatusPeerRetry is the Retry-After of home_unreachable when the peer
	// gave none.
	StatusPeerRetry = 10 * time.Second
)

// The status checks' buckets: per client address (clientIP: an IPv4
// address, an IPv6 /64) for /relay/status (DLV-H-5), per peer hub for
// /fed/v3/relay-status (DLV-W-19a).
var (
	rateRelayStatus    = relayRate{10, 50}
	rateFedRelayStatus = relayRate{100, 500}
)

// The answers of a status check (DLV §2.4.3).
const (
	RelayStatusQueued  = "queued"
	RelayStatusDone    = "done"
	RelayStatusUnknown = "unknown"
)

// relay_dack (DLV §3.2): exactly a handle, a dack and when it is deleted.
const (
	dackTable = `CREATE TABLE IF NOT EXISTS relay_dack (
	   handle BLOB PRIMARY KEY,
	   dack BLOB NOT NULL,
	   exp INTEGER NOT NULL
	 )`
	dackIndex = `CREATE INDEX IF NOT EXISTS idx_relay_dack_exp ON relay_dack(exp)`
)

// AckItem is one item of /relay/ack: a mailbox row the caller is done with,
// and, when it gives one, the delivery confirmation of that envelope
// (Handle of seal.HandleLen bytes and DAck of seal.DAckLen bytes, both or
// neither).
type AckItem struct {
	ID     int64
	Handle []byte
	DAck   []byte
}

// AckResult is what StoreDAcks did: Acked mailbox rows deleted, Stored
// confirmations written or overwritten, Evicted confirmations deleted to
// keep relay_dack within MaxDAckRows.
type AckResult struct {
	Acked, Stored, Evicted int
}

// dackState is what the store keeps in memory of relay_dack: its number of
// rows, once counted (under Store.mu), and the bound a test lowers.
type dackState struct {
	known bool
	rows  int64
	max   int64 // 0: MaxDAckRows
}

func (d *dackState) bound() int64 {
	if d.max > 0 {
		return d.max
	}
	return MaxDAckRows
}

// StoreDAcks is /relay/ack (DLV-H-3), in one transaction: it deletes the
// rows of toAID's mailbox the items name (relayAckTx) and, for each row this
// call deleted, stores the confirmation the first item naming it carries,
// if it carries one, for DAckTTL; a handle already stored has its dack and
// time replaced. The confirmation of an item whose row was not deleted here
// (somebody else's, acked before, never there) is dropped, and so is that
// of a later item naming the same row: one deleted row is at most one
// stored confirmation. Then, past MaxDAckRows, the rows that expire first
// are evicted.
func (s *Store) StoreDAcks(toAID string, items []AckItem) (AckResult, error) {
	if len(items) == 0 {
		return AckResult{}, nil
	}
	ids := make([]int64, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return AckResult{}, err
	}
	defer tx.Rollback()
	deleted, err := relayAckTx(tx, toAID, ids)
	if err != nil {
		return AckResult{}, err
	}
	res := AckResult{Acked: len(deleted)}
	exp := s.now().Add(DAckTTL).UnixMilli()
	used := map[int64]bool{}
	inserted := int64(0)
	for _, it := range items {
		if !deleted[it.ID] || used[it.ID] {
			continue
		}
		used[it.ID] = true
		if it.Handle == nil {
			continue
		}
		if len(it.Handle) != seal.HandleLen || len(it.DAck) != seal.DAckLen {
			return AckResult{}, fmt.Errorf("hub: a delivery confirmation of %d and %d bytes", len(it.Handle), len(it.DAck))
		}
		up, err := tx.Exec(`UPDATE relay_dack SET dack=?, exp=? WHERE handle=?`, it.DAck, exp, it.Handle)
		if err != nil {
			return AckResult{}, err
		}
		if n, _ := up.RowsAffected(); n == 0 {
			if _, err := tx.Exec(`INSERT INTO relay_dack(handle, dack, exp) VALUES(?,?,?)`, it.Handle, it.DAck, exp); err != nil {
				return AckResult{}, err
			}
			inserted++
		}
		res.Stored++
	}
	rows, evicted, err := s.boundDAcksTx(tx, inserted)
	if err != nil {
		return AckResult{}, err
	}
	res.Evicted = int(evicted)
	if err := tx.Commit(); err != nil {
		s.dack.known = false
		return AckResult{}, err
	}
	s.dack.known, s.dack.rows = true, rows
	return res, nil
}

// boundDAcksTx keeps relay_dack within its bound once inserted rows were
// added in tx (DLV-H-7): when the count kept says it is over, the table is
// counted (another process may have deleted rows), and what is over is
// deleted, the rows that expire first first. It returns the rows left and
// how many it deleted. The caller holds s.mu and sets s.dack once tx
// commits.
func (s *Store) boundDAcksTx(tx *sql.Tx, inserted int64) (rows, evicted int64, err error) {
	count := func() (int64, error) {
		var n int64
		err := tx.QueryRow(`SELECT COUNT(*) FROM relay_dack`).Scan(&n)
		return n, err
	}
	if s.dack.known {
		rows = s.dack.rows + inserted
	} else if rows, err = count(); err != nil {
		return 0, 0, err
	}
	bound := s.dack.bound()
	if rows <= bound {
		return rows, 0, nil
	}
	if rows, err = count(); err != nil || rows <= bound {
		return rows, 0, err
	}
	res, err := tx.Exec(`DELETE FROM relay_dack WHERE rowid IN
	                       (SELECT rowid FROM relay_dack ORDER BY exp, rowid LIMIT ?)`, rows-bound)
	if err != nil {
		return 0, 0, err
	}
	evicted, _ = res.RowsAffected()
	return rows - evicted, evicted, nil
}

// PurgeExpiredDAcks deletes the stored confirmations whose time is over
// (exp <= now) and returns how many it deleted (DLV-H-7). The relay janitor
// runs it in the same round as PurgeExpiredRelay.
func (s *Store) PurgeExpiredDAcks(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM relay_dack WHERE exp <= ?`, now.UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if s.dack.known {
		s.dack.rows = max(0, s.dack.rows-n)
	}
	return int(n), nil
}

// StatusItem is one item of a status check: the rid the sender was given
// and the handle of its confirmation, each of 16 bytes.
type StatusItem struct {
	RID, Handle []byte
}

// StatusResult is the answer to one StatusItem: RelayStatusQueued,
// RelayStatusDone with the stored DAck, or RelayStatusUnknown.
type StatusResult struct {
	State string
	DAck  []byte
}

// RelayStatus answers a status check item by item (DLV §2.4.3, DLV-H-4):
// queued while a mailbox row has the rid; else done, with the dack, when
// the handle is stored and its time is not over; else unknown. An item
// answered done has the time left to its row cut to DAckFetchedTTL, in the
// same transaction. The answer depends on nothing else (P4): not on who
// asks, not on the recipient of the row.
func (s *Store) RelayStatus(items []StatusItem) ([]StatusResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nowMS := s.now().UnixMilli()
	fetched := nowMS + DAckFetchedTTL.Milliseconds()
	out := make([]StatusResult, len(items))
	for i, it := range items {
		var one int
		switch err := tx.QueryRow(`SELECT 1 FROM relay_message WHERE rid=?`, it.RID).Scan(&one); {
		case err == nil:
			out[i] = StatusResult{State: RelayStatusQueued}
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return nil, err
		}
		var dack []byte
		switch err := tx.QueryRow(`SELECT dack FROM relay_dack WHERE handle=? AND exp>?`, it.Handle, nowMS).Scan(&dack); {
		case errors.Is(err, sql.ErrNoRows):
			out[i] = StatusResult{State: RelayStatusUnknown}
			continue
		case err != nil:
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE relay_dack SET exp=MIN(exp, ?) WHERE handle=?`, fetched, it.Handle); err != nil {
			return nil, err
		}
		out[i] = StatusResult{State: RelayStatusDone, DAck: dack}
	}
	return out, tx.Commit()
}

// ---- the wire (core §2.12.2) ----

// RelayStatusRequest is the /relay/status body: 1 to MaxStatusItems items,
// all with the same via_hub (absent for the envelopes this hub queued).
type RelayStatusRequest struct {
	Items []RelayStatusItem `json:"items"`
}

// RelayStatusItem is one item of a status check, as the sender sends it.
type RelayStatusItem struct {
	RID    string `json:"rid"`
	Handle string `json:"handle"`
	ViaHub string `json:"via_hub,omitempty"`
}

// RelayStatusResponse answers /relay/status and /fed/v3/relay-status: one
// result per item, in the order asked.
type RelayStatusResponse struct {
	Items []RelayStatusResult `json:"items"`
}

// RelayStatusResult is one answer: the state, and the dack when it is done.
type RelayStatusResult struct {
	State string `json:"state"`
	DAck  string `json:"dack,omitempty"`
}

// FedRelayStatusRequest is the /fed/v3/relay-status body: a status check
// without via_hub, which a peer hub sends for its sender.
type FedRelayStatusRequest struct {
	Items []FedRelayStatusItem `json:"items"`
}

// FedRelayStatusItem is one item a peer hub asks about.
type FedRelayStatusItem struct {
	RID    string `json:"rid"`
	Handle string `json:"handle"`
}

// The sentences of the delivery confirmation refusals (DLV §2.4.4).
const (
	sentenceBadStatusQuery    = "A status check takes 1 to 64 items with 16-byte rid and handle, all for one hub."
	sentenceStatusAnonymous   = "Status checks are anonymous: send them without X-ANet identity headers."
	sentenceStatusTooLarge    = "A status check body is at most 16 KiB."
	sentenceStatusRateLimited = "Too many status checks from this address; retry after the given seconds."
	sentenceStatusHomeDown    = "The recipient's hub did not answer; retry after the given seconds."
	sentenceFedStatusLimited  = "Too many status checks from your hub; retry after the given seconds."
)

// badAckItem is the error of a /relay/ack refused at item n (from 0; the
// item past the last for a list that is empty or too long).
func badAckItem(n int) wire3.Refusal {
	return wire3.Refusal{Reason: wire3.ReasonBadAckItem, Error: fmt.Sprintf(
		"Item %d: an id is required, handle (16 bytes) and dack (80 bytes) go together, and at most %d items are taken.",
		n, MaxAckItems)}
}

// decodeAckItems checks the items of a /relay/ack (DLV-W-14): 1 to
// MaxAckItems of them, each with an id, and a handle of seal.HandleLen bytes
// and a dack of seal.DAckLen bytes together or neither, in base64url. It
// returns them, or the index of the first item that is not one.
func decodeAckItems(req []RelayAckItem) ([]AckItem, int) {
	if len(req) == 0 {
		return nil, 0
	}
	if len(req) > MaxAckItems {
		return nil, MaxAckItems
	}
	out := make([]AckItem, len(req))
	for i, it := range req {
		if it.ID == nil || *it.ID <= 0 || (it.Handle == "") != (it.DAck == "") {
			return nil, i
		}
		out[i].ID = *it.ID
		if it.Handle == "" {
			continue
		}
		h, err := wire3.DecodeB64URLSize("handle", it.Handle, seal.HandleLen)
		if err != nil {
			return nil, i
		}
		d, err := wire3.DecodeB64URLSize("dack", it.DAck, seal.DAckLen)
		if err != nil {
			return nil, i
		}
		out[i].Handle, out[i].DAck = h, d
	}
	return out, -1
}

// decodeStatusItems checks the items of a status check (DLV-W-16 step 5):
// 1 to MaxStatusItems of them, each with a rid and a handle of 16 bytes in
// base64url, given by item.
func decodeStatusItems(n int, item func(i int) (rid, handle string)) ([]StatusItem, bool) {
	if n < 1 || n > MaxStatusItems {
		return nil, false
	}
	out := make([]StatusItem, n)
	for i := range out {
		rid, handle := item(i)
		r, err := wire3.DecodeB64URLSize("rid", rid, RIDLen)
		if err != nil {
			return nil, false
		}
		h, err := wire3.DecodeB64URLSize("handle", handle, seal.HandleLen)
		if err != nil {
			return nil, false
		}
		out[i] = StatusItem{RID: r, Handle: h}
	}
	return out, true
}

// encodeStatus is the wire answer of results.
func encodeStatus(results []StatusResult) RelayStatusResponse {
	out := RelayStatusResponse{Items: make([]RelayStatusResult, len(results))}
	for i, r := range results {
		out.Items[i].State = r.State
		if r.State == RelayStatusDone {
			out.Items[i].DAck = wire3.EncodeB64URL(r.DAck)
		}
	}
	return out
}

// decodePeerStatus reads a peer hub's answer to the status check of n items
// it was asked (/fed/v3/relay-status): exactly n results, each queued,
// unknown, or done with a dack of seal.DAckLen bytes. Anything else is not
// the contract's answer, and the caller tells its sender home_unreachable.
func decodePeerStatus(raw []byte, n int) ([]StatusResult, error) {
	var ans RelayStatusResponse
	if err := wire3.DecodeStrict(raw, &ans); err != nil {
		return nil, err
	}
	if len(ans.Items) != n {
		return nil, fmt.Errorf("hub: the peer answered %d items of %d", len(ans.Items), n)
	}
	out := make([]StatusResult, n)
	for i, it := range ans.Items {
		switch it.State {
		case RelayStatusQueued, RelayStatusUnknown:
			if it.DAck != "" {
				return nil, fmt.Errorf("hub: the peer answered %s with a dack", it.State)
			}
		case RelayStatusDone:
			d, err := wire3.DecodeB64URLSize("dack", it.DAck, seal.DAckLen)
			if err != nil {
				return nil, err
			}
			out[i].DAck = d
		default:
			return nil, errors.New("hub: the peer answered a state that is none of the three")
		}
		out[i].State = it.State
	}
	return out, nil
}

// ---- the server's half ----

// deliveryState is what the server keeps in memory for the status checks:
// their buckets, and the counters of DLV §2.8.
type deliveryState struct {
	// byAddr is each client address's bucket of /relay/status, byPeer
	// each peer hub's of /fed/v3/relay-status.
	byAddr, byPeer *bucketSet
	counters       deliveryCounters
}

func newDeliveryState(now func() time.Time) *deliveryState {
	return &deliveryState{byAddr: newBucketSet(now), byPeer: newBucketSet(now)}
}

// deliveryCounters are the hub's delivery confirmation counters (DLV
// §2.8). They count, and name nothing: no address, no AID, no handle.
type deliveryCounters struct {
	status, statusLimited, statusPeerError atomic.Int64
	stored, fetched, expired, evicted      atomic.Int64
	fedStatus, fedStatusLimited            atomic.Int64
}

// DeliveryCounters is the hub's delivery confirmation counters since the
// process started, by their names (DLV §2.8), for the operator:
// relay-status (status checks answered), relay-status-limited (refused by
// the address's bucket), relay-status-peer-error (answered
// home_unreachable), relay-dack-stored, relay-dack-fetched (items answered
// done), relay-dack-expired, relay-dack-evicted, fed-relay-status (peers'
// status checks answered) and fed-relay-status-limited.
func (s *Server) DeliveryCounters() map[string]int64 {
	c := &s.delivery.counters
	return map[string]int64{
		"relay-status": c.status.Load(), "relay-status-limited": c.statusLimited.Load(),
		"relay-status-peer-error": c.statusPeerError.Load(),
		"relay-dack-stored":       c.stored.Load(), "relay-dack-fetched": c.fetched.Load(),
		"relay-dack-expired": c.expired.Load(), "relay-dack-evicted": c.evicted.Load(),
		"fed-relay-status": c.fedStatus.Load(), "fed-relay-status-limited": c.fedStatusLimited.Load(),
	}
}

// countFetched counts the items of results answered done.
func (c *deliveryCounters) countFetched(results []StatusResult) {
	for _, r := range results {
		if r.State == RelayStatusDone {
			c.fetched.Add(1)
		}
	}
}

// answerStatus answers a status check for items, the envelopes of which
// were queued at via ("" or this hub's AID: here) (DLV-W-18): here, by
// RelayStatus; at a delivery peer, by asking that peer (askPeerStatus); at
// a hub that is not one, unknown for every item.
func (s *Server) answerStatus(ctx context.Context, w http.ResponseWriter, items []StatusItem, via string) {
	var results []StatusResult
	switch {
	case via == "" || via == s.hubAID:
		var err error
		if results, err = s.store.RelayStatus(items); err != nil {
			wire3.Internal(w, err)
			return
		}
	case s.fed != nil && s.fed.IsDeliveryPeer(via):
		var wait time.Duration
		if results, wait = s.askPeerStatus(ctx, via, items); results == nil {
			s.delivery.counters.statusPeerError.Add(1)
			wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonHomeUnreachable, RetryAfter: wait, Error: sentenceStatusHomeDown})
			return
		}
	default:
		results = make([]StatusResult, len(items))
		for i := range results {
			results[i].State = RelayStatusUnknown
		}
	}
	s.delivery.counters.status.Add(1)
	s.delivery.counters.countFetched(results)
	writeJSON(w, http.StatusOK, encodeStatus(results))
}

// statusAnswerLimit bounds a peer's answer to a status check: 64 dacks in
// base64url and their JSON.
const statusAnswerLimit = 64 << 10

// askPeerStatus asks the peer hub for the items (/fed/v3/relay-status),
// signed as this hub, within StatusPeerTimeout. It returns the peer's
// answer, or nil and the Retry-After to tell the sender when the peer did
// not give one this hub can read: no answer, an answer that is not 200, or
// a 200 that is not the contract's (DLV-W-18). Never unknown in its place:
// the peer may hold the envelope.
func (s *Server) askPeerStatus(ctx context.Context, peer string, items []StatusItem) ([]StatusResult, time.Duration) {
	req := FedRelayStatusRequest{Items: make([]FedRelayStatusItem, len(items))}
	for i, it := range items {
		req.Items[i] = FedRelayStatusItem{RID: wire3.EncodeB64URL(it.RID), Handle: wire3.EncodeB64URL(it.Handle)}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, StatusPeerRetry
	}
	ctx, cancel := context.WithTimeout(ctx, StatusPeerTimeout)
	defer cancel()
	resp, err := s.fed.RelayStatus(ctx, peer, body)
	if err != nil {
		return nil, StatusPeerRetry
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, statusAnswerLimit))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, passedRetryAfter(resp, StatusPeerRetry)
	}
	results, err := decodePeerStatus(raw, len(items))
	if err != nil {
		return nil, passedRetryAfter(resp, StatusPeerRetry)
	}
	return results, 0
}

// FedStatusEmpty reports, without taking a token, whether the status
// bucket of the peer hub aid is empty, and how long until it is not
// (federation authPeer's gate of /fed/v3/relay-status, before the body is
// read).
func (s *Server) FedStatusEmpty(aid string) (bool, time.Duration) {
	empty, wait := s.delivery.byPeer.peek(aid, rateFedRelayStatus)
	if empty {
		s.delivery.counters.fedStatusLimited.Add(1)
	}
	return empty, wait
}

// ServeFedRelayStatus answers /fed/v3/relay-status for a request the peer
// hub peer signed (federation authPeer has checked the peer, the signature
// and RC1), whose body is body (DLV-W-19, DLV-H-8): the peer's bucket
// (429 rate_limited), the body decoded strictly (a via_hub is a member this
// route does not take: 400 bad_request), the items (400 bad_status_query),
// and the answer of this hub's own mailbox and confirmations, as for
// /relay/status; always 200 once it is answered.
func (s *Server) ServeFedRelayStatus(w http.ResponseWriter, peer string, body []byte) {
	if ok, wait := s.delivery.byPeer.take(peer, rateFedRelayStatus); !ok {
		s.delivery.counters.fedStatusLimited.Add(1)
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonRateLimited, RetryAfter: wait, Error: sentenceFedStatusLimited})
		return
	}
	var req FedRelayStatusRequest
	if err := wire3.DecodeStrict(body, &req); err != nil {
		wire3.RefuseDecode(w, err)
		return
	}
	items, ok := decodeStatusItems(len(req.Items), func(i int) (string, string) { return req.Items[i].RID, req.Items[i].Handle })
	if !ok {
		wire3.Write(w, wire3.Refusal{Reason: wire3.ReasonBadStatusQuery, Error: sentenceBadStatusQuery})
		return
	}
	results, err := s.store.RelayStatus(items)
	if err != nil {
		wire3.Internal(w, err)
		return
	}
	s.delivery.counters.fedStatus.Add(1)
	s.delivery.counters.countFetched(results)
	writeJSON(w, http.StatusOK, encodeStatus(results))
}
