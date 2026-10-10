//go:build !no_federation

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// anet-hub clear (clear.go has what it is for).
func init() { subcommands["clear"] = runClear }

// clearReference is the note every discharge anet-hub clear signs carries
// in its statement id (aghub.IssueOwedSettlement adds the amount, the time
// and a random nonce, so no two statements share an id).
const clearReference = "anet-hub clear"

// runClear discharges amount of what this hub owes peerAID.
//
// In this order, each refusal leaving everything as it was: more than is
// due is refused before anything is signed (clear.over_due); the statement
// is signed and delivered; the peer's answer decides. Accepted (200), the
// due falls by amount (clear.ok). Refused by the peer, nothing changes
// here (clear.refused, naming the peer's reason code, or the HTTP status
// when what it sent is not shaped like one). No answer the hub can read — the peer unreachable,
// a proxy's error page, a reply cut off — and nobody here can tell whether
// the peer recorded it: nothing changes here, and the operator is told so
// (clear.unconfirmed). Sending another would be a second statement, applied
// on its own, so the sentence says to compare with the peer's operator
// first.
//
// The peer's endpoint is --peer-endpoint, or the peer's entry in this
// hub's federation.json when it is not given.
func runClear(c *console, data string, args []string) int {
	const use = "anet-hub clear <peer-aid> --amount N [--peer-endpoint URL]"
	fs, dataDir := newSubFlags("clear", data)
	amount := fs.Int64("amount", 0, "credits to discharge")
	endpoint := fs.String("peer-endpoint", "", "the peer hub's URL (default: its entry in federation.json)")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 1 || *amount <= 0 {
		return c.usage(use)
	}
	peer := pos[0]
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	due, err := store.DueTo(peer)
	if err != nil {
		return c.fail(err)
	}
	if *amount > due {
		return c.say("clear.over_due", map[string]string{"peer": peer, "m": num(due), "n": num(*amount)})
	}
	url := *endpoint
	if url == "" {
		if url, err = peerEndpointOf(*dataDir, peer); err != nil {
			return c.fail(err)
		}
		if url == "" {
			return c.usage(use)
		}
	}
	id, err := hubid.LoadOrIncept(*dataDir)
	if err != nil {
		return c.fail(err)
	}
	rec, err := store.IssueOwedSettlement(id.AID, peer, uint64(*amount), clearReference)
	if err != nil {
		return c.fail(err)
	}
	raw, err := rec.Marshal()
	if err != nil {
		return c.fail(err)
	}
	body, err := json.Marshal(aghub.ClearRequest{PeerAID: id.AID, Receipt: wire3.EncodeB64URL(raw)})
	if err != nil {
		return c.fail(err)
	}
	resp, err := federation.ClearAtPeer(context.Background(), id, peer, url, body)
	if err != nil {
		return c.say("clear.unconfirmed", map[string]string{"peer": peer})
	}
	defer resp.Body.Close()
	answer, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		var refusal struct {
			Reason string `json:"reason"`
		}
		if rerr == nil && json.Unmarshal(answer, &refusal) == nil && refusal.Reason != "" &&
			resp.StatusCode >= 400 && resp.StatusCode < 500 {
			// A hub's own refusal: the statement was not applied.
			return c.say("clear.refused", map[string]string{"peer": peer,
				"value": refusalValue(refusal.Reason, resp.StatusCode)})
		}
		return c.say("clear.unconfirmed", map[string]string{"peer": peer})
	}
	var ack aghub.ClearResponse
	if rerr != nil || json.Unmarshal(answer, &ack) != nil || ack.Peer != id.AID {
		// A 200 that is not the peer's acknowledgement says nothing about
		// whether it applied the statement.
		return c.say("clear.unconfirmed", map[string]string{"peer": peer})
	}
	// The statement's id is new, so a 200 is the peer applying it now,
	// never a repeat of an earlier one.
	if err := store.DischargeDue(peer, *amount); err != nil {
		if errors.Is(err, aghub.ErrOverDue) {
			// Another clear of the same debt finished in between.
			left, _ := store.DueTo(peer)
			return c.say("clear.over_due", map[string]string{"peer": peer, "m": num(left), "n": num(*amount)})
		}
		return c.fail(err)
	}
	left, err := store.DueTo(peer)
	if err != nil {
		return c.fail(err)
	}
	return c.say("clear.ok", map[string]string{"peer": peer, "n": num(*amount), "m": num(left)})
}

// refusalValue is what clear.refused shows of a peer's refusal: its reason
// when that is shaped like a reason code (core CORE-K19:
// ^[a-z][a-z0-9_]{0,29}$), else the HTTP status. The peer's own text is never
// put in front of the operator (ux UX-G2): a peer could otherwise write
// anything to the operator's terminal, control characters included.
func refusalValue(reason string, status int) string {
	if seal.ValidNoteReason(reason) {
		return reason
	}
	return strconv.Itoa(status)
}

// peerEndpointOf is the endpoint federation.json gives the peer hub aid, or
// "" when it lists no such peer.
func peerEndpointOf(dir, aid string) (string, error) {
	cfg, err := federation.LoadConfig(dir)
	if err != nil {
		return "", err
	}
	for _, p := range cfg.Peers {
		if p.AID == aid {
			return strings.TrimSpace(p.Endpoint), nil
		}
	}
	return "", nil
}
