package main

// anet-hub redemptions [--json] (hub-payment-privacy PAY-U2): the redemptions
// the operator has to settle outside this software, read from the database
// beside a running hub (the hub's WAL database, so no stop is needed). They
// are every redemption of the ledger window, oldest first; older ones are
// deleted (PAY-L2), so each has to be handled within 14 days (PAY-L7), which
// the last line says:
//
//	<at> <aid> <amount> <reference> <auth_id>   one line per redemption, tab-separated
//	redemptions.summary                         the count and the sum, a sentence
//
// The lines are data, like anet-hub supply's and the admission list's, not
// sentences. The reference is the redeemer's own text, so it is printed
// quoted (Go syntax): a tab, a line break or a terminal control sequence in
// it can neither break the line nor reach the operator's terminal.
//
// --json prints {redemptions: [{at, aid, amount, reference, auth_id}],
// count, sum, window_days} instead, and no sentence.

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetHub/internal/aghub"
)

// redemptionEntry is one redemption as anet-hub redemptions --json lists it.
type redemptionEntry struct {
	At        string `json:"at"`
	AID       string `json:"aid"`
	Amount    uint64 `json:"amount"`
	Reference string `json:"reference"`
	AuthID    string `json:"auth_id"`
	// StoredAmount is set, and Amount 0, only for a row a hub wrote before
	// the amount range check (aghub.Redemption).
	StoredAmount int64 `json:"stored_amount,omitempty"`
}

// redemptionsJSON is the whole of anet-hub redemptions --json.
type redemptionsJSON struct {
	Redemptions []redemptionEntry `json:"redemptions"`
	Count       int               `json:"count"`
	Sum         uint64            `json:"sum"`
	WindowDays  uint              `json:"window_days"`
}

func runRedemptions(c *console, data string, args []string) int {
	const use = "anet-hub redemptions [--json]"
	fs, dataDir := newSubFlags("redemptions", data)
	asJSON := fs.Bool("json", false, "print as JSON")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 0 {
		return c.usage(use)
	}
	store, code := openHubData(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	win, err := store.WindowRedemptions()
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		out := redemptionsJSON{Redemptions: []redemptionEntry{}, Count: win.Total, Sum: win.Sum,
			WindowDays: aghub.LedgerWindowDays}
		for _, r := range win.Redemptions {
			out.Redemptions = append(out.Redemptions, redemptionEntry{At: r.At, AID: r.AID, Amount: r.Amount,
				Reference: r.Reference, AuthID: r.AuthID, StoredAmount: r.StoredAmount})
		}
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return c.fail(err)
		}
		return 0
	}
	for _, r := range win.Redemptions {
		amount := strconv.FormatUint(r.Amount, 10)
		if r.Amount == 0 && r.StoredAmount != 0 {
			amount = strconv.FormatInt(r.StoredAmount, 10)
		}
		c.out.Write([]byte(strings.Join([]string{r.At, r.AID, amount, strconv.Quote(r.Reference), r.AuthID}, "\t") + "\n"))
	}
	return c.say("redemptions.summary", map[string]string{
		"n": num(win.Total), "m": strconv.FormatUint(win.Sum, 10)})
}
