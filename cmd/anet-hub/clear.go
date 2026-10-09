package main

// What this hub owes its peers, and paying it (hub-payment-privacy PAY-U1,
// PAY-U2):
//
//	anet-hub due [--json]
//	anet-hub clear <peer-aid> --amount N [--peer-endpoint URL]
//
// A peer that forwarded a settlement for its own agent (/fed/v3/settle) is
// owed what left this ledger (hub_due, by peer). How the operators pay each
// other is outside this software — an invoice, a transfer, a standing
// arrangement. Once paid, clear signs this hub's statement that the debt is
// discharged and delivers it to the peer (/fed/v3/clear, signed for
// fed_clear); only after the peer accepted it does this hub reduce what it
// records as due. Both open the hub's database beside a running hub; clear
// is in clear_fed.go, since a hub built without federation (-tags
// no_federation) has no peer to owe or to pay.

import "encoding/json"

// dueEntry is one line of anet-hub due --json.
type dueEntry struct {
	Peer   string `json:"peer"`
	Amount int64  `json:"amount"`
}

// runDue lists what this hub owes, one peer hub per line: its AID and the
// credits, tab-separated (data, like anet-hub supply, not sentences).
// Nothing owed prints nothing.
func runDue(c *console, data string, args []string) int {
	const use = "anet-hub due [--json]"
	fs, dataDir := newSubFlags("due", data)
	asJSON := fs.Bool("json", false, "print as JSON")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 0 {
		return c.usage(use)
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	due, err := store.Due()
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		out := []dueEntry{}
		for _, kv := range sortedAmounts(due) {
			out = append(out, dueEntry{Peer: kv.key, Amount: kv.n})
		}
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return c.fail(err)
		}
		return 0
	}
	for _, kv := range sortedAmounts(due) {
		c.out.Write([]byte(kv.key + "\t" + num(kv.n) + "\n"))
	}
	return 0
}
