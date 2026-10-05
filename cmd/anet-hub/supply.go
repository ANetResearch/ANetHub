package main

// anet-hub supply (hub-payment-privacy PAY-S7): where this hub's supply
// stands, read from the database beside a running hub, not over HTTP. One
// line per value, tab-separated like the admission list and anet-hub quota:
// they are data an operator compares with the public record, not sentences.
//
//	latest_epoch          <seq> <from_day> <to_day> <outstanding> <root>, or none
//	outstanding           what the hub owes its users now: issued − redeemed
//	issued, redeemed      the running totals
//	events_since_publish  supply events since the latest epoch
//	due <payee> <n>       one line per obligation to a peer's agent
//	owed <peer> <n>       one line per peer hub that owes this one

import (
	"sort"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

func runSupply(c *console, data string, args []string) int {
	const use = "anet-hub supply"
	fs, dataDir := newSubFlags("supply", data)
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 0 {
		return c.usage(use)
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	id, err := hubid.LoadOrIncept(*dataDir)
	if err != nil {
		return c.fail(err)
	}
	sup, err := store.Supply(id.AID)
	if err != nil {
		return c.fail(err)
	}
	due, err := store.Due()
	if err != nil {
		return c.fail(err)
	}
	owed, err := store.OwedByPeer()
	if err != nil {
		return c.fail(err)
	}
	line := func(fields ...string) { c.out.Write([]byte(strings.Join(fields, "\t") + "\n")) }
	u := func(n uint64) string { return strconv.FormatUint(n, 10) }
	if e := sup.Latest; e != nil {
		line("latest_epoch", u(e.Seq), u(e.FromDay), u(e.ToDay), u(e.Outstanding), e.Root)
	} else {
		line("latest_epoch", "none")
	}
	line("outstanding", num(sup.Outstanding))
	line("issued", num(sup.Issued))
	line("redeemed", num(sup.Redeemed))
	line("events_since_publish", num(sup.EventsSincePublish))
	for _, kv := range sortedAmounts(due) {
		line("due", kv.key, num(kv.n))
	}
	for _, kv := range sortedAmounts(owed) {
		line("owed", kv.key, num(kv.n))
	}
	return 0
}

type keyAmount struct {
	key string
	n   int64
}

// sortedAmounts is m in key order.
func sortedAmounts(m map[string]int64) []keyAmount {
	out := make([]keyAmount, 0, len(m))
	for k, n := range m {
		out = append(out, keyAmount{k, n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}
