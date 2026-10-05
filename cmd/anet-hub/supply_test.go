//go:build !no_federation

package main

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// makeEpochDue moves the last published day of the hub in dir back eight
// days, so PublishDue closes an epoch now, as it would a week after the
// last one. The hub must have had a supply event.
func makeEpochDue(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "hub.db")+"?_pragma=busy_timeout(15000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE supply_totals SET last_to_day = ? WHERE id = 1 AND last_to_day IS NOT NULL`,
		time.Now().UnixMilli()/86_400_000-8)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatal("the hub has had no supply event, so no epoch can close")
	}
}

// publishNow publishes the epoch of the hub in dir (whose store is store)
// as of now.
func publishNow(t *testing.T, dir string, store *aghub.Store) *aghub.SupplyEpochEntry {
	t.Helper()
	makeEpochDue(t, dir)
	e, err := store.PublishDue()
	if err != nil || e == nil {
		t.Fatalf("publish: %+v %v", e, err)
	}
	return e
}

// anet-hub supply (hub-payment-privacy PAY-S7): where the supply stands, as
// data lines, beside the hub: the latest epoch, outstanding, the running
// totals, the events since the latest epoch and what is due to and owed by
// peers.
func TestTheSupplySubcommand(t *testing.T) {
	dir := hubDir(t)
	c, aid := newAID(t)
	registerIn(t, dir, c)
	expectOut(t, cli(t, "en", "-data", dir, "grant", aid, "--amount", "40"),
		sentenceOf("en", "grant.ok", map[string]string{"aid": aid, "n": "40", "name": "operator grant", "m": "40"}))
	expectOut(t, cli(t, "en", "-data", dir, "supply"), "latest_epoch\tnone\noutstanding\t40\nissued\t40\n"+
		"redeemed\t0\nevents_since_publish\t1\n")
	store, err := aghub.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := hubIdentity(t, dir)
	store.SetHubKey(id)
	e := publishNow(t, dir, store)
	store.Close()
	want := "latest_epoch\t0\t" + strconv.FormatUint(e.FromDay, 10) + "\t" + strconv.FormatUint(e.ToDay, 10) +
		"\t40\t" + e.Root + "\noutstanding\t40\nissued\t40\nredeemed\t0\nevents_since_publish\t0\n"
	for _, lang := range []string{"en", "zh"} { // data, the same in every language
		expectOut(t, cli(t, lang, "-data", dir, "supply"), want)
	}
	if r := cli(t, "en", "-data", dir, "supply", "extra"); r.code != 2 || !strings.HasPrefix(r.stderr, "usage: anet-hub supply") {
		t.Errorf("supply with an argument: %+v", r)
	}
}

// hubIdentity is the identity of the hub in dir.
func hubIdentity(t *testing.T, dir string) *identity.Controller {
	t.Helper()
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		t.Fatal(err)
	}
	return id.Ctrl
}
