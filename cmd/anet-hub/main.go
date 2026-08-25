// Command anet-hub runs the v0.1 centralized Agent Hub: an HTTP registry + verifiable-review store that
// the anetspace web reads. It is not in the P2P data path — agents register and upload evidence to it
// voluntarily (see internal/aghub).
//
// Usage:
//
//	anet-hub [--addr :8088] [--data ./.anet-hub]
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/version"
)

// storeDelivery adapts the hub kernel store to federation.LocalDelivery.
type storeDelivery struct{ s *aghub.Store }

func (d storeDelivery) HasAgent(aid string) bool { _, err := d.s.AgentKEL(aid); return err == nil }
func (d storeDelivery) Enqueue(to, from, kind, iid string, payload []byte) (int64, error) {
	return d.s.RelayEnqueue(to, from, kind, iid, payload)
}

func main() {
	addr := flag.String("addr", ":8088", "HTTP listen address")
	data := flag.String("data", "./.anet-hub", "data directory (SQLite store)")
	showVersion := flag.Bool("version", false, "print version and exit")
	// Funding an account, which had no way in at all.
	//
	// Store.GrantCredit called itself "the operator's way in" and had
	// zero call sites — so an operator could not actually fund anything,
	// and every account on this hub was stuck with whatever the
	// registration grant gave it. A seam that compiles is not a seam that
	// is connected, and this is the fourth of that kind found this month.
	//
	// A flag on the hub binary rather than an HTTP endpoint, deliberately.
	// Who may create credit is a policy question this round does not
	// answer, and an endpoint would answer it by accident — badly, since
	// the obvious authentication for it does not exist yet. Requiring
	// shell access to the machine that holds the ledger is a defensible
	// interim: it is the same trust boundary as the database file.
	grant := flag.String("grant", "", "credit an account: -grant <aid> -amount <n> (requires the hub to be stopped)")
	amount := flag.Int64("amount", 0, "amount for -grant")
	reason := flag.String("reason", "operator grant", "why, recorded on the ledger entry")
	// Discharging what this hub owes a peer, which had no way in either.
	//
	// Store.IssueOwedSettlement signs the statement and had zero call
	// sites, so a hub that owed a peer could not tell it the debt was
	// paid. hub_owed only ever rose. What "paid" means between two hub
	// operators is outside this software — an invoice, a transfer, a
	// standing arrangement — and this does not model it. It signs the
	// statement that the obligation is discharged, and the peer holds the
	// signature.
	clearPeer := flag.String("clear", "", "discharge what this hub owes a peer: -clear <peer-aid> -amount <n> -peer-endpoint <url>")
	peerEndpoint := flag.String("peer-endpoint", "", "where to deliver the discharge for -clear")
	cleared := flag.String("payee", "", "which obligation -clear discharges: the payee AID from -due")
	repair := flag.String("repair-ledger", "",
		"write one entry so <aid>'s entries sum to its balance (amount derived, balance untouched)")
	showDue := flag.Bool("due", false, "list what this hub owes for payments made to agents that bank elsewhere")
	flag.Parse()
	if *showVersion {
		fmt.Printf("anet-hub %s (commit %s, built %s)\n",
			version.V, version.Commit, version.BuiltAt)
		return
	}

	store, err := aghub.Open(*data)
	if err != nil {
		log.Fatalf("anet-hub: open store: %v", err)
	}
	defer store.Close()

	// ctx is cancelled on SIGINT/SIGTERM; the guest-mode janitor runs under it and stops on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *repair != "" {
		if err := repairLedger(*data, *repair); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *showDue {
		if err := listDue(*data); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *clearPeer != "" {
		if err := clearOwed(*data, *clearPeer, uint64(*amount), *reason, *peerEndpoint, *cleared); err != nil {
			log.Fatalf("anet-hub: clear: %v", err)
		}
		return
	}
	if *grant != "" {
		if err := grantCredit(*data, *grant, *amount, *reason); err != nil {
			log.Fatalf("anet-hub: grant: %v", err)
		}
		return
	}

	hubID, err := hubid.LoadOrIncept(*data)
	if err != nil {
		log.Fatalf("anet-hub: hub identity: %v", err)
	}
	log.Printf("anet-hub identity: %s", hubID.AID)

	srv0 := aghub.NewServer(store)
	// This hub's own AID names the ledger it settles on (hub:<aid>), so a
	// credit here is visibly not a credit somewhere else.
	srv0.SetHubAID(hubID.AID)
	// The identity settlements are signed with, so a payer holds a receipt
	// it can show without asking this hub to agree.
	store.SetHubKey(hubID.Ctrl)
	// A hub upgraded into having an issuance chain has credit
	// outstanding from before the chain existed. Record that once, as
	// what it is, rather than leaving the chain permanently disagreeing
	// with the balances or backfilling a reconstruction and signing it as
	// though it were contemporaneous.
	if sup, err := store.Supply(hubID.AID); err == nil && sup.Outstanding > 0 {
		if err := store.OpenBalance(sup.Outstanding); err != nil {
			log.Printf("anet-hub: opening balance: %v", err)
		} else if sup.ChainIssued == 0 && sup.ChainOpening == 0 {
			log.Printf("anet-hub: issuance chain opened at %d outstanding "+
				"(issued before this chain existed; not attested outside this hub)",
				sup.Outstanding)
		}
	}
	// Guest mode is always on: no-daemon visitors are brokered to any registered agent that accepts guests
	// (guest_quota > 0, default 5 — each agent opts out via `anet hub-register --guest-messages 0`).
	if err := srv0.EnableGuestMode(ctx, *data); err != nil {
		log.Fatalf("anet-hub: enable guest mode: %v", err)
	}

	// Root mux: hub modules mount beside the registry/relay kernel. The
	// taskboard authenticates against the same agent registry (one KEL, one
	// auth scheme); /hub/identity is the federation trust anchor (K208).
	root := http.NewServeMux()
	root.Handle("/hub/identity", hubID.Handler())
	root.Handle("/", srv0.Handler())
	deps := &hubDeps{data: *data, store: store, hubID: hubID, srv0: srv0, root: root}
	names := ""
	for _, m := range mounts {
		closer, err := m.wire(deps)
		if err != nil {
			log.Fatalf("anet-hub: module %s: %v", m.name, err)
		}
		if closer != nil {
			defer closer()
		}
		names += " " + m.name
	}
	log.Printf("anet-hub modules:%s", names)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("anet-hub %s (commit %s) listening on %s (data: %s)",
			version.V, version.Commit, *addr, *data)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("anet-hub: serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("anet-hub: shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}

// grantCredit funds an account from the command line.
//
// Opens the store, credits, closes. Run against a stopped hub or a
// running one — SQLite serialises the write either way — but the balance
// a running hub has cached in flight is its own business, so the flag's
// help says stopped and means it.
//
// The hub's own row is debited by Credit, so a grant made this way shows
// up in /x402/supply as issued liability like any other. An operator
// creating credit off the books would defeat the one arithmetic that
// makes custody checkable.
func grantCredit(dir, aid string, amount int64, reason string) error {
	if amount == 0 {
		return fmt.Errorf("-amount is required and must not be zero (negative debits)")
	}
	store, err := aghub.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		return err
	}
	// The hub key names the row credit is issued from. Without it the
	// grant would appear from nowhere and the ledger would stop summing
	// to zero.
	store.SetHubKey(id.Ctrl)
	if err := store.GrantCredit(aid, amount, reason); err != nil {
		return err
	}
	bal, err := store.Balance(aid)
	if err != nil {
		return err
	}
	fmt.Printf("granted %d to %s (%s) — balance now %d\n", amount, aid, reason, bal)
	return nil
}

// clearOwed signs this hub's statement that it has discharged what it
// owes a peer, and delivers it.
//
// Delivered rather than only printed, because the statement is worth
// something only to the peer that holds the debt — a discharge sitting on
// the debtor's disk discharges nothing. The signature is printed too, so
// an operator who needs to deliver it another way can.
// repairLedger closes the gap between an account's entries and its
// balance, left by settlements that predate ledger entries existing.
func repairLedger(dir, aid string) error {
	store, err := aghub.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	delta, err := store.RepairLedger(aid)
	if err != nil {
		return err
	}
	if delta == 0 {
		fmt.Printf("%s: entries already sum to the balance; nothing written\n", aid)
		return nil
	}
	fmt.Printf("%s: wrote a correcting entry of %d\n", aid, delta)
	return nil
}

// listDue prints what this hub owes for credit that left its ledger to
// pay agents banking on peers.
//
// Reported by payee rather than by hub because that is what the
// authorization named. Which hub holds a payee is a fact this hub may not
// have, and inferring it would make the operator's discharge depend on a
// guess.
func listDue(dir string) error {
	store, err := aghub.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	due, err := store.Due()
	if err != nil {
		return err
	}
	if len(due) == 0 {
		fmt.Println("nothing due")
		return nil
	}
	aids := make([]string, 0, len(due))
	for aid := range due {
		aids = append(aids, aid)
	}
	sort.Strings(aids)
	for _, aid := range aids {
		fmt.Printf("%8d  %s\n", due[aid], aid)
	}
	return nil
}

func clearOwed(dir, peerAID string, amount uint64, reason, endpoint, payeeAID string) error {
	if amount == 0 {
		return fmt.Errorf("-amount is required")
	}
	store, err := aghub.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		return err
	}
	store.SetHubKey(id.Ctrl)

	// What the peer says it is owed before we start, so the answer after
	// can be checked against something rather than taken on faith.
	owedBefore := int64(-1)
	if endpoint != "" {
		if resp, gerr := http.Get(strings.TrimSuffix(endpoint, "/") + "/x402/supply"); gerr == nil {
			var sup struct {
				Supply struct {
					Owed int64 `json:"owed_by_peers"`
				} `json:"supply"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&sup) == nil {
				owedBefore = sup.Supply.Owed
			}
			resp.Body.Close()
		}
	}
	if owedBefore < 0 {
		// Unknown rather than zero. Treating "could not ask" as "owes
		// nothing" would make the check below pass for the wrong reason.
		owedBefore = int64(amount)
	}

	rec, err := store.IssueOwedSettlement(id.AID, peerAID, amount, reason)
	if err != nil {
		return err
	}
	raw, err := rec.Marshal()
	if err != nil {
		return err
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	fmt.Printf("discharge signed: %d to %s (%s)\n", amount, peerAID, reason)
	fmt.Println(enc)

	if endpoint == "" {
		fmt.Println("no -peer-endpoint given; deliver the line above to the peer's POST /federation/clear")
		return nil
	}
	body, err := json.Marshal(map[string]string{
		"peer_aid": id.AID, "receipt": enc})
	if err != nil {
		return err
	}
	resp, err := http.Post(strings.TrimSuffix(endpoint, "/")+"/federation/clear",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("delivering to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer answered %s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	fmt.Printf("delivered: %s\n", strings.TrimSpace(string(out)))
	// A 200 is not "applied".
	//
	// The creditor answers 200 on the replay path too — it treats a
	// repeated statement id as a repeat of one it already applied and
	// changes nothing. Reading that as success meant this hub reduced its
	// own record while the peer's stayed where it was, and the two then
	// disagreed about a debt. The reply carries the peer's remaining
	// owed; checking it is the difference between believing a status code
	// and believing the number.
	var ack struct {
		Peer string `json:"peer"`
		Owed int64  `json:"owed"`
	}
	if json.Unmarshal(out, &ack) == nil {
		if ack.Owed > owedBefore-int64(amount) {
			return fmt.Errorf(
				"%s still shows %d owed after a discharge of %d (it was %d) — "+
					"the statement was accepted and not applied, most likely as a repeat "+
					"of one already on file; nothing was reduced here",
				peerAID, ack.Owed, amount, owedBefore)
		}
		fmt.Printf("peer now owes %d\n", ack.Owed)
	}
	// Only now, and only if the operator named which obligation this was.
	//
	// After delivery rather than before: a discharge the peer refused is
	// one this hub still owes, and reducing the record first would leave
	// this hub believing it had paid something the peer still shows as
	// owed. Optional because a discharge can also be an out-of-band
	// arrangement that no hub_due row corresponds to.
	if payeeAID != "" {
		if err := store.DischargeDue(payeeAID, int64(amount)); err != nil {
			return fmt.Errorf("delivered, but the local record was not reduced: %w", err)
		}
		fmt.Printf("due to %s reduced by %d\n", payeeAID, amount)
	}
	return nil
}
