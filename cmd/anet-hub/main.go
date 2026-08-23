// Command anet-hub runs the v0.1 centralized Agent Hub: an HTTP registry + verifiable-review store that
// the anetspace web reads. It is not in the P2P data path — agents register and upload evidence to it
// voluntarily (see internal/aghub).
//
// Usage:
//
//	anet-hub [--addr :8088] [--data ./.anet-hub]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
