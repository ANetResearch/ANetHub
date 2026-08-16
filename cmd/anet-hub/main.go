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
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/taskboard"
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
	flag.Parse()
	if *showVersion {
		fmt.Println("anet-hub", version.V)
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

	tb, err := taskboard.Open(*data)
	if err != nil {
		log.Fatalf("anet-hub: open taskboard: %v", err)
	}
	defer tb.Close()
	hubID, err := hubid.LoadOrIncept(*data)
	if err != nil {
		log.Fatalf("anet-hub: hub identity: %v", err)
	}
	log.Printf("anet-hub identity: %s", hubID.AID)

	fedCfg, err := federation.LoadConfig(*data)
	if err != nil {
		log.Fatalf("anet-hub: federation config: %v", err)
	}
	fed, err := federation.New(*data, fedCfg, hubID, storeDelivery{store})
	if err != nil {
		log.Fatalf("anet-hub: federation: %v", err)
	}
	defer fed.Close()

	srv0 := aghub.NewServer(store)
	if fed.Enabled() {
		srv0.SetForwarder(fed.TryForward)
		log.Printf("anet-hub federation: delivery=%s peers=%d", fedCfg.Delivery, len(fedCfg.Peers))
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
	root.Handle("/tasks/", taskboard.NewServer(tb, store).Handler())
	root.Handle("/hub/identity", hubID.Handler())
	root.Handle("/fed/v1/", fed.Handler())
	root.Handle("/", srv0.Handler())

	srv := &http.Server{
		Addr:              *addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("anet-hub %s listening on %s (data: %s)", version.V, *addr, *data)
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
