//go:build !no_federation

package main

import (
	"context"
	"log"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/federation"
)

func init() {
	registerMount(mount{name: "federation", wire: func(d *hubDeps) (func() error, error) {
		cfg, err := federation.LoadConfig(d.data)
		if err != nil {
			return nil, err
		}
		fed, err := federation.New(d.data, cfg, d.hubID, storeDelivery{d.store})
		if err != nil {
			return nil, err
		}
		d.root.Handle("/fed/v1/", fed.Handler())
		if fed.Enabled() {
			d.srv0.SetForwarder(fed.TryForward)
			log.Printf("anet-hub federation: delivery=%s peers=%d", cfg.Delivery, len(cfg.Peers))
		}

		// The discovery sub-plane switches independently: a hub may carry
		// a peer's traffic without also publishing its directory, and
		// those are genuinely different decisions to make about a peer.
		fed.SetDirectory(aghub.FedDirectory{S: d.store})
		stop := func() error { return fed.Close() }
		if fed.DiscoveryEnabled() {
			d.srv0.SetFederatedDirectory(d.store.FederatedAgents)
			ctx, cancel := context.WithCancel(context.Background())
			go syncLoop(ctx, fed)
			stop = func() error { cancel(); return fed.Close() }
			log.Printf("anet-hub federation: discovery=%s home=%s", cfg.Discovery, cfg.Home)
		}
		return stop, nil
	}})
}

// syncLoop pulls peer directories forward.
//
// Pull rather than push, per K208 §5: a hub asks its peers what is new
// and decides what to admit, so nobody can make this hub store a card by
// sending it one. The cadence is unhurried because a directory entry is
// not time-critical — an agent that appeared a minute ago being findable
// a minute later costs nothing, and polling a peer hard costs it.
func syncLoop(ctx context.Context, fed *federation.Service) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		if admitted, refused := fed.SyncOnce(ctx); admitted > 0 || refused > 0 {
			log.Printf("anet-hub federation: directory sync admitted=%d refused=%d", admitted, refused)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
