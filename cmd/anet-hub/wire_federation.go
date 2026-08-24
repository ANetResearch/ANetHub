//go:build !no_federation

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ANetResearch/ANetCore/payment"
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
		// A payment on a peer's ledger is that peer's to settle. We ask
		// it, verify the receipt it signs, credit our own payee, and
		// record what the peer now owes us.
		// Whose ledgers we will clear against, so an agent here can price
		// itself in a way a peer's agent can actually pay.
		d.store.SetClearablePeers(fed.PeerAIDs)
		d.store.SetPeerSettler(func(network string, pp *payment.PaymentPayload) (payment.SettlementResponse, bool) {
			body, err := json.Marshal(map[string]any{
				"x402Version": payment.Version, "paymentPayload": pp,
			})
			if err != nil {
				return payment.SettlementResponse{}, false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			raw, peerAID, err := fed.SettleAtPeer(ctx, network, body)
			if err != nil {
				return payment.SettlementResponse{Success: false,
					ErrorReason: "cross-hub settlement: " + err.Error(), Network: network}, true
			}
			var out payment.SettlementResponse
			if err := json.Unmarshal(raw, &out); err != nil {
				return payment.SettlementResponse{Success: false,
					ErrorReason: "cross-hub settlement: malformed reply", Network: network}, true
			}
			if !out.Success {
				return out, true
			}
			if err := clearPeerSettlement(d.store, fed, peerAID, out); err != nil {
				// The peer moved credit and we could not credit our payee.
				// Saying so is the only honest answer: the money left one
				// ledger and did not arrive on the other, and somebody has
				// to know that happened.
				out.Success = false
				out.ErrorReason = "settled at " + peerAID + " but not cleared here: " + err.Error()
			}
			return out, true
		})
		stop := func() error { return fed.Close() }
		// A peer that says it has paid what it owed has to be checkable.
		// Wired here rather than imported, so the kernel still knows
		// nothing about federation (K207).
		d.srv0.SetPeerKELResolver(fed.PeerKEL)
		// And where that peer lives, so /x402/witnesses can tell a reader
		// where to go and check an attestation for themselves.
		d.srv0.SetPeerEndpointResolver(fed.PeerEndpoint)
		// Pinning peers' issuance heads. Default on; "witness":"off" in
		// federation.json turns it off. See internal/aghub/witness.go for
		// why a peer's attestation is worth more than the subject's own
		// record of itself.
		fed.SetWitness(aghub.FedWitness{S: d.store})
		if fed.DiscoveryEnabled() {
			d.srv0.SetFederatedDirectory(d.store.FederatedAgents)
			ctx, cancel := context.WithCancel(context.Background())
			go syncLoop(ctx, fed)
			if cfg.WitnessEnabled() {
				go witnessLoop(ctx, fed)
				log.Printf("anet-hub federation: witnessing %d peer(s)", len(cfg.Peers))
			}
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
	// Fast while converging, unhurried once converged.
	//
	// Two hubs are usually started together, so the first attempt tends to
	// find the peer not listening yet — and a hub that then waited the
	// steady-state interval would take minutes to learn about a peer that
	// came up seconds later. A directory entry is not time-critical once
	// things are settled, but the settling itself should not be slow.
	const (
		eager  = 5 * time.Second
		steady = 2 * time.Minute
	)
	delay := eager
	for {
		admitted, refused := fed.SyncOnce(ctx)
		if admitted > 0 || refused > 0 {
			log.Printf("anet-hub federation: directory sync admitted=%d refused=%d", admitted, refused)
		}
		if admitted > 0 {
			// Something arrived, so the peers are reachable and there may
			// be more; keep asking until a round comes back empty.
			delay = eager
		} else if delay < steady {
			delay *= 3
			if delay > steady {
				delay = steady
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// clearPeerSettlement verifies the peer's signed receipt and credits the
// local payee against it.
func clearPeerSettlement(store *aghub.Store, fed *federation.Service,
	peerAID string, out payment.SettlementResponse) error {
	b64, _ := out.Extensions[payment.ExtReceipt].(string)
	if b64 == "" {
		return fmt.Errorf("peer settled without a receipt we can keep")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	rec, err := payment.UnmarshalReceipt(raw)
	if err != nil {
		return err
	}
	kel, err := fed.PeerKEL(peerAID)
	if err != nil {
		return err
	}
	return store.ClearFromPeer(peerAID, kel, rec)
}

// witnessLoop pins each peer's issuance head on a slow cadence.
//
// Hourly rather than with the directory sync. A directory entry is worth
// having quickly; a chain head is worth having *often enough that the
// gaps are short*, which is a different requirement. Pinning every two
// minutes would multiply the stored attestations by thirty for no gain —
// what an auditor needs is a head from an hour ago, not from ninety
// seconds ago, because a hub rewriting its ledger is not doing it in the
// gaps between two-minute polls.
func witnessLoop(ctx context.Context, fed *federation.Service) {
	const every = time.Hour
	// One pass shortly after start, so a hub restarted after a long
	// outage does not leave an hour-shaped hole before its first pin.
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if n := fed.WitnessOnce(ctx); n > 0 {
			log.Printf("anet-hub federation: pinned %d peer issuance head(s)", n)
		}
		timer.Reset(every)
	}
}
