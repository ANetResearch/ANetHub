//go:build !no_federation

package main

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/payment"

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
		d.root.Handle("/fed/v2/", fed.Handler())
		// Forwarded envelopes are bounded like local ones.
		fed.SetMaxEnvelope(d.srv0.Limits().MaxEnvelope)
		// /fed/v2/keys answers for any AID registered here, by exact AID,
		// to peers only (A2A-DESIGN §3.9).
		fed.SetKeySource(aghub.StoreKeySource{S: d.store})
		if fed.Enabled() {
			d.srv0.SetForwarder(fed.TryForward)
			// The lookup a sender here needs for a peer's hub-local agent
			// ([C32]). Left out only under the test switch; answering
			// peers' /fed/v2/keys (SetKeySource above) is not affected.
			if !d.noFedKeyLookup {
				d.srv0.SetFederatedKeyLookup(fed.LookupKeys)
			}
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
		d.store.SetPeerSettler(peerSettler(d.store, fed))
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

// peerSettleTimeout bounds one forwarded settlement. The federation
// client's own timeout (10 s) normally ends the call first; this bound is
// kept below the daemon's 30 s facilitator timeout (ANet module/x402
// hubCallTimeout) so that the entry hub answers settlement_pending before
// the merchant's own request gives up.
const peerSettleTimeout = 20 * time.Second

// peerSettler is the entry hub's half of a cross-hub settlement
// (A2A-DESIGN §8.5).
//
// The kernel has already compared the payment with the requirements
// (aghub.CheckRequirements); a payment that fails that is not forwarded.
// This forwards the x402 v2 body {x402Version, paymentPayload,
// paymentRequirements} to the hub whose ledger the network names, which
// verifies the signature and compares the terms again. On success the
// kernel checks that the peer's receipt states the required payee and
// amount and credits the local payee against it.
//
// A transport error, a timeout or an unreadable reply leaves the outcome
// unknown: the peer may have settled. That is settlement_pending, not a
// failure, and the merchant retries with the same payload; the peer
// answers a settled authorization with its original receipt, so the retry
// completes the clearing and credits the payee once.
//
// A network that is not an allowlisted peer's ledger is not handled here,
// and the kernel refuses the payment with network_mismatch.
func peerSettler(store *aghub.Store, fed *federation.Service) aghub.PeerSettler {
	return func(network string, pp *payment.PaymentPayload, req *payment.PaymentRequirements,
		auth *payment.Authorization) (payment.SettlementResponse, bool) {
		peerAID, ok := strings.CutPrefix(network, "hub:")
		if !ok || !slices.Contains(fed.PeerAIDs(), peerAID) {
			return payment.SettlementResponse{}, false
		}
		body, err := json.Marshal(payment.FacilitatorRequest{
			X402Version: payment.Version, PaymentPayload: pp, PaymentRequirements: req,
		})
		if err != nil {
			// Nothing was sent, so the outcome is known: not settled.
			return payment.SettlementResponse{Success: false, ErrorReason: payment.ReasonSettlementFailed,
				Network: network, Payer: auth.Payer,
				Extensions: map[string]any{payment.ExtErrorDetail: "encoding the forwarded request: " + err.Error()}}, true
		}
		ctx, cancel := context.WithTimeout(context.Background(), peerSettleTimeout)
		defer cancel()
		raw, from, err := fed.SettleAtPeer(ctx, network, body)
		if err != nil {
			return aghub.SettlementPending(auth, network,
				"no answer from the ledger hub "+peerAID+": "+err.Error(), nil), true
		}
		var out payment.SettlementResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return aghub.SettlementPending(auth, network,
				"unreadable answer from the ledger hub "+peerAID+": "+err.Error(), nil), true
		}
		if !out.Success && out.ErrorReason == "" {
			// JSON, but not a facilitator's refusal: a hub refusal always
			// names its reason. An error body from a proxy or from a
			// server-side failure (`{"error": ...}`) decodes to this, and
			// it does not say whether the ledger hub settled. Passing it
			// on as a refusal would tell the merchant the payment failed,
			// with an errorReason no client can branch on, while the payer
			// may have been charged.
			return aghub.SettlementPending(auth, network,
				"the ledger hub "+peerAID+" answered with neither a success nor a reason: "+
					truncate(string(raw), 200), nil), true
		}
		if !out.Success {
			// The ledger hub's own refusal, with its reason. Definitive
			// unless the reason says otherwise.
			return out, true
		}
		return store.ClearPeerSettlement(from, fed.PeerKEL, out, auth, req), true
	}
}

// truncate shortens a peer's answer for an error detail, so a large error
// page does not become a large settlement response.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
