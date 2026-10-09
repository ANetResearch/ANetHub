package aghub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity/identitytest"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/relayauth"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

func init() { wire3Setups["fed_settle"] = wire3FedSettleSetup }

// wire3FedSettleSetup is a hub with its federation module and one peer hub,
// for the cross-hub settlement fixtures (testdata/wire3/fed_settle.json;
// hub-payment-privacy §2.4, PAY-L4, PAY-U2; core §2.12.2, G3). Identities
// that sign (relayauth, as hubs): "peer", a hub of the peer table, whose
// /hub/identity is served; "stranger", a hub that is not a peer. payer and
// payee are registered here, payer funded with 500; the peer owes this hub
// 40 (a receipt of the peer's, cleared). Bodies:
//
//	${settle_away}   an x402 FacilitatorRequest: payer pays 30 to an agent of the peer
//	${settle_here}   the same shape, paying payee, who banks here
//	${clear_ok}      {peer_aid, receipt}: the peer discharges 5 of what it owes
//	${clear_padded}  the same statement with "=" after its base64url
//	${clear_other}   the statement with another hub's AID as peer_aid
//	${clear_over}    a statement for 100, more than the peer owes
func wire3FedSettleSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	h := newRelayHub(t)
	peerID, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	strangerID, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peerSrv := httptest.NewServer(wire3.Contract(peerID.Handler()))
	t.Cleanup(peerSrv.Close)
	fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Witness: "off",
		Home: "https://hub.test", Peers: []federation.Peer{{AID: peerID.AID, Endpoint: peerSrv.URL}}}, h.hubID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fed.Close() })
	fed.SetKernel(h.srv)
	fed.SetClearing(h.srv)
	h.srv.SetFederation(fed)
	h.srv.SetPeerKELResolver(fed.PeerKEL)
	root := http.NewServeMux()
	root.Handle("/hub/identity", h.hubID.Handler())
	root.Handle("/fed/v3/", fed.Handler())
	root.Handle("/", h.srv.Handler())

	payer, payee := h.bareAgent(), h.bareAgent()
	if err := h.store.GrantCredit(payer.aid, 500, "fixture"); err != nil {
		t.Fatal(err)
	}
	own := payment.CreditNetwork(h.hubAID)
	now := h.clock()
	request := func(payTo, nonce string) string {
		a := authAt(t, payer.c, payTo, 30, own, "bind-"+nonce, nonce, now.Add(-time.Second), 5*time.Minute)
		b, err := json.Marshal(payment.FacilitatorRequest{X402Version: payment.Version,
			PaymentPayload: payloadFor(t, a), PaymentRequirements: requirementsOf(a)})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// What the peer owes this hub: a receipt of its own, cleared.
	owed := &payment.Receipt{AuthID: "peer-settled-1", Payer: "did:anet:their-user", PayTo: payee.aid, Amount: 40,
		Network: payment.CreditNetwork(peerID.AID), SettleAt: now.UnixMilli()}
	if err := owed.Sign(peerID.Ctrl); err != nil {
		t.Fatal(err)
	}
	if err := h.store.ClearFromPeer(peerID.AID, peerID.Ctrl.KEL(), owed); err != nil {
		t.Fatal(err)
	}
	statement := func(amount uint64) string {
		rec := &payment.Receipt{AuthID: fmt.Sprintf("clear:fixture:%d", amount), Payer: peerID.AID, PayTo: h.hubAID,
			Amount: amount, Network: payment.CreditNetwork(peerID.AID), SettleAt: now.UnixMilli()}
		if err := rec.Sign(peerID.Ctrl); err != nil {
			t.Fatal(err)
		}
		raw, err := rec.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return wire3.EncodeB64URL(raw)
	}
	clear := func(peerAID, receipt string) string {
		b, _ := json.Marshal(ClearRequest{PeerAID: peerAID, Receipt: receipt})
		return string(b)
	}
	other, _ := identitytest.Hub()
	five := statement(5)
	vars := map[string]string{
		"hub": h.hubAID, "peer": peerID.AID, "payer": payer.aid, "payee": payee.aid, "own": own,
		"settle_away":  request("did:anet:peer-agent", "away"),
		"settle_here":  request(payee.aid, "here"),
		"clear_ok":     clear(peerID.AID, five),
		"clear_padded": clear(peerID.AID, five+"="),
		"clear_other":  clear(other.AID(), five),
		"clear_over":   clear(peerID.AID, statement(100)),
	}
	signers := map[string]*hubid.Identity{"peer": peerID, "stranger": strangerID}
	return &wire3test.Env{
		Handler: wire3.Contract(root),
		Vars:    vars,
		Sign: func(req *http.Request, body []byte, action, as string) error {
			id, ok := signers[as]
			if !ok {
				return fmt.Errorf("no identity %q in this setup", as)
			}
			ts := relaySignTS()
			sig, seq := id.Ctrl.Sign(relayauth.PreimageV2(action, id.AID, h.hubAID, ts, req.Method, req.URL.RequestURI(), body))
			req.Header.Set(relayauth.HeaderAID, id.AID)
			req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
			req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
			req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
			return nil
		},
	}
}
