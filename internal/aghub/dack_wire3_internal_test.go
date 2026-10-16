package aghub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

// The delivery confirmation fixtures (p2p-receipts §7.1 G5; core §5.2
// WIRE3-*): testdata/wire3/relay-ack.json, relay-status.json and
// fed-relay-status.json.
func init() {
	wire3Setups["relay_ack"] = wire3RelayAckSetup
	wire3Setups["relay_status"] = wire3RelayStatusSetup
	wire3Setups["fed_relay_status"] = wire3FedRelayStatusSetup
}

// dackVars are the values of one confirmation, as fixtures name them:
// ${h<name>} the handle, ${d<name>} the dack, base64url.
func dackVars(vars map[string]string, name string, c confirmation) {
	vars["h"+name], vars["d"+name] = b64u(c.handle), b64u(c.dack)
}

// signAs signs req for the agents of a relayHub, by name.
func signAs(h *relayHub, agents map[string]*relayAgent) func(req *http.Request, body []byte, action, as string) error {
	return func(req *http.Request, body []byte, action, as string) error {
		a, ok := agents[as]
		if !ok {
			return fmt.Errorf("no identity %q in this setup", as)
		}
		ts := relaySignTS()
		sig, seq := a.c.Sign(relayauth.PreimageV2(action, a.aid, h.hubAID, ts, req.Method, req.URL.RequestURI(), body))
		req.Header.Set(relayauth.HeaderAID, a.aid)
		req.Header.Set(relayauth.HeaderTS, strconv.FormatUint(ts, 10))
		req.Header.Set(relayauth.HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(relayauth.HeaderSig, relayauth.EncodeSig(sig))
		return nil
	}
}

// behindTheProxy serves h as the hub runs behind its reverse proxy on the
// same machine: a request carrying X-Real-IP comes from loopback, and the
// client's address is that header's (limits.go clientIP).
func behindTheProxy(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Real-IP") != "" {
			r.RemoteAddr = "127.0.0.1:4000"
		}
		h.ServeHTTP(w, r)
	})
}

// wire3RelayAckSetup is a hub for the /relay/ack fixtures (DLV-W-14,
// DLV-W-15, DLV-H-3). r is registered with three rows in its mailbox,
// ${id1}, ${id2} and ${id3}; other with one, ${id_other}. Confirmations
// ${h1}/${d1} and ${h2}/${d2}; ${h_padded} is h1 padded, ${h_short} a 15-byte
// handle, ${d_std} an 80-byte dack in the standard alphabet. r and other
// sign.
func wire3RelayAckSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	h := newRelayHub(t)
	r, other := h.agent(), h.agent()
	vars := map[string]string{"hub": h.hubAID, "r": r.aid, "other": other.aid}
	for i := 1; i <= 3; i++ {
		vars["id"+strconv.Itoa(i)] = strconv.FormatInt(h.queue(r, fmt.Sprint("row ", i)).ID, 10)
	}
	vars["id_other"] = strconv.FormatInt(h.queue(other, "theirs").ID, 10)
	c1, c2 := newConfirmation(t), newConfirmation(t)
	dackVars(vars, "1", c1)
	dackVars(vars, "2", c2)
	vars["h_padded"] = base64.URLEncoding.EncodeToString(c1.handle)
	vars["h_short"] = b64u(c1.handle[:15])
	vars["d_std"] = base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, seal.DAckLen))
	return &wire3test.Env{Handler: h.h, Vars: vars,
		Sign: signAs(h, map[string]*relayAgent{"r": r, "other": other})}
}

// wire3RelayStatusSetup is a hub for the /relay/status fixtures (§2.4.3,
// DLV-W-16, DLV-W-18). r's mailbox holds the row ${rid_wait}; the row
// ${rid_done} was collected and its confirmation ${h_done}/${d_done} handed
// in. ${rid_unknown} and ${h_unknown} were never anybody's; ${rid_short} is
// 15 bytes, ${rid_padded} rid_wait padded; ${big} is a body over 16 KiB.
// The hub delivers to the peer ${peer}, which does not answer; ${nobody_hub}
// is no peer. It is served behind its proxy (X-Real-IP), and the address
// 198.51.100.66 has spent its bucket of status checks.
func wire3RelayStatusSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	h := newRelayHub(t)
	r := h.agent()
	wait, done := h.queue(r, "waiting"), h.queue(r, "done")
	cd := newConfirmation(t)
	h.ack(r, ackItem(done.ID, &cd))
	peerID, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Witness: "off",
		Peers: []federation.Peer{{AID: peerID.AID, Endpoint: gone.URL}}}, h.hubID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fed.Close() })
	fed.SetKernel(h.srv)
	fed.SetDeliveryStatus(h.srv)
	h.srv.SetFederation(fed)
	for i := 0; i < int(rateRelayStatus.burst); i++ {
		h.srv.delivery.byAddr.take("198.51.100.66", rateRelayStatus)
	}
	nobody, err := hubid.LoadOrIncept(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"hub": h.hubAID, "peer": peerID.AID, "nobody_hub": nobody.AID,
		"rid_wait": b64u(wait.RID), "rid_done": b64u(done.RID),
		"rid_unknown": b64u(randomBytes(t, RIDLen)), "h_unknown": b64u(randomBytes(t, seal.HandleLen)),
		"rid_short": b64u(wait.RID[:15]), "rid_padded": base64.URLEncoding.EncodeToString(wait.RID),
		"big": `{"items":[],"pad":"` + strings.Repeat("a", StatusBodyLimit) + `"}`}
	dackVars(vars, "_done", cd)
	return &wire3test.Env{Handler: behindTheProxy(h.h), Vars: vars}
}

// wire3FedRelayStatusSetup is a hub with its federation module for the
// /fed/v3/relay-status fixtures (§2.5, DLV-W-19, DLV-W-19a): "peer" and
// "peer2" are hubs of its peer table (peer2 has spent its bucket of status
// checks), "stranger" is not. Rows as in wire3RelayStatusSetup:
// ${rid_wait}, ${rid_done} with ${h_done}/${d_done}; ${items65} is a JSON
// array of 65 items.
func wire3FedRelayStatusSetup(t *testing.T) *wire3test.Env {
	t.Helper()
	h := newRelayHub(t)
	r := h.agent()
	wait, done := h.queue(r, "waiting"), h.queue(r, "done")
	cd := newConfirmation(t)
	h.ack(r, ackItem(done.ID, &cd))
	ids := map[string]*hubid.Identity{}
	var peers []federation.Peer
	for _, name := range []string{"peer", "peer2", "stranger"} {
		id, err := hubid.LoadOrIncept(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = id
		srv := httptest.NewServer(wire3.Contract(id.Handler()))
		t.Cleanup(srv.Close)
		if name != "stranger" {
			peers = append(peers, federation.Peer{AID: id.AID, Endpoint: srv.URL})
		}
	}
	fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Witness: "off", Peers: peers}, h.hubID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fed.Close() })
	fed.SetKernel(h.srv)
	fed.SetDeliveryStatus(h.srv)
	h.srv.SetFederation(fed)
	root := http.NewServeMux()
	root.Handle("/fed/v3/", fed.Handler())
	root.Handle("/", h.h)
	for i := 0; i < int(rateFedRelayStatus.burst); i++ {
		h.srv.delivery.byPeer.take(ids["peer2"].AID, rateFedRelayStatus)
	}
	items := make([]FedRelayStatusItem, 65)
	for i := range items {
		items[i] = FedRelayStatusItem{RID: b64u(wait.RID), Handle: b64u(cd.handle)}
	}
	items65, _ := json.Marshal(items)
	vars := map[string]string{"hub": h.hubAID, "rid_wait": b64u(wait.RID), "rid_done": b64u(done.RID),
		"rid_unknown": b64u(randomBytes(t, RIDLen)), "h_unknown": b64u(randomBytes(t, seal.HandleLen)),
		"items65": string(items65), "big": `{"items":[],"pad":"` + strings.Repeat("a", StatusBodyLimit) + `"}`}
	dackVars(vars, "_done", cd)
	return &wire3test.Env{Handler: wire3.Contract(root), Vars: vars,
		Sign: func(req *http.Request, body []byte, action, as string) error {
			id, ok := ids[as]
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
		}}
}
