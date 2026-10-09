package aghub

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/relayauth"
	"github.com/ANetResearch/ANetCore/seal"

	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/wire3"
	"github.com/ANetResearch/ANetHub/internal/wire3/wire3test"
)

func init() { wire3Setups["fed"] = wire3FedSetup }

// wire3FedSetup is a hub with its federation module for the federation v3
// fixtures (testdata/wire3/fed_v3.json; sealed-sender §2.8, §4.2.7; core
// §2.12.2, G3): delivery and discovery on, one peer hub. Identities that
// sign (relayauth, as hubs): "peer", a hub of the peer table, whose
// /hub/identity is served; "stranger", a hub that is not a peer. bob is
// registered here with a key set (so the directory holds one entry).
// Envelopes, base64url, with what their forwards need:
//
//	${env_first}   a first contact to bob, ${access0} its access
//	${env_nobody}  a first contact to an AID not registered here
//	${env_cap}     an envelope to bob under a credential bob issued, ${access_cap}
//	${env_forged}  the same credential with a proof by another key, ${access_forged}
func wire3FedSetup(t *testing.T) *wire3test.Env {
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
	fed, err := federation.New(t.TempDir(), federation.Config{Delivery: "allowlist", Discovery: "allowlist",
		Witness: "off", Home: "https://hub.test", Peers: []federation.Peer{{AID: peerID.AID, Endpoint: peerSrv.URL}}}, h.hubID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fed.Close() })
	fed.SetDirectory(FedDirectory{S: h.store})
	fed.SetKernel(h.srv)
	h.srv.SetFederation(fed)
	root := http.NewServeMux()
	h.hubID.DirMaxBits = h.srv.DirMaxBits
	root.Handle("/hub/identity", h.hubID.Handler())
	root.Handle("/fed/v3/", fed.Handler())
	root.Handle("/", h.srv.Handler())

	bob := h.agent()
	g := h.issue(bob, seal.CapClassContact, time.Hour)
	b64 := base64.RawURLEncoding.EncodeToString
	vars := map[string]string{"hub": h.hubAID, "bob": bob.aid}
	vars["env_first"] = b64(envelope(t, bob.aid, []byte("first")))
	vars["access0"] = b64([]byte{0xa1, 0x01, 0x00})
	vars["env_nobody"] = b64(envelope(t, bob.aid+"x", []byte("nobody")))
	capEnv := withCap(t, envelope(t, bob.aid, []byte("cap")), g)
	vars["env_cap"], vars["access_cap"] = b64(capEnv), b64(accessRaw(t, capEnv))
	_, g.holder, _ = ed25519.GenerateKey(nil)
	forged := withCap(t, envelope(t, bob.aid, []byte("forged")), g)
	vars["env_forged"], vars["access_forged"] = b64(forged), b64(accessRaw(t, forged))
	// One review uploaded here, of an agent that federates, as the
	// handler stores it: ${rv_receipt}, ${rv_review}, ${rv_att} and
	// ${rv_kel} are what the review stream serves of it.
	subject, reviewer := h.bareAgent(), h.bareAgent()
	if err := h.store.SetVisibility(subject.aid, VisibilityFederated); err != nil {
		t.Fatal(err)
	}
	kit := NewReviewKitForTest(t, subject.c, reviewer.c, "ix-fed-fixture", 5)
	upRaw, err := json.Marshal(kit.Body(t))
	if err != nil {
		t.Fatal(err)
	}
	up, rf := decodeReviewUpload(upRaw)
	if rf != nil {
		t.Fatalf("the fixture's upload: %+v", rf)
	}
	stored, att, err := h.store.attest(reviewer.aid, up, reviewDay(h.store.now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.StoreReview(stored, up.receiptRaw, up.reviewRaw, att); err != nil {
		t.Fatal(err)
	}
	subjectKEL, err := identity.MarshalKEL(subject.c.KEL())
	if err != nil {
		t.Fatal(err)
	}
	vars["rv_receipt"], vars["rv_review"] = b64(up.receiptRaw), b64(up.reviewRaw)
	vars["rv_att"], vars["rv_kel"] = b64(att), b64(subjectKEL)
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
