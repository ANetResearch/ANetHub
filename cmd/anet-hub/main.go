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
	"errors"
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
	"github.com/ANetResearch/ANetHub/internal/federation"
	"github.com/ANetResearch/ANetHub/internal/hubid"
	"github.com/ANetResearch/ANetHub/internal/version"
	"github.com/ANetResearch/ANetHub/internal/wire3"
)

// storeDelivery adapts the hub kernel store to federation.LocalDelivery,
// the receiving half of the federation v2 forward. The kernel's relay errors
// are mapped onto federation's, so that the forward handler can answer 507
// and 400 without importing the kernel.
//
// v030-todo(SS-6): /fed/v3/forward checks the delivery credential itself and
// queues through the kernel's /relay/send steps; this adapter goes with v2.
type storeDelivery struct{ s *aghub.Store }

func (d storeDelivery) HasAgent(aid string) bool { _, err := d.s.AgentKEL(aid); return err == nil }
func (d storeDelivery) Enqueue(to string, envelope []byte) (int64, error) {
	q, err := d.s.QueueEnvelope(to, envelope)
	var limited *aghub.RedeliveryLimitedError
	switch {
	case errors.Is(err, aghub.ErrMailboxFull), errors.Is(err, aghub.ErrStrangersBusy), errors.As(err, &limited):
		// Federation v2 has one "cannot take it now" answer.
		return 0, fmt.Errorf("%w: %v", federation.ErrMailboxFull, err)
	case errors.Is(err, aghub.ErrBadEnvelope):
		return 0, fmt.Errorf("%w: %v", federation.ErrBadEnvelope, err)
	}
	return q.ID, err
}

// hubFlags is every flag this binary takes.
//
// Declared in one function rather than inline in main so a test can
// register the same set on its own FlagSet and assert against what the
// binary will actually see. A test that redeclares the flags it wants to
// check asserts about its own copy, which is how a help string can go on
// describing behaviour the binary does not have.
type hubFlags struct {
	addr        *string
	publicURL   *string
	data        *string
	showVersion *bool
	// v030-todo(PAY-4): -amount, -reason, -clear, -payee, -peer-endpoint,
	// -due and -repair-ledger become the subcommands due and clear, and
	// -repair-ledger goes (hub_flag_removed.none).
	amount       *int64
	reason       *string
	clearPeer    *string
	peerEndpoint *string
	cleared      *string
	repair       *string
	showDue      *bool
	// removed collects the action flags that are subcommands now, in the
	// order given (core G12; removedFlags).
	removed *[]removedUse
	// The §3.7 relay limits (A2A-DESIGN). See aghub.Limits.
	maxEnvelope       *int64
	mailboxMessages   *int
	mailboxBytes      *int64
	undeliveredTTL    *time.Duration
	pollBudget        *int64
	registerPerMinute *float64
	registerBurst     *int
}

func defineFlags(fs *flag.FlagSet) *hubFlags {
	f := &hubFlags{}
	f.addr = fs.String("addr", ":8088", "HTTP listen address")
	f.data = fs.String("data", "./.anet-hub", "data directory (SQLite store)")
	f.publicURL = fs.String("public-url", "",
		"this hub's public base URL (e.g. https://hub.example.org), stated as homeHub in /a2a/v1/agents and "+
			"checked against the relay URL of admitted A2A cards; empty: the origin of each request")
	f.showVersion = fs.Bool("version", false, "print version and exit")
	// Discharging what this hub owes a peer, which had no way in either.
	//
	// Store.IssueOwedSettlement signs the statement and had zero call
	// sites, so a hub that owed a peer could not tell it the debt was
	// paid. hub_owed only ever rose. What "paid" means between two hub
	// operators is outside this software — an invoice, a transfer, a
	// standing arrangement — and this does not model it. It signs the
	// statement that the obligation is discharged, and the peer holds the
	// signature.
	f.amount = fs.Int64("amount", 0, "amount for -clear")
	f.reason = fs.String("reason", "operator grant", "why, recorded on the ledger entry")
	f.clearPeer = fs.String("clear", "", "discharge what this hub owes a peer: -clear <peer-aid> -amount <n> -peer-endpoint <url>")
	f.peerEndpoint = fs.String("peer-endpoint", "", "where to deliver the discharge for -clear")
	f.cleared = fs.String("payee", "", "which obligation -clear discharges: the payee AID from -due")
	f.repair = fs.String("repair-ledger", "",
		"write one entry so <aid>'s entries sum to its balance (amount derived, balance untouched)")
	f.showDue = fs.Bool("due", false, "list what this hub owes for payments made to agents that bank elsewhere")
	// The action flags that became subcommands (core G12): still known
	// to the parser, so each is answered with the subcommand to run
	// rather than with "flag provided but not defined".
	f.removed = defineRemovedFlags(fs)
	// Relay limits (A2A-DESIGN §3.7). Defaults are aghub.DefaultLimits.
	def := aghub.DefaultLimits()
	f.maxEnvelope = fs.Int64("relay-max-envelope", def.MaxEnvelope,
		"largest sealed envelope /relay/send accepts, in bytes (413 above it); keep the reverse proxy's "+
			"client_max_body_size at or above this")
	f.mailboxMessages = fs.Int("relay-mailbox-messages", def.MailboxMessages,
		"undelivered envelopes one recipient may have queued (507 above it)")
	f.mailboxBytes = fs.Int64("relay-mailbox-bytes", def.MailboxBytes,
		"undelivered envelope bytes one recipient may have queued (507 above it)")
	f.undeliveredTTL = fs.Duration("relay-ttl", def.UndeliveredTTL,
		"how long an undelivered envelope is kept before it is deleted")
	f.pollBudget = fs.Int64("relay-poll-budget", def.PollBudget,
		"cumulative envelope bytes one /relay/poll response returns (the first message always)")
	f.registerPerMinute = fs.Float64("register-rate", def.RegisterPerMinute,
		"per-client-IP /register token refill, per minute (429 when empty)")
	f.registerBurst = fs.Int("register-burst", def.RegisterBurst, "per-client-IP /register token bucket size")
	return f
}

// limits collects the relay limit flags. The relay's send buckets
// (aghub/limits.go) are fixed values (sealed-sender SSR-H20, SSR-H21): no
// flag sets them.
func (f *hubFlags) limits() aghub.Limits {
	return aghub.Limits{
		MaxEnvelope:     *f.maxEnvelope,
		MailboxMessages: *f.mailboxMessages, MailboxBytes: *f.mailboxBytes,
		UndeliveredTTL: *f.undeliveredTTL, PollBudget: *f.pollBudget,
		RegisterPerMinute: *f.registerPerMinute, RegisterBurst: *f.registerBurst,
	}
}

// modeFlags name a thing to act on instead of starting the hub. An empty
// value names nothing.
var modeFlags = []string{"clear", "repair-ledger"}

// removedFlags are the flags of 0.2 that are gone. A command line with one
// is refused before anything is opened, exit 2:
//
//   - the action flags, subcommands now (core G12, hub-payment-privacy
//     PAY-U3): hub_flag_removed, with the subcommand to run;
//   - the sealed-sender settings, fixed values now (sealed-sender SSR-H20,
//     SSR-H21): hub_flag_removed.fixed. A hub does not tune them; an
//     operator raises one recipient's quota with anet-hub quota.
var removedFlags = []struct {
	name, subcommand string
	boolean          bool
	// fixed: the setting is a fixed value now (subcommand is empty).
	fixed bool
}{
	{name: "grant", subcommand: "grant"},
	{name: "invite-required", subcommand: "admission"},
	{name: "invite-new", subcommand: "admit", boolean: true},
	{name: "label", subcommand: "admit"},
	{name: "invite-uses", subcommand: "admit"},
	{name: "invite-days", subcommand: "admit"},
	{name: "invite-list", subcommand: "admissions", boolean: true},
	{name: "invite-revoke", subcommand: "admissions revoke"},
	{name: "relay-send-rate", fixed: true},
	{name: "relay-send-burst", fixed: true},
	{name: "keys-lookup-rate", fixed: true},
	{name: "keys-lookup-burst", fixed: true},
	{name: "test-no-fed-key-lookup", boolean: true, fixed: true},
}

// removedUse is one removed flag on the command line.
type removedUse struct {
	flag, subcommand string
	fixed            bool
}

// removedFlagValue records that a removed flag was given; boolean ones take
// no value, the others take one (so the parser stays in step with the rest
// of the command line).
type removedFlagValue struct {
	name, subcommand string
	boolean, fixed   bool
	seen             *[]removedUse
}

func (v *removedFlagValue) String() string { return "" }
func (v *removedFlagValue) Set(string) error {
	*v.seen = append(*v.seen, removedUse{flag: "-" + v.name, subcommand: v.subcommand, fixed: v.fixed})
	return nil
}
func (v *removedFlagValue) IsBoolFlag() bool { return v.boolean }

// defineRemovedFlags declares the removed flags on fs.
func defineRemovedFlags(fs *flag.FlagSet) *[]removedUse {
	seen := &[]removedUse{}
	for _, r := range removedFlags {
		usage := "removed: run anet-hub " + r.subcommand
		if r.fixed {
			usage = "removed: a fixed value now"
		}
		fs.Var(&removedFlagValue{name: r.name, subcommand: r.subcommand, boolean: r.boolean, fixed: r.fixed, seen: seen},
			r.name, usage)
	}
	return seen
}

// refuseEmptyModeFlags rejects a mode flag that was given an empty value.
//
// flag.Parse cannot distinguish -grant "" from -grant being absent, and
// the dispatch below branches on *grant != "" — so `anet-hub -grant
// "$AID"` with AID unset looked exactly like `anet-hub` and started a
// full hub on the -data directory instead of reporting that no account
// was named. FlagSet.Visit reports only the flags actually present on the
// command line, which is the distinction the dispatch cannot make.
//
// The cost is that an empty value can no longer mean "ignore this flag"
// in a wrapper that always passes it. Nothing in this repository does
// that, and a wrapper that wants to omit a flag can omit it.
func refuseEmptyModeFlags(fs *flag.FlagSet) error {
	var bad []string
	fs.Visit(func(fl *flag.Flag) {
		if fl.Value.String() != "" {
			return
		}
		for _, n := range modeFlags {
			if fl.Name == n {
				bad = append(bad, "-"+n)
			}
		}
	})
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%s given an empty value: these flags name what to act on, "+
		"and an unset shell variable expands to nothing. Reading that as "+
		"\"flag not given\" would start the hub instead", strings.Join(bad, ", "))
}

// beforeServing is what the command line asks for other than serving: a
// removed action flag is answered first, before anything is opened, with
// the subcommand to run instead (hub_flag_removed, exit 2); then -version;
// then a subcommand, a one-off operation on the hub's database beside a
// running hub (core G12). done is false when the hub is to be served.
func beforeServing(f *hubFlags, fs *flag.FlagSet, c *console) (code int, done bool) {
	if r := *f.removed; len(r) > 0 {
		if r[0].fixed {
			return c.say("hub_flag_removed.fixed", map[string]string{"flag": r[0].flag}), true
		}
		return c.say("hub_flag_removed", map[string]string{"flag": r[0].flag, "subcommand": r[0].subcommand}), true
	}
	if *f.showVersion {
		fmt.Fprintln(c.out, versionLine())
		return 0, true
	}
	if fs.NArg() > 0 {
		return runSubcommand(c, fs.Arg(0), *f.data, fs.Args()[1:]), true
	}
	return 0, false
}

// versionLine is what -version prints: the release, and the wire contract
// it speaks with the anet release that contract needs. The wire is what an
// operator upgrading from wire 1 has to know about the binary in hand
// before starting it (the first start migrates the database; internal notes
// 0027 in the ANet repository).
func versionLine() string {
	return fmt.Sprintf("anet-hub %s (wire %d, nodes need anet >= %s; commit %s, built %s)",
		version.V, aghub.WireVersion, aghub.RequiredAnet, version.Commit, version.BuiltAt)
}

func main() {
	f := defineFlags(flag.CommandLine)
	flag.Parse()
	c := newConsole(os.Stdout, os.Stderr)
	if code, done := beforeServing(f, flag.CommandLine, c); done {
		os.Exit(code)
	}
	if err := refuseEmptyModeFlags(flag.CommandLine); err != nil {
		log.Fatalf("anet-hub: %v", err)
	}

	store, code := openStore(c, *f.data)
	if store == nil {
		os.Exit(code)
	}
	defer store.Close()

	// ctx is cancelled on SIGINT/SIGTERM; the relay TTL janitor runs under it and stops on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *f.repair != "" {
		if err := repairLedger(*f.data, *f.repair); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *f.showDue {
		if err := listDue(*f.data); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *f.clearPeer != "" {
		if err := clearOwed(*f.data, *f.clearPeer, *f.amount, *f.reason, *f.peerEndpoint, *f.cleared); err != nil {
			log.Fatalf("anet-hub: clear: %v", err)
		}
		return
	}
	hubID, err := hubid.LoadOrIncept(*f.data)
	if err != nil {
		log.Fatalf("anet-hub: hub identity: %v", err)
	}
	log.Printf("anet-hub identity: %s", hubID.AID)

	srv0 := aghub.NewServer(store)
	if err := srv0.SetLimits(f.limits()); err != nil {
		log.Fatalf("anet-hub: relay limits: %v", err)
	}
	if err := srv0.SetPublicURL(*f.publicURL); err != nil {
		log.Fatalf("anet-hub: -public-url: %v", err)
	}
	// This hub's own AID names the ledger it settles on (hub:<aid>), so a
	// credit here is visibly not a credit somewhere else. It is also bound
	// into every relayauth v2 signature, so a signature made for this hub
	// is refused by any other.
	srv0.SetHubAID(hubID.AID)
	// The identity settlements and supply epochs are signed with, so a
	// payer holds a receipt it can show without asking this hub to agree.
	store.SetHubKey(hubID.Ctrl)
	// A supply epoch is published when one is due: now, for a hub that was
	// down over a midnight, and after every UTC midnight (PAY-S2).
	go store.RunSupplyEpochs(ctx)
	// Envelopes nobody collects are deleted after the undelivered TTL.
	go srv0.RunRelayJanitor(ctx, 10*time.Minute)
	// This process is the hub: it drops what it holds in memory for an AID
	// deregistered by another process (anet-hub admissions revoke, the
	// admin tool) within a second (hub-payment-privacy PAY-O2).
	if err := store.StartDeregWatcher(ctx); err != nil {
		log.Fatalf("anet-hub: watching for deregistrations: %v", err)
	}
	// Accounts that never collected their mail in 7 days are deregistered,
	// hourly (PAY-A6).
	go store.RunAdmissionJanitor(ctx, time.Hour)
	// Revocations of delivery credentials are kept 31 days (sealed-sender
	// SSR-H10).
	go store.RunRevocationJanitor(ctx, time.Hour)

	root := newRoot(hubID, srv0)
	deps := &hubDeps{data: *f.data, store: store, hubID: hubID, srv0: srv0, root: root}
	wired, closers, err := wireMounts(deps)
	for _, closer := range closers {
		defer closer()
	}
	if err != nil {
		log.Fatalf("anet-hub: %v", err)
	}
	names := ""
	for _, n := range wired {
		names += " " + n
	}
	log.Printf("anet-hub modules:%s", names)

	srv := &http.Server{
		Addr:              *f.addr,
		Handler:           hubHandler(root),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("anet-hub %s (commit %s) listening on %s (data: %s)",
			version.V, version.Commit, *f.addr, *f.data)
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

// openStore opens the hub's database in dir for serving. A database this
// release does not open (core CORE-V4) is refused with its sentence, exit 1:
// one of 0.2 or earlier (hub_identity_v02), or one a newer anet-hub wrote
// (hub_data_too_new; it is valid data, so the next step is to upgrade, not
// to move it away).
func openStore(c *console, dir string) (*aghub.Store, int) {
	store, err := aghub.Open(dir)
	if err != nil {
		return nil, c.refuseData(err)
	}
	return store, 0
}

// refuseData answers an aghub.Open error: the sentence of a database this
// release does not open, or the error itself (exit 1).
func (c *console) refuseData(err error) int {
	switch {
	case errors.Is(err, aghub.ErrHubDataV02):
		return c.say("hub_identity_v02", nil)
	case errors.Is(err, aghub.ErrHubDataTooNew):
		return c.say("hub_data_too_new", nil)
	}
	return c.fail(err)
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

func clearOwed(dir, peerAID string, credits int64, reason, endpoint, payeeAID string) error {
	// The flag is an int64. It used to arrive here as uint64(*f.amount),
	// so -amount -1000 became 2^64-1000: a statement signed for an amount
	// the peer books as -1000, which raises the debt it claims to settle,
	// and a DischargeDue of -1000, which raised what is due. Only a
	// positive number of credits is a discharge.
	if credits == 0 {
		return fmt.Errorf("-amount is required")
	}
	if credits < 0 {
		return fmt.Errorf("-amount must be a positive number of credits, got %d", credits)
	}
	amount := uint64(credits) // in 1..MaxInt64, checked above
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

	// Requests to the peer are hub requests: they state the wire (core
	// CORE-V1), or a wire-3 peer answers the POST below with 426.
	peer := &http.Client{Transport: wire3.Transport(nil)}

	// What the peer says it is owed before we start, so the answer after
	// can be checked against something rather than taken on faith.
	owedBefore := int64(-1)
	if endpoint != "" {
		if resp, gerr := peer.Get(strings.TrimSuffix(endpoint, "/") + "/x402/supply"); gerr == nil {
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
		owedBefore = credits
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
	resp, err := peer.Post(strings.TrimSuffix(endpoint, "/")+"/federation/clear",
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
		if ack.Owed > owedBefore-credits {
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
		if err := store.DischargeDue(payeeAID, credits); err != nil {
			return fmt.Errorf("delivered, but the local record was not reduced: %w", err)
		}
		fmt.Printf("due to %s reduced by %d\n", payeeAID, amount)
	}
	return nil
}
