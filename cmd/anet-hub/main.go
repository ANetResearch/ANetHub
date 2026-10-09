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
	"errors"
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
		"how long an undelivered envelope is kept before it is deleted: at most "+
			aghub.MaxUndeliveredTTL.String()+" ("+daysText(aghub.MaxUndeliveredTTL)+", the message lifetime "+
			"minus the delivery deadline minus the allowed clock skew), since an envelope kept longer could "+
			"outlive the only key that opens it; a longer value stops the start")
	f.pollBudget = fs.Int64("relay-poll-budget", def.PollBudget,
		"cumulative envelope bytes one /relay/poll response returns (the first message always)")
	f.registerPerMinute = fs.Float64("register-rate", def.RegisterPerMinute,
		"per-client-IP /register token refill, per minute (429 when empty)")
	f.registerBurst = fs.Int("register-burst", def.RegisterBurst, "per-client-IP /register token bucket size")
	return f
}

// daysText writes d as days, hours and minutes ("14 days 22 h 55 min"), for
// a help text whose value is in hours.
func daysText(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	return fmt.Sprintf("%d days %d h %d min", days, d/time.Hour, (d%time.Hour)/time.Minute)
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

// removedFlags are the flags of 0.2 that are gone. A command line with one
// is refused before anything is opened, exit 2:
//
//   - the action flags, subcommands now (core G12, hub-payment-privacy
//     PAY-U3): hub_flag_removed, with the subcommand to run. A flag that
//     only qualified an action (-amount, -label) names the subcommand of
//     the action it went with; when the action's own flag is on the same
//     command line, that one is answered;
//   - -repair-ledger, which has no replacement: the ledger keeps 14 days,
//     so there is no gap left to repair (hub_flag_removed.none);
//   - the sealed-sender settings, fixed values now (sealed-sender SSR-H20,
//     SSR-H21): hub_flag_removed.fixed. A hub does not tune them; an
//     operator raises one recipient's quota with anet-hub quota.
var removedFlags = []struct {
	name, subcommand string
	boolean          bool
	// modifier: the flag qualified an action flag rather than being one.
	modifier bool
	// fixed: the setting is a fixed value now (subcommand is empty).
	fixed bool
	// none: removed with no replacement (subcommand is empty).
	none bool
}{
	{name: "grant", subcommand: "grant"},
	{name: "invite-required", subcommand: "admission"},
	{name: "invite-new", subcommand: "admit", boolean: true},
	{name: "label", subcommand: "admit", modifier: true},
	{name: "invite-uses", subcommand: "admit", modifier: true},
	{name: "invite-days", subcommand: "admit", modifier: true},
	{name: "invite-list", subcommand: "admissions", boolean: true},
	{name: "invite-revoke", subcommand: "admissions revoke"},
	{name: "clear", subcommand: "clear"},
	{name: "amount", subcommand: "clear", modifier: true},
	{name: "payee", subcommand: "clear", modifier: true},
	{name: "peer-endpoint", subcommand: "clear", modifier: true},
	{name: "reason", subcommand: "grant", modifier: true},
	{name: "due", subcommand: "due", boolean: true},
	{name: "repair-ledger", none: true},
	{name: "relay-send-rate", fixed: true},
	{name: "relay-send-burst", fixed: true},
	{name: "keys-lookup-rate", fixed: true},
	{name: "keys-lookup-burst", fixed: true},
	{name: "test-no-fed-key-lookup", boolean: true, fixed: true},
}

// removedUse is one removed flag on the command line.
type removedUse struct {
	flag, subcommand      string
	modifier, fixed, none bool
}

// removedFlagValue records that a removed flag was given; boolean ones take
// no value, the others take one (so the parser stays in step with the rest
// of the command line). An empty value is recorded too: -clear "$PEER"
// with PEER unset is still a removed flag, not a hub to start.
type removedFlagValue struct {
	name, subcommand               string
	boolean, modifier, fixed, none bool
	seen                           *[]removedUse
}

func (v *removedFlagValue) String() string { return "" }
func (v *removedFlagValue) Set(string) error {
	*v.seen = append(*v.seen, removedUse{flag: "-" + v.name, subcommand: v.subcommand,
		modifier: v.modifier, fixed: v.fixed, none: v.none})
	return nil
}
func (v *removedFlagValue) IsBoolFlag() bool { return v.boolean }

// defineRemovedFlags declares the removed flags on fs.
func defineRemovedFlags(fs *flag.FlagSet) *[]removedUse {
	seen := &[]removedUse{}
	for _, r := range removedFlags {
		usage := "removed: run anet-hub " + r.subcommand
		switch {
		case r.fixed:
			usage = "removed: a fixed value now"
		case r.none:
			usage = "removed, with no replacement"
		}
		fs.Var(&removedFlagValue{name: r.name, subcommand: r.subcommand, boolean: r.boolean,
			modifier: r.modifier, fixed: r.fixed, none: r.none, seen: seen}, r.name, usage)
	}
	return seen
}

// firstRemoved is the removed flag a command line is answered for: the
// first one given that is an action or a setting, else the first one.
func firstRemoved(r []removedUse) removedUse {
	for _, u := range r {
		if !u.modifier {
			return u
		}
	}
	return r[0]
}

// beforeServing is what the command line asks for other than serving: a
// removed action flag is answered first, before anything is opened, with
// the subcommand to run instead (hub_flag_removed, exit 2); then -version;
// then a subcommand, a one-off operation on the hub's database beside a
// running hub (core G12). done is false when the hub is to be served.
func beforeServing(f *hubFlags, fs *flag.FlagSet, c *console) (code int, done bool) {
	if r := *f.removed; len(r) > 0 {
		u := firstRemoved(r)
		switch {
		case u.fixed:
			return c.say("hub_flag_removed.fixed", map[string]string{"flag": u.flag}), true
		case u.none:
			return c.say("hub_flag_removed.none", map[string]string{"flag": u.flag}), true
		}
		return c.say("hub_flag_removed", map[string]string{"flag": u.flag, "subcommand": u.subcommand}), true
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
// operator has to know about the binary in hand before starting it: a data
// directory another release wrote is refused, not converted (core CORE-V4).
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

	store, code := openStore(c, *f.data)
	if store == nil {
		os.Exit(code)
	}
	defer store.Close()

	// ctx is cancelled on SIGINT/SIGTERM; the relay TTL janitor runs under it and stops on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The hub identity, under the data directory's lock for as long as the
	// hub runs: an identity rotation waits for the hub to stop (KEL H-32).
	hubID, lock, code := startIdentity(c, *f.data, store, log.Printf)
	if hubID == nil {
		os.Exit(code)
	}
	defer lock.Release()
	log.Printf("anet-hub identity: %s", hubID.AID)

	// The review tag key (hub-payment-privacy §3.3): made on the first
	// start, and a key file this hub cannot use stops the start here
	// rather than at the first review.
	if id, err := store.LoadReviewTagKey(); err != nil {
		log.Fatalf("anet-hub: %v", err)
	} else {
		log.Printf("anet-hub review tag key: tag_key_id %d", id)
	}

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
	// startIdentity handed the store the identity settlements and supply
	// epochs are signed with, so a payer holds a receipt it can show
	// without asking this hub to agree.
	// A supply epoch is published when one is due: now, for a hub that was
	// down over a midnight, and after every UTC midnight (PAY-S2).
	go store.RunSupplyEpochs(ctx)
	// The ledger window: what each settlement and redemption left behind is
	// deleted on its schedule, hourly (hub-payment-privacy PAY-L2).
	go store.RunLedgerJanitor(ctx)
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
	// The witness notice of every agent a sender can find here is kept at
	// most 10 minutes old, whether or not the agent polled lately (KEL
	// H-11, D-26).
	go store.RunNoticeRefresher(ctx)

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
// to move it away). A hub identity file of 0.2 is refused the same way
// (hub_identity_v02, KEL S-2), before anything in dir is opened.
func openStore(c *console, dir string) (*aghub.Store, int) {
	if err := hubid.CheckFile(dir); err != nil {
		return nil, c.refuseIdentity(err)
	}
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
