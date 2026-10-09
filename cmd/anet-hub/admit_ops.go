package main

// The admission subcommands (hub-payment-privacy PAY-A7, PAY-U1, PAY-U2):
//
//	anet-hub admit <AID> [--grant N] [--label L]
//	anet-hub admit --file F [--grant N] [--label L]
//	anet-hub admit --window <duration> --max <N> [--label L]
//	anet-hub admit --window off
//	anet-hub admissions [--json]
//	anet-hub admissions revoke <AID>
//	anet-hub admission [open|closed]
//	anet-hub grant <AID> --amount N [--reason R]
//	anet-hub supply                       (supply.go)
//	anet-hub due, anet-hub clear          (clear.go, clear_fed.go)
//	anet-hub redemptions [--json]         (redemptions.go)
//	anet-hub identity status|setup-recovery|rotate   (identity_ops.go)
//	anet-hub restore <backup>             (restore.go; the hub stopped)
//
// Each opens the hub's database beside a running hub (WAL, a busy timeout,
// IMMEDIATE transactions), so none needs the hub stopped, but for the
// identity's setup-recovery and rotate and for restore, which run while it is
// stopped. What they print comes from text.go.

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// subcommands are the one-off operations (core G12). Areas add theirs here.
var subcommands = map[string]func(c *console, data string, args []string) int{
	"admit":       runAdmit,
	"admissions":  runAdmissions,
	"admission":   runAdmission,
	"grant":       runGrant,
	"quota":       runQuota,       // quota.go
	"supply":      runSupply,      // supply.go
	"due":         runDue,         // clear.go; clear is clear_fed.go's
	"identity":    runIdentity,    // identity_ops.go
	"redemptions": runRedemptions, // redemptions.go
	"restore":     runRestore,     // restore.go
}

// runSubcommand runs the subcommand name with args; data is the --data the
// command line gave before the subcommand (the subcommand may give its own).
func runSubcommand(c *console, name, data string, args []string) int {
	f, ok := subcommands[name]
	if !ok {
		return c.usage("anet-hub [flags] | anet-hub admit|admissions|admission|grant|quota|supply|due|clear|redemptions|identity|restore …")
	}
	return f(c, data, args)
}

// parseArgs parses fs over args, with the positional arguments allowed
// between the flags ("admit <AID> --grant 5" as well as "admit --grant 5
// <AID>"). It returns the positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// newSubFlags is a subcommand's flag set, with --data.
func newSubFlags(name, data string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("anet-hub "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs, fs.String("data", data, "data directory of the hub (as anet-hub --data)")
}

// openHub opens the hub's database in dir, which must be one a hub has run
// with: a subcommand pointed at the wrong directory must not create an empty
// hub there and report success. The hub's identity is loaded too: credit a
// subcommand issues comes off the hub's own row, which its AID names.
func openHub(c *console, dir string) (*aghub.Store, int) {
	store, code := openHubData(c, dir)
	if store == nil {
		return nil, code
	}
	id, err := hubid.LoadOrIncept(dir)
	if err != nil {
		store.Close()
		return nil, c.refuseIdentity(err)
	}
	store.SetHubKey(id.Ctrl)
	return store, 0
}

// openHubData is openHub without the hub's identity, for a subcommand that
// only reads the database (anet-hub redemptions): the same refusals of a
// directory that is not the hub's or that this release does not open.
func openHubData(c *console, dir string) (*aghub.Store, int) {
	if _, err := os.Stat(filepath.Join(dir, "hub.db")); err != nil {
		return nil, c.say("data.missing", map[string]string{"path": dir})
	}
	if err := hubid.CheckFile(dir); err != nil {
		return nil, c.refuseIdentity(err)
	}
	store, err := aghub.Open(dir)
	if err != nil {
		return nil, c.refuseData(err)
	}
	return store, 0
}

// fail reports an error no sentence covers (the database could not be read
// or written): the error itself, exit 1. It is not something an operator
// typed wrong.
func (c *console) fail(err error) int {
	c.errw.Write([]byte("anet-hub: " + err.Error() + "\n"))
	return 1
}

// ---- admit ----

func runAdmit(c *console, data string, args []string) int {
	const use = "anet-hub admit <AID> [--grant N] [--label L] | --file F [--grant N] | --window <duration> --max N [--label L] | --window off"
	fs, dataDir := newSubFlags("admit", data)
	grant := fs.Int64("grant", 0, "credits paid when the AID first registers")
	label := fs.String("label", "", "what the admission is for")
	file := fs.String("file", "", "admit every AID in this file, one per line")
	window := fs.String("window", "", "open a sign-up window for this long (e.g. 2h or 3d, at most 7d), or off")
	maxN := fs.Int("max", 0, "the most AIDs the sign-up window admits")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return c.usage(use)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch {
	case set["window"]:
		if len(pos) != 0 || set["file"] || set["grant"] {
			return c.usage(use)
		}
		return admitWindow(c, *dataDir, *window, *maxN, set["max"], *label)
	case set["file"]:
		if len(pos) != 0 || set["max"] || *grant < 0 {
			return c.usage(use)
		}
		store, code := openHub(c, *dataDir)
		if store == nil {
			return code
		}
		defer store.Close()
		n, m, err := store.AdmitFile(*file, *grant, *label, set["label"])
		var bad *aghub.BadLineError
		switch {
		case errors.As(err, &bad):
			return c.say("admit.file_bad_line", map[string]string{"n": num(bad.Line)})
		case err != nil:
			return c.fail(err)
		}
		return c.say("admit.file_ok", map[string]string{"n": num(n), "m": num(m), "path": *file})
	}
	if len(pos) != 1 || set["max"] || *grant < 0 {
		return c.usage(use)
	}
	aid := pos[0]
	if !aghub.ValidAID(aid) {
		return c.say("admit.bad_aid", map[string]string{"value": aid})
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	res, err := store.Admit(aid, *grant, *label, set["label"])
	if err != nil {
		return c.fail(err)
	}
	args2 := map[string]string{"aid": aid}
	switch {
	case res.AlreadyGranted:
		return c.say("admit.already_granted", args2)
	case res.Registered && res.Paid > 0:
		args2["n"] = num(res.Paid)
		return c.say("admit.ok.registered_grant", args2)
	case res.Registered:
		return c.say("admit.ok.registered", args2)
	case res.Grant > 0:
		args2["n"] = num(res.Grant)
		return c.say("admit.ok.grant", args2)
	}
	return c.say("admit.ok", args2)
}

// admitWindow opens or closes the sign-up window.
func admitWindow(c *console, dir, window string, maxN int, maxSet bool, label string) int {
	const use = "anet-hub admit --window <duration> --max N [--label L] | anet-hub admit --window off"
	if window == "off" {
		if maxSet {
			return c.usage(use)
		}
		store, code := openHub(c, dir)
		if store == nil {
			return code
		}
		defer store.Close()
		w, _, err := store.CloseWindow()
		if err != nil {
			return c.fail(err)
		}
		return c.say("admit.window_closed", map[string]string{"n": num(w.Used)})
	}
	d, err := parseWindowLength(window)
	if err != nil || !maxSet {
		return c.usage(use)
	}
	if d <= 0 || d > aghub.MaxWindowLength || maxN <= 0 || maxN > aghub.MaxWindowSize {
		return c.say("admit.window_too_big", nil)
	}
	store, code := openHub(c, dir)
	if store == nil {
		return code
	}
	defer store.Close()
	w, err := store.OpenWindow(d, maxN, label)
	var open *aghub.ErrWindowOpen
	switch {
	case errors.As(err, &open):
		return c.say("admit.window_exists", map[string]string{"time": c.timeText(time.UnixMilli(open.Window.ClosesAt))})
	case errors.Is(err, aghub.ErrWindowTooBig):
		return c.say("admit.window_too_big", nil)
	case err != nil:
		return c.fail(err)
	}
	return c.say("admit.window_open", map[string]string{
		"time": c.timeText(time.UnixMilli(w.ClosesAt)), "n": num(w.Max)})
}

// errWindowLength is parseWindowLength's refusal; the operator is shown the
// usage line.
var errWindowLength = errors.New("window_length")

// parseWindowLength reads the length of a sign-up window: a Go duration
// ("2h", "90m") or a number of days, optionally followed by one ("3d",
// "1d12h"), since a window is counted in days up to its limit of 7.
func parseWindowLength(s string) (time.Duration, error) {
	days, rest, ok := strings.Cut(s, "d")
	if !ok {
		return time.ParseDuration(s)
	}
	n, err := strconv.ParseUint(days, 10, 16)
	if err != nil || days == "" || days[0] == '+' {
		return 0, errWindowLength
	}
	d := time.Duration(n) * 24 * time.Hour
	if rest == "" {
		return d, nil
	}
	more, err := time.ParseDuration(rest)
	if err != nil || more < 0 {
		return 0, errWindowLength
	}
	return d + more, nil
}

// ---- admissions ----

func runAdmissions(c *console, data string, args []string) int {
	const use = "anet-hub admissions [--json] | anet-hub admissions revoke <AID>"
	fs, dataDir := newSubFlags("admissions", data)
	asJSON := fs.Bool("json", false, "print as JSON")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return c.usage(use)
	}
	if len(pos) > 0 {
		if pos[0] != "revoke" || len(pos) != 2 || *asJSON {
			return c.usage(use)
		}
		return admissionsRevoke(c, *dataDir, pos[1])
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	a, err := store.ListAdmissions()
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(a); err != nil {
			return c.fail(err)
		}
		return 0
	}
	c.say("admission."+a.Mode, nil)
	if a.Window != nil {
		c.say("admit.window_open", map[string]string{
			"time": c.timeText(time.UnixMilli(a.Window.ClosesAt)), "n": num(a.Window.Max)})
	}
	// The list itself is data, one AID per line with its label and grant,
	// tab-separated so it can be cut and fed back to anet-hub admit --file.
	for _, r := range a.Admitted {
		state := ""
		if r.Grant > 0 {
			state = num(r.Grant)
			if r.Granted {
				state += "*"
			}
		}
		c.out.Write([]byte(strings.Join([]string{r.AID, state, r.Label}, "\t") + "\n"))
	}
	return 0
}

func admissionsRevoke(c *console, dir, aid string) int {
	if !aghub.ValidAID(aid) {
		return c.say("admit.bad_aid", map[string]string{"value": aid})
	}
	store, code := openHub(c, dir)
	if store == nil {
		return code
	}
	defer store.Close()
	res, err := store.RevokeAdmission(aid)
	switch {
	case errors.Is(err, aghub.ErrNotListed):
		return c.say("admissions.not_listed", map[string]string{"aid": aid})
	case err != nil:
		return c.fail(err)
	case res.Registered:
		return c.say("admissions.revoked_registered", map[string]string{"aid": aid, "n": num(res.Balance)})
	}
	return c.say("admissions.revoked", map[string]string{"aid": aid})
}

// ---- admission ----

func runAdmission(c *console, data string, args []string) int {
	const use = "anet-hub admission [open|closed]"
	fs, dataDir := newSubFlags("admission", data)
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) > 1 {
		return c.usage(use)
	}
	if len(pos) == 1 && pos[0] != aghub.AdmissionOpen && pos[0] != aghub.AdmissionClosed {
		return c.usage(use)
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	if len(pos) == 1 {
		if err := store.SetAdmissionMode(pos[0]); err != nil {
			return c.fail(err)
		}
	}
	mode, err := store.AdmissionMode()
	if err != nil {
		return c.fail(err)
	}
	return c.say("admission."+mode, nil)
}

// ---- grant ----

func runGrant(c *console, data string, args []string) int {
	const use = "anet-hub grant <AID> --amount N [--reason R]"
	fs, dataDir := newSubFlags("grant", data)
	amount := fs.Int64("amount", 0, "credits to grant")
	reason := fs.String("reason", "operator grant", "why, recorded on the ledger entry")
	pos, err := parseArgs(fs, args)
	if err != nil || len(pos) != 1 || *amount <= 0 {
		return c.usage(use)
	}
	aid := pos[0]
	if !aghub.ValidAID(aid) {
		return c.say("admit.bad_aid", map[string]string{"value": aid})
	}
	store, code := openHub(c, *dataDir)
	if store == nil {
		return code
	}
	defer store.Close()
	if !store.KnowsAgent(aid) {
		return c.say("grant.unknown_aid", map[string]string{"aid": aid})
	}
	if err := store.GrantCredit(aid, *amount, *reason); err != nil {
		return c.fail(err)
	}
	bal, err := store.Balance(aid)
	if err != nil {
		return c.fail(err)
	}
	return c.say("grant.ok", map[string]string{"aid": aid, "n": num(*amount), "name": *reason, "m": num(bal)})
}
