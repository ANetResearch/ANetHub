// Command anet-hub-admin runs the Hub operator plane: an admin console + API mounted at /admin, beside
// (never inside) the public anet-hub service. See internal/admin for what it does.
//
// Usage:
//
//	anet-hub-admin [--addr 127.0.0.1:8078] [--hub-data /opt/anet-hub/data] \
//	               [--data /opt/anet-hub/admin] [--base /admin]
//
// The operator token comes from $ADMIN_TOKEN and is required. A placeholder value (CHANGE_ME, the
// value deploy/anet-hub-admin.service ships with, and similar) stops the process from starting.
// `anet-hub-admin -check-token` applies the same rule to $ADMIN_TOKEN and exits 0 or 1 without
// starting, which is how deploy/deploy-admin.sh checks a host before restarting the service.
//
// The official-agent directory is read from <--data>/officials.json, a JSON array of registry-only
// manifests (id, aid, hub, caps and descriptive labels). Absent file → no official agents.
//
// What it refuses to start with, each with one sentence (internal/admin text.go) and before it
// serves anything: --restore-agents-from and --keep-only-agents, removed (exit 2, before any
// database is opened); an admin.db of an earlier release (admin.db_too_old); a hub data directory of
// 0.2 or of a newer anet-hub (anet-hub's own hub_identity_v02 and hub_data_too_new), left as it was.
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

	"github.com/ANetResearch/ANetHub/internal/admin"
	"github.com/ANetResearch/ANetHub/internal/aghub"
	"github.com/ANetResearch/ANetHub/internal/version"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8078", "HTTP listen address (keep loopback; nginx fronts it)")
	hubData := flag.String("hub-data", "/opt/anet-hub/data", "the PUBLIC hub's data directory (hub.db)")
	data := flag.String("data", "/opt/anet-hub/admin", "admin plane data directory (admin.db + datasets/)")
	base := flag.String("base", "/admin", "URL base path")
	snapEvery := flag.Duration("snapshot-every", 5*time.Minute, "stats snapshot interval (0 = off)")
	harvestEvery := flag.Duration("harvest-every", 30*time.Minute,
		"interval of the harvest run, which has no sources and does nothing (0 = off)")
	removed := defineRemovedFlags(flag.CommandLine)
	showVersion := flag.Bool("version", false, "print version and exit")
	checkToken := flag.Bool("check-token", false, "check $ADMIN_TOKEN against the start-up rules and exit: "+
		"0 if the admin surface would start with it, 1 if not (deploy/deploy-admin.sh runs this on the host "+
		"before a restart; the value is not printed)")
	flag.Parse()
	// A removed flag is answered first, before anything is opened.
	if len(*removed) > 0 {
		os.Exit(admin.Say(os.Stderr, (*removed)[0], nil))
	}
	if *showVersion {
		fmt.Println(versionLine())
		return
	}
	if *checkToken {
		if msg := tokenRefusal(os.Getenv("ADMIN_TOKEN")); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
			os.Exit(1)
		}
		return
	}
	token := os.Getenv("ADMIN_TOKEN")
	if msg := tokenRefusal(token); msg != "" {
		log.Fatal(msg)
	}
	if admin.WeakToken(token) {
		// Loud, repeated, and not fatal.
		//
		// Not fatal because refusing here takes the admin surface down on
		// the next deploy of a hub that is working, and an operator who
		// discovers that from an outage learns it at the worst moment.
		// Loud because this credential is in a public repository and the
		// surface it guards can delete agents — a warning nobody reads is
		// the same as no warning, so it is printed at start and every hour
		// it keeps running.
		warn := func() {
			log.Printf("SECURITY: ADMIN_TOKEN is a credential this software published. " +
				"Anyone who has read the source can log in. Set a new one in the unit " +
				"file and restart. The admin surface can delete agents from the registry.")
		}
		warn()
		go func() {
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for range t.C {
				warn()
			}
		}()
	}
	store, err := admin.OpenStore(*data)
	if errors.Is(err, admin.ErrAdminDBTooOld) {
		os.Exit(admin.Say(os.Stderr, "admin.db_too_old", nil))
	}
	if err != nil {
		log.Fatalf("anet-hub-admin: %v", err)
	}
	defer store.Close()
	// The official-agent directory comes from the admin plane's own data
	// directory, not from the binary. Absent file → no official agents. A
	// manifest that still carries runtime, monitor, ops or datasets is
	// refused and stops the start (see admin.ParseManifest).
	officialsPath := admin.OfficialsConfigPath(*data)
	added, err := store.SeedOfficialsFromFile(officialsPath)
	if err != nil {
		log.Fatalf("anet-hub-admin: officials: %v", err)
	}
	if added > 0 {
		log.Printf("anet-hub-admin: loaded %d official agent(s) from %s", added, officialsPath)
	}
	hub, err := admin.OpenHubDB(*hubData)
	if code, refused := refuseHubData(err); refused {
		os.Exit(code)
	}
	if err != nil {
		log.Fatalf("anet-hub-admin: %v", err)
	}
	defer hub.Close()

	hv := admin.NewHarvester(*data + "/datasets")
	// Semantic capability discovery via the anet-vec service (ChromaDB + CPU embedder). Disabled if
	// unreachable — discovery falls back to the lexical matcher.
	vec := admin.NewVecClient(envOr("ANET_VEC_URL", "http://127.0.0.1:8600"))
	srv0 := admin.NewServer(store, hub, hv, vec, token, *base)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv0.StartTickers(ctx, *snapEvery, *harvestEvery)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           srv0.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("anet-hub-admin %s listening on %s (base %s, hub data %s, admin data %s)",
			version.V, *addr, *base, *hubData, *data)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("anet-hub-admin: serve: %v", err)
		}
	}()
	<-ctx.Done()
	log.Println("anet-hub-admin: shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
}

// tokenRefusal returns why the admin surface must not start with token, or
// "" when it may. The start-up path and -check-token both call it, so the
// deployment check and the service decide the same way.
//
// A placeholder is fatal, unlike the published defaults (admin.WeakToken,
// which only warn): a placeholder was never chosen by anyone, so the
// deployment was installed from the template and not configured, and the
// value is readable in this repository.
func tokenRefusal(token string) string {
	if token == "" {
		return "ADMIN_TOKEN is required: refusing to start the admin surface with no credential (was: insecure built-in default)"
	}
	if admin.PlaceholderToken(token) {
		return "ADMIN_TOKEN is a placeholder (for example CHANGE_ME from the unit template): " +
			"refusing to start the admin surface. Set a random token in the unit's environment and restart."
	}
	return ""
}

// versionLine is what --version prints.
//
// It printed the release constant alone, which is hand-maintained and identical
// for every build cut between two releases — so it could not answer "is this
// artifact the one I just built". deploy-admin.sh greps this line for
// commit=unknown to refuse shipping a binary that was built without the
// -ldflags stamp; /admin/healthz reports the same three fields at runtime.
func versionLine() string {
	return fmt.Sprintf("anet-hub-admin %s commit=%s built_at=%s", version.V, version.Commit, version.BuiltAt)
}

// refuseHubData answers a hub data directory this release does not open (core CORE-V4) with the
// sentence anet-hub gives for it, exit 1: data of 0.2 or earlier (hub_identity_v02), or data a newer
// anet-hub wrote (hub_data_too_new). OpenHubDB has left the directory as it was.
func refuseHubData(err error) (code int, refused bool) {
	switch {
	case errors.Is(err, aghub.ErrHubDataV02):
		return admin.Say(os.Stderr, "hub_identity_v02", nil), true
	case errors.Is(err, aghub.ErrHubDataTooNew):
		return admin.Say(os.Stderr, "hub_data_too_new", nil), true
	}
	return 0, false
}

// removedFlags are the flags of the two paths that wrote stored key histories back into the
// registry, with the sentence each is answered with (hub-payment-privacy PAY-O4). They stay known to
// the parser so that a command line with one is answered with what to do instead, exit 2, rather
// than with "flag provided but not defined".
var removedFlags = []struct{ name, key string }{
	{"restore-agents-from", "admin.flag_removed.restore"},
	{"keep-only-agents", "admin.flag_removed.prune"},
}

// removedFlag records that a removed flag was given. It takes no value of its own (a bool flag), so
// "--restore-agents-from x" and a flag given last are both recognised; "=x" is accepted and ignored.
type removedFlag struct {
	key  string
	seen *[]string
}

func (f removedFlag) String() string   { return "" }
func (f removedFlag) IsBoolFlag() bool { return true }
func (f removedFlag) Set(string) error {
	*f.seen = append(*f.seen, f.key)
	return nil
}

// defineRemovedFlags declares the removed flags on fs; the returned list collects the sentence key
// of each one given, in order.
func defineRemovedFlags(fs *flag.FlagSet) *[]string {
	seen := &[]string{}
	for _, r := range removedFlags {
		fs.Var(removedFlag{key: r.key, seen: seen}, r.name, "removed (see the sentence it is answered with)")
	}
	return seen
}
