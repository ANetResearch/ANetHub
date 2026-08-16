// Command anet-hub-admin runs the Hub operator plane: an admin console + API mounted at /admin, beside
// (never inside) the public anet-hub service. See internal/admin for what it does.
//
// Usage:
//
//	anet-hub-admin [--addr 127.0.0.1:8078] [--hub-data /data/projs/anet-hub/data] \
//	               [--data /data/projs/anet-hub/admin] [--base /admin]
//
// The operator token comes from $ADMIN_TOKEN (default the classic console token). The monitor
// passthrough token comes from $ADMIN_MONITOR_TOKEN (default: same as the operator token).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ANetResearch/ANetHub/internal/admin"
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
	hubData := flag.String("hub-data", "/data/projs/anet-hub/data", "the PUBLIC hub's data directory (hub.db)")
	data := flag.String("data", "/data/projs/anet-hub/admin", "admin plane data directory (admin.db + datasets/)")
	base := flag.String("base", "/admin", "URL base path")
	snapEvery := flag.Duration("snapshot-every", 5*time.Minute, "stats snapshot interval (0 = off)")
	harvestEvery := flag.Duration("harvest-every", 30*time.Minute, "dataset harvest interval (0 = off)")
	restoreFrom := flag.String("restore-agents-from", "", "one-shot recovery: INSERT-OR-IGNORE agents from this backup hub.db into --hub-data, then exit")
	keepOnly := flag.String("keep-only-agents", "", "one-shot: delete all agents EXCEPT this comma-separated AID list (undo an over-broad restore), then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("anet-hub-admin", version.V)
		return
	}
	// One-shot registry recovery (see recovery.go). Additive only — cannot delete/overwrite live agents.
	if *restoreFrom != "" {
		before, after, err := admin.RestoreAgentsFromBackup(*hubData, *restoreFrom)
		if err != nil {
			log.Fatalf("anet-hub-admin: restore: %v", err)
		}
		log.Printf("anet-hub-admin: restored agents from %s — before=%d after=%d (+%d)", *restoreFrom, before, after, after-before)
		return
	}
	if *keepOnly != "" {
		var keep []string
		for _, a := range splitComma(*keepOnly) {
			if a != "" {
				keep = append(keep, a)
			}
		}
		before, after, removed, err := admin.PruneAgentsExcept(*hubData, keep)
		if err != nil {
			log.Fatalf("anet-hub-admin: prune: %v", err)
		}
		log.Printf("anet-hub-admin: pruned agents — before=%d removed=%d after=%d (kept %d)", before, removed, after, len(keep))
		return
	}

	token := os.Getenv("ADMIN_TOKEN")
	if token == "" {
		log.Fatal("ADMIN_TOKEN is required: refusing to start the admin surface with no credential (was: insecure built-in default)")
	}
	monToken := envOr("ADMIN_MONITOR_TOKEN", token)

	store, err := admin.OpenStore(*data)
	if err != nil {
		log.Fatalf("anet-hub-admin: %v", err)
	}
	defer store.Close()
	if err := store.SeedOfficials(); err != nil {
		log.Fatalf("anet-hub-admin: seed officials: %v", err)
	}
	hub, err := admin.OpenHubDB(*hubData)
	if err != nil {
		log.Fatalf("anet-hub-admin: %v", err)
	}
	defer hub.Close()

	monProxy := admin.NewMonitorProxy(monToken)
	hv := admin.NewHarvester(store, hub, monProxy, *data+"/datasets")
	// Semantic capability discovery via the anet-vec service (ChromaDB + CPU embedder). Disabled if
	// unreachable — discovery falls back to the lexical matcher.
	vec := admin.NewVecClient(envOr("ANET_VEC_URL", "http://127.0.0.1:8600"))
	srv0 := admin.NewServer(store, hub, admin.NewOps(90*time.Second), monProxy, hv, vec, token, *base)

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

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
		} else if r != ' ' {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}
