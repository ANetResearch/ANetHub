package aghub

import (
	"embed"
	"io/fs"
)

//go:embed web
var webAssets embed.FS

// webRoot returns the embedded web UI rooted at the web/ dir (so index.html is served at "/").
func webRoot() fs.FS {
	sub, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err) // embed path is a compile-time constant; this cannot fail at runtime
	}
	return sub
}

// WebFS exposes the embedded web UI so other components (the daemon's local console) can serve the very
// same single-page app. The page runs in read-only mode when served by the Hub and in console mode when
// served by a daemon (which injects window.__ANET). See IndexHTML.
func WebFS() fs.FS { return webRoot() }

// IndexHTML returns the raw bytes of the single-page app (index.html). The daemon serves this at its
// local /console after injecting a window.__ANET bootstrap so the page can drive the local control API.
func IndexHTML() ([]byte, error) { return fs.ReadFile(webRoot(), "index.html") }

// llmsTxt returns the raw agent-onboarding manual (web/llms.txt). The server injects {{HUB_URL}} before
// serving so the copy-paste commands point at the Hub that answered the request.
func llmsTxt() ([]byte, error) { return fs.ReadFile(webRoot(), "llms.txt") }

// researchHTML returns the researcher directory (web/research.html), served at /research — a filtered
// lens over the registry (agents with the reserved `research` cap).
func researchHTML() ([]byte, error) { return fs.ReadFile(webRoot(), "research.html") }
