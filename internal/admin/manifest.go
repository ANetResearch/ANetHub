package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

// Manifest is the JSON mirror of an ANetAgents AGENT.yaml (schema anet-agent-manifest/1.0). The admin
// plane stores manifests as JSON (the repo keeps YAML for humans; the two are field-identical). Only
// what the ops plane needs is modeled — unknown keys are preserved-by-repo, not here.
type Manifest struct {
	Schema      string   `json:"schema,omitempty"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tier        string   `json:"tier"`         // official | community
	ProductLine string   `json:"product_line"` // anetscreen | anetos | anetpin | anetcraft | agentnetwork | community
	AID         string   `json:"aid,omitempty"`
	Hub         string   `json:"hub,omitempty"`
	Caps        []string `json:"caps,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Maintainer  string   `json:"maintainer,omitempty"`
	Runtime     struct {
		Host         string   `json:"host,omitempty"`
		SSHUser      string   `json:"ssh_user,omitempty"`
		Workdir      string   `json:"workdir,omitempty"`
		Units        []string `json:"units,omitempty"`
		HistoryJSONL string   `json:"history_jsonl,omitempty"`
	} `json:"runtime,omitempty"`
	Monitor struct {
		URL  string `json:"url,omitempty"`
		Auth string `json:"auth,omitempty"` // "token" = classic console token gate (value injected server-side)
	} `json:"monitor,omitempty"`
	Ops struct {
		Allowed []string `json:"allowed,omitempty"` // subset of: status logs start stop restart update
		Update  string   `json:"update,omitempty"`  // the ONE update command an operator may trigger
	} `json:"ops,omitempty"`
	Datasets struct {
		Harvest      bool   `json:"harvest,omitempty"`
		IntentSource string `json:"intent_source,omitempty"` // e.g. "service_id" for AI Studio JobRecs
	} `json:"datasets,omitempty"`
}

var manifestIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ParseManifest decodes + validates a manifest JSON document.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("admin: manifest: %w", err)
	}
	if !manifestIDRe.MatchString(m.ID) {
		return nil, fmt.Errorf("admin: manifest: id %q must match %s", m.ID, manifestIDRe)
	}
	if m.Name == "" {
		return nil, fmt.Errorf("admin: manifest: name required")
	}
	switch m.Tier {
	case "official", "community":
	default:
		return nil, fmt.Errorf("admin: manifest: tier must be official|community, got %q", m.Tier)
	}
	switch m.ProductLine {
	case "anetscreen", "anetos", "anetpin", "anetcraft", "agentnetwork", "community":
	default:
		return nil, fmt.Errorf("admin: manifest: unknown product_line %q", m.ProductLine)
	}
	for _, op := range m.Ops.Allowed {
		if !opAllowed(op) {
			return nil, fmt.Errorf("admin: manifest: unknown op %q", op)
		}
	}
	if m.Tier == "official" && m.Runtime.Host != "" && m.Runtime.SSHUser == "" {
		m.Runtime.SSHUser = "root"
	}
	return &m, nil
}

// OfficialsFileName is the operator-supplied official-agent directory, read
// from the admin plane's own data directory.
const OfficialsFileName = "officials.json"

// OfficialsConfigPath is where SeedOfficialsFromFile looks inside dataDir.
func OfficialsConfigPath(dataDir string) string { return filepath.Join(dataDir, OfficialsFileName) }

// SeedOfficialsFromFile loads the official-agent directory from path and
// inserts the manifests that are not present yet. Manifests already in the
// store are left alone, including operator edits. It returns how many were
// added.
//
// This list used to be a Go literal compiled into the binary, naming a
// production host, its ssh user, its working directory, its systemd units and
// its monitor URL. Two consequences, both of them real:
//
//   - The binary carried the infrastructure topology wherever it was
//     distributed. Anyone holding a copy could read where the fleet runs and
//     which account it runs as.
//   - Every fresh admin.db was seeded with that entry, which made a read-only
//     endpoint (GET /api/official/{id}/monitor/{what}, and the probe behind
//     /api/overview) open an ssh connection to a production machine and run
//     commands there. A deployment that had never been configured for that host
//     still reached out to it.
//
// A missing file therefore means "no official agents" and is not an error: the
// default build knows about no hosts at all, and an operator declares the fleet
// in their own data directory. The cost is that a new deployment has an empty
// ops plane until that file is written, which is the intended trade — an empty
// list reaches nothing.
func (s *Store) SeedOfficialsFromFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("admin: officials %s: %w", path, err)
	}
	var docs []json.RawMessage
	if err := json.Unmarshal(raw, &docs); err != nil {
		return 0, fmt.Errorf("admin: officials %s: expected a JSON array of manifests: %w", path, err)
	}
	added := 0
	for i, d := range docs {
		m, err := ParseManifest(d)
		if err != nil {
			return added, fmt.Errorf("admin: officials %s[%d]: %w", path, i, err)
		}
		if _, err := s.Official(m.ID); err == nil {
			continue // already present (possibly operator-edited) — leave it alone
		}
		if err := s.PutOfficial(m); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}
