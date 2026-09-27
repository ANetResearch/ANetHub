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

// Manifest registers one official agent in the admin plane.
//
// It is a registry entry and nothing more: id, AID, hub and capabilities, plus descriptive labels
// (name, tier, product line, summary, maintainer) used to group and display agents. Earlier versions
// also carried runtime (an ssh host, user, working directory, systemd units and a job-history path),
// monitor (a URL and the agent's console token) and ops (lifecycle commands to run over ssh), and
// datasets (whether to harvest the agent's job history, prompts included). With those the admin
// plane on the hub host could read an official agent's task content and operate it as root. They
// are removed (A2A-DESIGN §9 row admin 官方 agent, §15, [C39]); operating an official agent is done
// with a separate tool that does not run on the hub host.
//
// ParseManifest refuses a document that still carries any of the four removed keys, so that an
// operator's old manifest is reported rather than silently reduced.
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
}

// removedManifestKeys are the manifest sections the admin plane no longer accepts.
var removedManifestKeys = []string{"runtime", "monitor", "ops", "datasets"}

var manifestIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ParseManifest decodes + validates a manifest JSON document.
func ParseManifest(raw []byte) (*Manifest, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("admin: manifest: %w", err)
	}
	for _, k := range removedManifestKeys {
		if _, ok := keys[k]; ok {
			return nil, fmt.Errorf("admin: manifest: %q is no longer accepted: an official agent is "+
				"registered by id, aid, hub and caps only (runtime, monitor, ops and datasets were "+
				"removed); delete the key and submit the manifest again", k)
		}
	}
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
// its monitor URL, so the binary carried the infrastructure topology wherever
// it was distributed. It is operator configuration instead, and since the
// removal of runtime, monitor, ops and datasets it names no host at all.
//
// A missing file means "no official agents" and is not an error. A file whose
// manifests still carry a removed section is an error, which stops the admin
// plane from starting until the file is corrected.
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
