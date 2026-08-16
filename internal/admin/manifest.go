package admin

import (
	"encoding/json"
	"fmt"
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

// seedManifests is the built-in official-agent directory, applied on first boot so a fresh admin plane
// knows the fleet without manual entry. Source of truth is the ANetAgents repo (one AGENT.yaml per
// folder); keep this in sync when agents are added there.
var seedManifests = []string{`{
  "schema": "anet-agent-manifest/1.0",
  "id": "ai-studio",
  "name": "ANetOS AI Studio",
  "tier": "official",
  "product_line": "anetos",
  "aid": "bafyreicyovw3nmfbjd5ky2l7ovcjez4kf7vivhprudcowtmsovmnwzxsim",
  "hub": "https://hub.agentnetwork.org.cn",
  "caps": ["chat", "image-generation", "image-edit", "photo-restore", "video-generation", "tts", "asr", "vision", "embedding", "translate", "ai-art", "smart-frame"],
  "summary": "AI generation service agent on AgentNetwork — v2 exposes the FULL Gravitex + Bailian surface (any LLM chat, t2i/i2i, t2v/i2v, TTS/ASR, vision, embedding) as universal services with per-call model selection, plus 25 curated ANetOS frame services. Authorized access only (ACL allowlist).",
  "maintainer": "anet-core",
  "runtime": {
    "host": "bmax.chatchat.space",
    "ssh_user": "root",
    "workdir": "/data/projs/anet-ai-srv",
    "units": ["anet-ai-daemon.service", "anet-ai-srv.service"],
    "history_jsonl": "/data/projs/anet-ai-srv/history.jsonl"
  },
  "monitor": {"url": "http://bmax.chatchat.space:8791", "auth": "token"},
  "ops": {
    "allowed": ["status", "logs", "start", "stop", "restart", "update"],
    "update": "systemctl restart anet-ai-srv"
  },
  "datasets": {"harvest": true, "intent_source": "service_id"}
}`}

// SeedOfficials inserts the built-in manifests that are not present yet (never overwrites edits).
func (s *Store) SeedOfficials() error {
	for _, raw := range seedManifests {
		m, err := ParseManifest([]byte(raw))
		if err != nil {
			return fmt.Errorf("admin: seed: %w", err)
		}
		if _, err := s.Official(m.ID); err == nil {
			continue // already present (possibly operator-edited) — leave it alone
		}
		if err := s.PutOfficial(m); err != nil {
			return err
		}
	}
	return nil
}
