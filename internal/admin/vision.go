package admin

import "context"

// vision maps the live state of the platform onto the six capability leaps of
// the agent-internet roadmap, so that the roadmap can be measured. Each leap
// gives what it is, which ANetHub component carries it and its current
// metrics. It serves both as external narrative and as an operator self-check.
// The text is English; the JSON field names and the metric keys (snake_case)
// are stable.

// VisionLeap is one capability leap.
type VisionLeap struct {
	Key       string         `json:"key"`
	Title     string         `json:"title"`     // the roadmap deliverable
	Leap      string         `json:"leap"`      // the leap in one sentence
	Component string         `json:"component"` // the ANetHub component that carries it
	Metrics   map[string]any `json:"metrics"`   // current metrics
	Status    string         `json:"status"`    // live | partial | planned
}

// VisionMap is the six leaps and an overview.
type VisionMap struct {
	Headline string       `json:"headline"`
	Leaps    []VisionLeap `json:"leaps"`
}

// buildVisionMap computes the live vision map from the hub + admin state.
func (s *Server) buildVisionMap(ctx context.Context) VisionMap {
	totals, _ := s.hub.Totals()
	officials, _ := s.store.Officials()
	counts, _ := s.store.SessionCounts()
	states, _ := s.store.HarvestStates()
	caps := s.buildCapsules(ctx)

	var sessions, records int64
	for _, c := range counts {
		sessions += c["sessions"]
	}
	for _, st := range states {
		records += int64(st.Records)
	}
	official, community := 0, 0
	for _, c := range caps {
		if c.Tier == "official" {
			official++
		} else {
			community++
		}
	}

	return VisionMap{
		Headline: "The internet carries information, the Internet of Things connects devices, and the agent internet carries capability and organises action; ANetHub is the operable foundation of that backbone.",
		Leaps: []VisionLeap{
			{
				Key: "backbone", Title: "One agent-internet backbone", Component: "Hub relay and delegation (task passing and delivery verification)",
				Leap:    "From connecting information and devices to connecting capability and forming organisations",
				Metrics: map[string]any{"registered_agents": totals.Agents, "published_receipts": totals.TasksCompleted, "verified_reviews": totals.Reviews, "relay_backlog": totals.RelayBacklog},
				Status:  "live",
			},
			{
				Key: "discovery", Title: "Agent identity and capability discovery network", Component: "Self-certifying KEL identity, capability package registry and task-to-capability discovery",
				Leap:    "From people finding tools and orchestrating by hand to tasks finding capability and forming an executing organisation automatically",
				Metrics: map[string]any{"capability_packages": len(caps), "official_capabilities": official, "community_capabilities": community, "listed_providers": totals.Listed},
				Status:  "partial",
			},
			{
				Key: "access", Title: "Access layer for digital and physical resources", Component: "ANetOS AI Studio (unified access gateway for digital resources)",
				Leap:    "From custom integration of each system to one network-wide call surface for digital and physical resources",
				Metrics: map[string]any{"official_gateways": len(officials), "ai_studio_models": 108, "general_capabilities": 9, "embodied_access": "ANetScreen/ANetOS (roadmap)"},
				Status:  "partial",
			},
			{
				Key: "regulation", Title: "Trusted execution and security oversight", Component: "Admin oversight plane (registry oversight, listing and delisting, audit)",
				Leap:    "From governing single outputs to governing organised action: authorisable, interruptible, auditable and accountable",
				Metrics: map[string]any{"registered_official_agents": len(officials), "audit_trail": "every mutating operation", "circuit_breaker": "registry delisting and restoration", "task_content": "neither the hub nor admin holds task content"},
				Status:  "live",
			},
			{
				Key: "evolution", Title: "Global capability repository and evolution network", Component: "Capability package catalogue (harvesting is removed: the hub holds no task content)",
				Leap:    "From rebuilding the same thing per site and project to verifying once, reusing everywhere and evolving continuously",
				Metrics: map[string]any{"legacy_sessions_pending_cleanup": sessions, "legacy_records_pending_cleanup": records, "harvest_sources": 0, "legacy_harvest_cursors": len(states)},
				Status:  "planned",
			},
			{
				Key: "demonstration", Title: "Flagship demonstration projects", Component: "Agent organisations across product lines (ANetScreen, ANetOS, ANetPIN, ANetCraft)",
				Leap:    "From single-scenario automation in closed systems to society-scale organisational intelligence across industries, regions and parties",
				Metrics: map[string]any{"product_lines": "ANetOS smart frame; ANetCraft arena (running)", "flagship_project": "Global embodied-intelligence capability sharing and transfer network (vision)"},
				Status:  "planned",
			},
		},
	}
}
