package admin

import "context"

// Harvester is what remains of the dataset harvest: the scheduled run, with
// no sources.
//
// Earlier versions had two sources, both removed (A2A-DESIGN §9 row admin
// 采集, [C39]):
//
//	hub-relay  decoded every relay payload in hub.db (the delegation goal,
//	           chat bodies and the deliverable) into JSONL files under
//	           datasets/ and a session index in admin.db, kept beyond the
//	           relay's own retention.
//	ai-studio  copied official agents' job history, including each job's
//	           prompt, over ssh or through the agent's monitor.
//
// Both made the hub host a holder of task content, which the hub must not
// be. RunAll is kept, with no sources, so that the ticker and the
// operator's "run harvest" action stay valid calls and a test can pin that
// they touch nothing. The files earlier versions wrote under the datasets
// root are neither read nor served; the production cleanup
// (deploy/cleanup-content-v0.2.sh) deletes them.
type Harvester struct {
	root string // datasets root directory earlier versions wrote to
}

// NewHarvester returns a harvester; root is the datasets directory earlier
// versions wrote to.
func NewHarvester(root string) *Harvester {
	return &Harvester{root: root}
}

// Root returns the datasets root directory.
func (hv *Harvester) Root() string { return hv.root }

// RunResult summarizes one harvest pass of one source.
type RunResult struct {
	Source   string `json:"source"`
	Events   int    `json:"events"`
	Sessions int    `json:"sessions"`
	Cursor   string `json:"cursor"`
	Err      string `json:"err,omitempty"`
}

// RunAll runs every harvest source once. There are none: it reads no
// database, contacts no host, writes nothing under the datasets root and
// returns an empty list. Adding a source here is adding a content path to
// the hub host, which A2A-DESIGN §9 forbids; TestRunAllTouchesNothing
// fails if one is added.
func (hv *Harvester) RunAll(ctx context.Context) []RunResult {
	return []RunResult{}
}
