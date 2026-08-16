package admin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The ops executor gives operators "彻底观测" over OFFICIAL agents: liveness, logs, lifecycle
// (start/stop/restart) and a single manifest-declared update command — all over ssh to the agent's
// declared runtime host. The op set is a CLOSED whitelist; free-form commands are structurally
// impossible (there is no API that takes a command string — only an op name + a bounded argument).

var opWhitelist = map[string]bool{
	"status": true, "logs": true, "start": true, "stop": true, "restart": true, "update": true,
}

func opAllowed(op string) bool { return opWhitelist[op] }

// OpResult is one executed op.
type OpResult struct {
	Op         string `json:"op"`
	Command    string `json:"command"` // what actually ran (for the audit trail + UI transparency)
	Output     string `json:"output"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Err        string `json:"err,omitempty"`
}

// Probe is a cached liveness reading for one official agent.
type Probe struct {
	ID        string            `json:"id"`
	CheckedAt string            `json:"checked_at"`
	Units     map[string]string `json:"units,omitempty"`   // unit → is-active output (active/inactive/failed/…)
	Monitor   string            `json:"monitor,omitempty"` // ok | unreachable | <error>
	SSH       string            `json:"ssh"`               // ok | <error> — whether the ops channel works at all
}

// Ops executes whitelisted operations against official agents' runtime hosts.
type Ops struct {
	timeout time.Duration

	mu     sync.Mutex
	probes map[string]Probe // id → last probe (TTL-cached)
}

// NewOps returns an executor with the given per-op timeout.
func NewOps(timeout time.Duration) *Ops {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &Ops{timeout: timeout, probes: map[string]Probe{}}
}

// sshArgs builds the ssh invocation for a manifest host. BatchMode keeps a missing key from hanging on
// a password prompt — it fails fast and the error surfaces in the UI.
func sshArgs(m *Manifest, remoteCmd string) []string {
	user := m.Runtime.SSHUser
	if user == "" {
		user = "root"
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=8",
		"-o", "StrictHostKeyChecking=accept-new",
		user + "@" + m.Runtime.Host,
		"--", remoteCmd,
	}
}

// shq single-quotes s for safe embedding in a remote shell command line.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// buildCommand maps (manifest, op, arg) to the remote command line. arg's meaning is per-op: for
// "logs" it is "[unit] [lines]"; other ops ignore it.
func buildCommand(m *Manifest, op, arg string) (string, error) {
	units := m.Runtime.Units
	if len(units) == 0 && op != "update" {
		return "", fmt.Errorf("admin: manifest %s declares no systemd units", m.ID)
	}
	quoted := make([]string, len(units))
	for i, u := range units {
		quoted[i] = shq(u)
	}
	all := strings.Join(quoted, " ")
	switch op {
	case "status":
		return fmt.Sprintf("systemctl is-active %s; systemctl status --no-pager -l -n 5 %s | head -100", all, all), nil
	case "logs":
		unit, lines := units[len(units)-1], 200 // default: the worker unit (last declared), 200 lines
		if arg != "" {
			parts := strings.Fields(arg)
			for _, p := range parts {
				if n, err := strconv.Atoi(p); err == nil {
					if n > 0 && n <= 2000 {
						lines = n
					}
					continue
				}
				ok := false
				for _, u := range units {
					if u == p {
						unit, ok = p, true
						break
					}
				}
				if !ok {
					return "", fmt.Errorf("admin: %q is not a declared unit of %s", p, m.ID)
				}
			}
		}
		return fmt.Sprintf("journalctl -u %s -n %d --no-pager", shq(unit), lines), nil
	case "start", "stop", "restart":
		return fmt.Sprintf("systemctl %s %s; sleep 1; systemctl is-active %s", op, all, all), nil
	case "update":
		if strings.TrimSpace(m.Ops.Update) == "" {
			return "", fmt.Errorf("admin: manifest %s declares no update command", m.ID)
		}
		return m.Ops.Update, nil
	default:
		return "", fmt.Errorf("admin: unknown op %q", op)
	}
}

// Run executes one whitelisted op for m. It checks the manifest's own allowed list, so an operator can
// narrow (never widen) what each agent supports.
func (o *Ops) Run(ctx context.Context, m *Manifest, op, arg string) OpResult {
	res := OpResult{Op: op}
	if !opAllowed(op) {
		res.Err = fmt.Sprintf("unknown op %q", op)
		return res
	}
	allowed := false
	for _, a := range m.Ops.Allowed {
		if a == op {
			allowed = true
			break
		}
	}
	if !allowed {
		res.Err = fmt.Sprintf("op %q not allowed by manifest %s", op, m.ID)
		return res
	}
	if m.Runtime.Host == "" {
		res.Err = "manifest declares no runtime host"
		return res
	}
	cmd, err := buildCommand(m, op, arg)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Command = cmd
	cctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	start := time.Now()
	c := exec.CommandContext(cctx, "ssh", sshArgs(m, cmd)...)
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err = c.Run()
	res.DurationMs = time.Since(start).Milliseconds()
	out := buf.Bytes()
	if len(out) > 64<<10 {
		out = out[len(out)-(64<<10):] // keep the tail — that's where failures show
	}
	res.Output = string(out)
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
		res.Err = err.Error()
	}
	return res
}

// probeTTL bounds how stale a cached liveness reading may be.
const probeTTL = 2 * time.Minute

// Probe returns a liveness reading for m, cached up to probeTTL (force bypasses the cache). It checks
// two independent channels: systemd unit state over ssh (may be unavailable if the ops key is not yet
// authorized on the host) and the agent's monitor /healthz over HTTP.
func (o *Ops) Probe(ctx context.Context, m *Manifest, force bool) Probe {
	o.mu.Lock()
	if p, ok := o.probes[m.ID]; ok && !force {
		if t, err := time.Parse(time.RFC3339, p.CheckedAt); err == nil && time.Since(t) < probeTTL {
			o.mu.Unlock()
			return p
		}
	}
	o.mu.Unlock()

	p := Probe{ID: m.ID, CheckedAt: nowRFC3339(), Units: map[string]string{}}

	// Channel 1: systemd over ssh.
	if m.Runtime.Host != "" && len(m.Runtime.Units) > 0 {
		quoted := make([]string, len(m.Runtime.Units))
		for i, u := range m.Runtime.Units {
			quoted[i] = shq(u)
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c := exec.CommandContext(cctx, "ssh", sshArgs(m, "systemctl is-active "+strings.Join(quoted, " "))...)
		out, err := c.CombinedOutput()
		cancel()
		lines := strings.Fields(strings.TrimSpace(string(out)))
		// is-active prints one state per unit and exits non-zero when any is inactive — the per-unit
		// lines are still meaningful, so only a transport-level failure (no output) marks ssh down.
		if len(lines) == len(m.Runtime.Units) {
			p.SSH = "ok"
			for i, u := range m.Runtime.Units {
				p.Units[u] = lines[i]
			}
		} else if err != nil {
			p.SSH = strings.TrimSpace(string(out))
			if p.SSH == "" {
				p.SSH = err.Error()
			}
		}
	} else {
		p.SSH = "no runtime host declared"
	}

	// Channel 2: monitor healthz.
	if m.Monitor.URL != "" {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, _ := http.NewRequestWithContext(cctx, http.MethodGet, strings.TrimRight(m.Monitor.URL, "/")+"/healthz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			p.Monitor = "unreachable"
		} else {
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				p.Monitor = "ok"
			} else {
				p.Monitor = fmt.Sprintf("http %d", resp.StatusCode)
			}
		}
		cancel()
	}

	o.mu.Lock()
	o.probes[m.ID] = p
	o.mu.Unlock()
	return p
}
