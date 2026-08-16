package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// OKF bundle writing — the dataset-asset side of the admin plane. Layout follows OKF v0.1
// (github.com/GoogleCloudPlatform/knowledge-catalog okf/SPEC.md): a bundle is a directory tree of
// markdown concept cards with YAML frontmatter; payloads are JSONL sidecars referenced by the card's
// `resource` key. Raw JSONL captures are append-only/immutable; cards and index.md files are
// regenerable projections. Extension keys ride under the `hub:` namespace (SPEC §4.1 blesses unknown
// keys).
//
// Bundle layout per source:
//
//	<root>/<bundle>/
//	├── index.md                    # okf_version 0.1 + generated listing
//	├── log.md                      # newest-first harvest history
//	├── sessions/<yyyymm>/<id>.md   # type: Agent Session — one card per interaction/job
//	├── references/intents/<id>.md  # type: Intent — stub minted on first sight of a label
//	└── data/sessions/<yyyymm>/<id>.jsonl   # raw event/job records (immutable)

// escYAML quotes s for a single-line YAML string value.
func escYAML(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	return `"` + s + `"`
}

// oneLine compresses s to a single trimmed line of at most max runes (card descriptions are consumed
// verbatim by index generation, so they must stay one sentence).
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

// SessionCard is everything needed to render one Agent Session concept card.
type SessionCard struct {
	Bundle      string // "hub-relay" | "ai-studio"
	ID          string // interaction id (sanitized)
	Shard       string // yyyymm shard the card + data live in
	Title       string
	Description string
	Tags        []string
	Intent      string // intent/service id ("" = unlabeled)
	Provider    string
	Requester   string
	Status      string
	StartedAt   string
	EndedAt     string
	Events      int
	Bytes       int64
	Extra       map[string]string // extra hub: extension lines (already "key: value" formatted, pre-indented content only)
}

// cardRelPath returns the card path relative to the bundle root.
func cardRelPath(shard, id string) string { return filepath.Join("sessions", shard, id+".md") }

// dataRelPath returns the payload path relative to the bundle root.
func dataRelPath(shard, id string) string {
	return filepath.Join("data", "sessions", shard, id+".jsonl")
}

// WriteSessionCard renders + writes the card, returning its bundle-relative path.
func WriteSessionCard(root string, c SessionCard) (string, error) {
	rel := cardRelPath(c.Shard, c.ID)
	full := filepath.Join(root, c.Bundle, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", err
	}
	dataRel := dataRelPath(c.Shard, c.ID)
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("type: Agent Session\n")
	b.WriteString("title: " + escYAML(oneLine(c.Title, 80)) + "\n")
	b.WriteString("description: " + escYAML(oneLine(c.Description, 160)) + "\n")
	b.WriteString("resource: " + escYAML("../../"+filepath.ToSlash(dataRel)) + "\n")
	if len(c.Tags) > 0 {
		quoted := make([]string, len(c.Tags))
		for i, t := range c.Tags {
			quoted[i] = escYAML(t)
		}
		b.WriteString("tags: [" + strings.Join(quoted, ", ") + "]\n")
	}
	b.WriteString("timestamp: " + escYAML(nowRFC3339()) + "\n")
	b.WriteString("hub:\n")
	b.WriteString("  schema: anet-session-card/1.0\n")
	if c.Intent != "" {
		b.WriteString("  intent: " + escYAML(c.Intent) + "\n")
	}
	if c.Provider != "" {
		b.WriteString("  provider: " + escYAML(c.Provider) + "\n")
	}
	if c.Requester != "" {
		b.WriteString("  requester: " + escYAML(c.Requester) + "\n")
	}
	if c.Status != "" {
		b.WriteString("  status: " + escYAML(c.Status) + "\n")
	}
	if c.StartedAt != "" || c.EndedAt != "" {
		b.WriteString(fmt.Sprintf("  window: { started_at: %s, ended_at: %s }\n", escYAML(c.StartedAt), escYAML(c.EndedAt)))
	}
	b.WriteString(fmt.Sprintf("  volume: { events: %d, bytes: %d }\n", c.Events, c.Bytes))
	for k, v := range c.Extra {
		b.WriteString("  " + k + ": " + v + "\n")
	}
	b.WriteString("---\n\n")
	b.WriteString(oneLine(c.Description, 400) + "\n")
	if c.Intent != "" {
		b.WriteString("\n# Intents\n\n")
		b.WriteString(fmt.Sprintf("- [%s](../../references/intents/%s.md)\n", c.Intent, c.Intent))
	}
	b.WriteString("\n# Citations\n\n")
	b.WriteString(fmt.Sprintf("[1] ../../%s\n", filepath.ToSlash(dataRel)))
	if err := os.WriteFile(full, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return filepath.ToSlash(rel), nil
}

// EnsureIntentCard mints a stub Intent concept on first sight of a label (idempotent; never overwrites
// an existing card, which may have been human-enriched).
func EnsureIntentCard(root, bundle, intent, description string) error {
	if intent == "" {
		return nil
	}
	full := filepath.Join(root, bundle, "references", "intents", intent+".md")
	if _, err := os.Stat(full); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if description == "" {
		description = "Intent label " + intent + " (stub minted by the harvester; enrich with definition, examples and edge cases)."
	}
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("type: Intent\n")
	b.WriteString("title: " + escYAML(intent) + "\n")
	b.WriteString("description: " + escYAML(oneLine(description, 160)) + "\n")
	b.WriteString("tags: [\"intent\"]\n")
	b.WriteString("timestamp: " + escYAML(nowRFC3339()) + "\n")
	b.WriteString("---\n\n")
	b.WriteString(oneLine(description, 400) + "\n")
	return os.WriteFile(full, []byte(b.String()), 0o644)
}

// frontmatterField pulls a top-level scalar field out of a card's YAML frontmatter (cheap parser for
// index generation only — full YAML is not needed for the fields the writer itself produced).
func frontmatterField(content, key string) string {
	rest, ok := strings.CutPrefix(content, "---\n")
	if !ok {
		return ""
	}
	body, _, ok := strings.Cut(rest, "\n---")
	if !ok {
		return ""
	}
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, key+": "); ok {
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"`)
			v = strings.ReplaceAll(v, `\"`, `"`)
			return v
		}
	}
	return ""
}

// RegenIndex rewrites dir/index.md from the concept cards directly inside dir (OKF SPEC §6 listing
// format). root=true adds the bundle-level okf_version marker.
func RegenIndex(dir string, rootIndex bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type item struct{ name, title, desc string }
	var files []item
	var subdirs []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if name != "data" && !strings.HasPrefix(name, ".") {
				subdirs = append(subdirs, name)
			}
			continue
		}
		if !strings.HasSuffix(name, ".md") || name == "index.md" || name == "log.md" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		content := string(raw)
		title := frontmatterField(content, "title")
		if title == "" {
			title = strings.TrimSuffix(name, ".md")
		}
		files = append(files, item{name, title, frontmatterField(content, "description")})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	sort.Strings(subdirs)

	var b strings.Builder
	if rootIndex {
		b.WriteString("---\nokf_version: \"0.1\"\n---\n\n")
	}
	b.WriteString("# " + filepath.Base(dir) + "\n\n")
	if len(subdirs) > 0 {
		b.WriteString("## Directories\n\n")
		for _, d := range subdirs {
			b.WriteString(fmt.Sprintf("* [%s/](./%s/index.md)\n", d, d))
		}
		b.WriteString("\n")
	}
	if len(files) > 0 {
		b.WriteString("## Concepts\n\n")
		for _, f := range files {
			desc := f.desc
			if desc == "" {
				desc = f.name
			}
			b.WriteString(fmt.Sprintf("* [%s](./%s) - %s\n", f.title, f.name, desc))
		}
	}
	return os.WriteFile(filepath.Join(dir, "index.md"), []byte(b.String()), 0o644)
}

// AppendLog prepends one harvest entry to the bundle's log.md (OKF SPEC §7: newest-first, ISO date
// headings, bold conventional verbs).
func AppendLog(root, bundle, entry string) error {
	p := filepath.Join(root, bundle, "log.md")
	today := time.Now().UTC().Format("2006-01-02")
	old, _ := os.ReadFile(p)
	var b strings.Builder
	line := "- **Update** " + entry + "\n"
	if strings.HasPrefix(string(old), "## "+today+"\n") {
		rest := strings.TrimPrefix(string(old), "## "+today+"\n")
		b.WriteString("## " + today + "\n" + line + rest)
	} else {
		b.WriteString("## " + today + "\n" + line)
		if len(old) > 0 {
			b.WriteString("\n" + string(old))
		}
	}
	return os.WriteFile(p, []byte(b.String()), 0o644)
}
