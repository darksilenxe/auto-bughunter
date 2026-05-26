// Package openhack loads and exposes the OpenHack-derived expert and
// orchestration agent prompts that ship inside the backend binary.
//
// The prompt pack lives under docs/openhack/ for human reference. A vendored
// copy is embedded under prompts/ via go:embed so the backend always has the
// canonical text available at runtime — there is no on-disk dependency once
// the binary is built. Refresh the embedded copy by re-running the import in
// docs/openhack/README.md and copying the markdown into prompts/.
//
// The Pack returned by LoadDefault parses the YAML-style frontmatter on each
// expert prompt and exposes:
//
//   - Experts() : the 12 OWASP-aligned expert prompts, indexed by id and by
//     routing signals (lower-cased keywords from the frontmatter and the
//     `tags` list).
//   - Orchestration prompts: scenario router, finding triage, orchestrator.
//   - Recon prompt: source-recon.
//   - Shared protocol prompt that all subagents share as system context.
//
// Consumers in the agent layer combine the shared protocol prompt with the
// matching expert/orchestration prompt to form a complete system prompt for
// the LLM. The package itself does no AI calls — it only loads, parses, and
// matches text — so it can be exercised cheaply in unit tests.
package openhack

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

//go:embed all:prompts
var promptsFS embed.FS

// Expert is a parsed OpenHack expert prompt.
type Expert struct {
	// ID is the slug from the prompt frontmatter (e.g. "injection",
	// "broken-access-control"). Stable across refreshes.
	ID string
	// Title is the human-readable label (e.g. "A03:2025 - Injection").
	Title string
	// Category is the canonical OWASP category slug from the frontmatter.
	Category string
	// Tags are normalised lower-case tags (owasp-a03-2025, cwe-79, …).
	Tags []string
	// RoutingSignals are the lower-cased keywords from the frontmatter
	// `routing_signals` block; consumers fuzzy-match finding categories,
	// titles, and CWEs against this list to pick the right expert.
	RoutingSignals []string
	// StandardRefs are the normalised standards references (OWASP A05:2025, …).
	StandardRefs []string
	// Body is the full markdown body of the prompt (frontmatter stripped).
	// Use this directly as a system prompt for the LLM.
	Body string
}

// Orchestration is a parsed orchestration prompt (orchestrator, scenario
// router, finding triage). Only ID/Title/Body are exposed because the
// frontmatter does not carry routing signals for these prompts.
type Orchestration struct {
	ID    string
	Title string
	Body  string
}

// Pack is the in-memory representation of the OpenHack prompt pack. It is
// safe for concurrent reads after LoadDefault returns.
type Pack struct {
	experts        []*Expert
	expertsByID    map[string]*Expert
	orchestration  map[string]*Orchestration
	recon          *Orchestration
	sharedProtocol string
}

var (
	defaultPack     *Pack
	defaultPackErr  error
	defaultPackOnce sync.Once
)

// LoadDefault returns the package-level Pack, loading it from the embedded
// filesystem on the first call. Subsequent calls return the cached instance.
// An error is returned only if the embedded files cannot be parsed, which
// indicates a packaging bug rather than a runtime configuration issue.
func LoadDefault() (*Pack, error) {
	defaultPackOnce.Do(func() {
		defaultPack, defaultPackErr = load(promptsFS, "prompts")
	})
	return defaultPack, defaultPackErr
}

// MustLoadDefault is a convenience wrapper for code paths where a missing
// prompt pack would always indicate a build problem (e.g. tests, init).
func MustLoadDefault() *Pack {
	p, err := LoadDefault()
	if err != nil {
		panic(fmt.Errorf("openhack: load embedded prompt pack: %w", err))
	}
	return p
}

func load(fsys fs.FS, root string) (*Pack, error) {
	p := &Pack{
		expertsByID:   map[string]*Expert{},
		orchestration: map[string]*Orchestration{},
	}

	expertDir := root + "/agents/experts"
	entries, err := fs.ReadDir(fsys, expertDir)
	if err != nil {
		return nil, fmt.Errorf("read experts dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		data, err := fs.ReadFile(fsys, expertDir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		expert, err := parseExpert(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		p.experts = append(p.experts, expert)
		p.expertsByID[expert.ID] = expert
	}
	sort.Slice(p.experts, func(i, j int) bool {
		return p.experts[i].ID < p.experts[j].ID
	})

	orchDir := root + "/agents/orchestration"
	orchEntries, err := fs.ReadDir(fsys, orchDir)
	if err != nil {
		return nil, fmt.Errorf("read orchestration dir: %w", err)
	}
	for _, e := range orchEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		data, err := fs.ReadFile(fsys, orchDir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		o, err := parseOrchestration(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		p.orchestration[o.ID] = o
	}

	// Reconnaissance prompt — optional, currently a single file.
	if data, err := fs.ReadFile(fsys, root+"/agents/reconnaissance/source-recon.md"); err == nil {
		if rec, err := parseOrchestration(data); err == nil {
			p.recon = rec
		}
	}

	// Shared protocol prompt is concatenated onto every expert/triage call.
	if data, err := fs.ReadFile(fsys, root+"/agents/shared/protocol.md"); err == nil {
		p.sharedProtocol = strings.TrimSpace(stripFrontmatter(string(data)))
	}

	return p, nil
}

// Experts returns the experts in stable id order. The returned slice is a
// fresh copy of the internal pointers so callers may sort or filter it
// without affecting the Pack.
func (p *Pack) Experts() []*Expert {
	if p == nil {
		return nil
	}
	out := make([]*Expert, len(p.experts))
	copy(out, p.experts)
	return out
}

// ExpertByID returns the expert with the given id, or nil if not found.
func (p *Pack) ExpertByID(id string) *Expert {
	if p == nil {
		return nil
	}
	return p.expertsByID[strings.ToLower(strings.TrimSpace(id))]
}

// Orchestration returns the orchestration prompt with the given id (e.g.
// "scenario-router", "finding-triage", "orchestrator"), or nil if missing.
func (p *Pack) Orchestration(id string) *Orchestration {
	if p == nil {
		return nil
	}
	return p.orchestration[strings.ToLower(strings.TrimSpace(id))]
}

// Recon returns the source-recon orchestration prompt, or nil if missing.
func (p *Pack) Recon() *Orchestration {
	if p == nil {
		return nil
	}
	return p.recon
}

// SharedProtocol returns the shared protocol prompt body (frontmatter
// stripped). Consumers should prepend this to every LLM call that uses one of
// the expert or orchestration bodies so the model picks up the OpenHack
// output contract.
func (p *Pack) SharedProtocol() string {
	if p == nil {
		return ""
	}
	return p.sharedProtocol
}

// SystemPromptFor returns a complete system prompt that combines the shared
// protocol and the named expert/orchestration body. Returns the empty string
// when neither an expert nor an orchestration prompt matches the id.
func (p *Pack) SystemPromptFor(id string) string {
	if p == nil {
		return ""
	}
	if exp := p.ExpertByID(id); exp != nil {
		return joinPromptParts(p.sharedProtocol, exp.Body)
	}
	if orch := p.Orchestration(id); orch != nil {
		return joinPromptParts(p.sharedProtocol, orch.Body)
	}
	return ""
}

func joinPromptParts(parts ...string) string {
	var b strings.Builder
	first := true
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !first {
			b.WriteString("\n\n---\n\n")
		}
		b.WriteString(part)
		first = false
	}
	return b.String()
}
