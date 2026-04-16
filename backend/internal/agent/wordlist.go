package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

type WordlistAgent struct {
	wordlistScanner *scanner.WordlistScanner
	enabled         bool
}

func NewWordlistAgent(enabled bool) *WordlistAgent {
	return &WordlistAgent{
		wordlistScanner: scanner.NewWordlistScanner(5, 0),
		enabled:         enabled,
	}
}

func (a *WordlistAgent) Name() string {
	return "wordlist"
}

func (a *WordlistAgent) Enabled() bool {
	return a.enabled
}

func (a *WordlistAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	dirs := a.wordlistScanner.ScanDirectories(ctx, input.Target, input.AuthProfile, input.Scope)
	output.Findings = append(output.Findings, dirs...)

	subs := a.wordlistScanner.ScanSubdomains(ctx, input.Target, input.Scope)
	output.Findings = append(output.Findings, subs...)

	apis := a.wordlistScanner.ScanAPIEndpoints(ctx, input.Target, input.AuthProfile, input.Scope)
	output.Findings = append(output.Findings, apis...)

	output.Metadata["directories_found"] = fmt.Sprintf("%d", len(dirs))
	output.Metadata["subdomains_found"] = fmt.Sprintf("%d", len(subs))
	output.Metadata["api_endpoints_found"] = fmt.Sprintf("%d", len(apis))
	output.Metadata["total_found"] = fmt.Sprintf("%d", len(output.Findings))
	output.Metadata["targets_attempted"] = fmt.Sprintf("%d", len(dirs)+len(subs)+len(apis))
	output.Metadata["targets_skipped"] = "0"

	prioritized := prioritizeLikelyHighRiskEndpoints(output.Findings)
	if len(prioritized) > 0 {
		output.Metadata["prioritized_endpoints"] = strings.Join(prioritized, ",")
		output.Findings = append(output.Findings, model.Finding{
			ID:             "wordlist-priority-targets",
			Category:       "prioritization",
			Severity:       model.SeverityInfo,
			Title:          "Priority endpoints identified for focused probing",
			Description:    "Endpoints with admin/auth/input/API characteristics were prioritized for follow-up checks.",
			Evidence:       strings.Join(prioritized, ", "),
			Recommendation: "Prioritize these endpoints for deeper validation and manual testing.",
			Confidence:     0.82,
			Sources:        []string{"wordlist"},
			EvidenceFields: map[string]string{
				"endpointCount": fmt.Sprintf("%d", len(prioritized)),
			},
			BusinessTags: []string{"internet-facing"},
			Exploitability: &model.Exploitability{
				Reachable:       true,
				RequiredRole:    "unknown",
				Prerequisites:   []string{"endpoint_reachable"},
				AttackPathHints: []string{"auth-bypass-checks", "input-validation-fuzzing"},
			},
		})
	}

	output.DebugNotes = fmt.Sprintf("Wordlist scanning completed: %d directories, %d subdomains, %d API endpoints discovered.", len(dirs), len(subs), len(apis))

	return output, nil
}

func prioritizeLikelyHighRiskEndpoints(findings []model.Finding) []string {
	candidates := map[string]struct{}{}
	for _, f := range findings {
		e := strings.ToLower(strings.TrimSpace(f.Evidence))
		if e == "" {
			continue
		}
		if strings.Contains(e, "/admin") ||
			strings.Contains(e, "/login") ||
			strings.Contains(e, "/auth") ||
			strings.Contains(e, "/api/") ||
			strings.Contains(e, "graphql") ||
			strings.Contains(e, "upload") ||
			strings.Contains(e, "callback") {
			candidates[e] = struct{}{}
		}
	}
	out := make([]string, 0, len(candidates))
	for c := range candidates {
		out = append(out, c)
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
