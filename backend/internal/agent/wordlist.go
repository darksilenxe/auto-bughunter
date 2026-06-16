package agent

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// An AI advisor may reorder or skip entries based on scan context.
var wordlistChecks = []string{
	"directories",
	"seed_routes",
	"subdomains",
	"api_endpoints",
}

type WordlistAgent struct {
	wordlistScanner *scanner.WordlistScanner
	enabled         bool
}

func NewWordlistAgent(enabled bool) *WordlistAgent {
	return &WordlistAgent{
		wordlistScanner: scanner.NewWordlistScanner(20, 0),
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

	// If an AgentAdvisor pre-run hook wrote advice to the blackboard, use it
	// to reorder or skip checks. Default order is preserved when no advice is
	// present.
	advice := ParseAdviceNote(input.SharedScanContext.GetNote(a.Name()))
	ordered := OrderChecks(advice, wordlistChecks)

	// seed_routes depends on history; collect once so the closure captures it.
	seedRoutes := sastDiscoveredRoutes(input.History)

	var dirs, seeded, subs, apis []model.Finding

	type checkFn func()
	checkMap := map[string]checkFn{
		"directories": func() {
			dirs = a.wordlistScanner.ScanDirectories(ctx, input.Target, input.AuthProfile, input.Scope)
			output.Findings = append(output.Findings, dirs...)
		},
		"seed_routes": func() {
			// When the JavaScript SAST agent has already surfaced routes from the
			// target's own code, probe those confirmed endpoints directly first.
			if len(seedRoutes) > 0 {
				seeded = a.wordlistScanner.ScanSeedRoutes(ctx, input.Target, seedRoutes, input.AuthProfile, input.Scope)
				output.Findings = append(output.Findings, seeded...)
				output.Metadata["code_discovered_routes_probed"] = fmt.Sprintf("%d", len(seedRoutes))
			}
		},
		"subdomains": func() {
			subs = a.wordlistScanner.ScanSubdomains(ctx, input.Target, input.Scope)
			output.Findings = append(output.Findings, subs...)
		},
		"api_endpoints": func() {
			apis = a.wordlistScanner.ScanAPIEndpoints(ctx, input.Target, input.AuthProfile, input.Scope)
			output.Findings = append(output.Findings, apis...)
		},
	}

	for _, check := range ordered {
		if ctx.Err() != nil {
			break
		}
		if fn, ok := checkMap[check]; ok {
			fn()
		}
	}

	output.Metadata["directories_found"] = fmt.Sprintf("%d", acceptedWordlistCount(dirs))
	output.Metadata["subdomains_found"] = fmt.Sprintf("%d", len(subs))
	output.Metadata["api_endpoints_found"] = fmt.Sprintf("%d", acceptedWordlistCount(apis))
	output.Metadata["total_found"] = fmt.Sprintf("%d", len(output.Findings))
	output.Metadata["targets_attempted"] = fmt.Sprintf("%d", acceptedWordlistCount(dirs)+len(subs)+acceptedWordlistCount(apis))
	output.Metadata["targets_skipped"] = fmt.Sprintf("%d", suppressedWordlistCount(dirs)+suppressedWordlistCount(apis))

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

	output.DebugNotes = fmt.Sprintf("Wordlist scanning completed. Checked: %s. %d directories, %d subdomains, %d API endpoints discovered.", strings.Join(ordered, ", "), len(dirs), len(subs), len(apis))

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

func acceptedWordlistCount(findings []model.Finding) int {
	total := 0
	for _, f := range findings {
		if raw := strings.TrimSpace(f.EvidenceFields["acceptedCount"]); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				total += n
			}
		}
	}
	return total
}

func suppressedWordlistCount(findings []model.Finding) int {
	total := 0
	for _, f := range findings {
		if raw := strings.TrimSpace(f.EvidenceFields["suppressedCount"]); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				total += n
			}
		}
	}
	return total
}
