package ai

import (
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

func localReasonerSummary(target string, findings []model.Finding) string {
	return localReasonerSummaryWithKnowledge(target, findings, nil)
}

func localReasonerSummaryWithKnowledge(target string, findings []model.Finding, knowledge *model.SecurityKnowledgeContext) string {
	if len(findings) == 0 {
		return "Offline AI summary: no findings were reported. Continue periodic scans and keep security headers, cookie flags, and TLS settings hardened."
	}

	sevCounts := map[model.Severity]int{}
	categoryCounts := map[string]int{}
	for _, f := range findings {
		sevCounts[f.Severity]++
		category := strings.TrimSpace(strings.ToLower(f.Category))
		if category == "" {
			category = "other"
		}
		categoryCounts[category]++
	}

	sorted := append([]model.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a := severityWeight(sorted[i].Severity)
		b := severityWeight(sorted[j].Severity)
		if a != b {
			return a > b
		}
		if sorted[i].Category != sorted[j].Category {
			return sorted[i].Category < sorted[j].Category
		}
		return sorted[i].Title < sorted[j].Title
	})

	topN := 3
	if len(sorted) < topN {
		topN = len(sorted)
	}
	priorities := make([]string, 0, topN)
	for i := 0; i < topN; i++ {
		f := sorted[i]
		priorities = append(priorities, fmt.Sprintf("%d) [%s] %s (%s)", i+1, f.Severity, compact(f.Title), compact(f.Category)))
	}

	sequence := buildRemediationSequence(sorted)
	topCategories := topCategoryList(categoryCounts, 3)

	summary := fmt.Sprintf(
		"Offline AI summary for %s\n\nRisk summary: high=%d, medium=%d, low=%d, info=%d. Most frequent categories: %s.\n\nTop priorities:\n%s\n\nSuggested remediation sequence:\n%s\n\nMethod: deterministic local reasoning over finding severity, category concentration, and recommendation text.",
		target,
		sevCounts[model.SeverityHigh],
		sevCounts[model.SeverityMedium],
		sevCounts[model.SeverityLow],
		sevCounts[model.SeverityInfo],
		strings.Join(topCategories, ", "),
		strings.Join(priorities, "\n"),
		strings.Join(sequence, "\n"),
	)
	if knowledge == nil || len(knowledge.References) == 0 {
		return summary
	}
	refs := make([]string, 0, min(3, len(knowledge.References)))
	for i, ref := range knowledge.References {
		if i >= 3 {
			break
		}
		refs = append(refs, fmt.Sprintf("- %s (%s)", ref.Title, ref.URL))
	}
	return summary + "\n\nSupporting references:\n" + strings.Join(refs, "\n")
}

func buildRemediationSequence(sorted []model.Finding) []string {
	steps := []string{}
	seen := map[string]struct{}{}

	for _, f := range sorted {
		rec := compact(f.Recommendation)
		if rec == "" {
			continue
		}
		key := strings.ToLower(rec)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		steps = append(steps, fmt.Sprintf("- %s", rec))
		if len(steps) == 5 {
			break
		}
	}

	if len(steps) == 0 {
		steps = append(steps, "- Triage high and medium findings first, verify exploitability, then apply standard hardening controls.")
	}
	return steps
}

func topCategoryList(counts map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{k: k, v: v})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) < n {
		n = len(items)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s(%d)", items[i].k, items[i].v))
	}
	if len(out) == 0 {
		return []string{"none"}
	}
	return out
}

func severityWeight(s model.Severity) int {
	switch s {
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func compact(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// localReasonerHypotheses generates a rule-based set of VulnerabilityHypotheses
// when no AI provider is configured. It examines the current finding set and
// known endpoints to propose targeted probes for the scanner's deterministic
// verification step.
func localReasonerHypotheses(target string, findings []model.Finding, endpoints []string) []VulnerabilityHypothesis {
	// Build a set of already-known categories to avoid redundant re-probing.
	knownCategories := map[string]bool{}
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat != "" {
			knownCategories[cat] = true
		}
		if strings.Contains(strings.ToLower(f.CWE), "89") {
			knownCategories["sqli"] = true
		}
		if strings.Contains(strings.ToLower(f.CWE), "79") {
			knownCategories["xss"] = true
		}
	}

	// Choose a representative endpoint for hypothesis targeting.
	representative := target
	for _, ep := range endpoints {
		if ep = strings.TrimSpace(ep); ep != "" {
			representative = ep
			break
		}
	}

	var hs []VulnerabilityHypothesis

	// Rule 1: Reflected parameter detected but no XSS confirmed yet — propose XSS probe.
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.ID), "contextual-param-reflection") && !knownCategories["xss"] {
			hs = append(hs, VulnerabilityHypothesis{
				ID:          "local-hyp-xss-reflection",
				Endpoint:    f.AffectedURL,
				Method:      "GET",
				ParamName:   "q",
				PayloadHint: `"><svg/onload=prompt(1)>`,
				Category:    "xss",
				Rationale:   "Reflected parameter already confirmed; XSS confirmation probe not yet run.",
			})
			break
		}
	}

	// Rule 2: Open-redirect present — propose OAuth redirect-uri abuse probe.
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Category), "redirect") {
			hs = append(hs, VulnerabilityHypothesis{
				ID:          "local-hyp-oauth-redirect",
				Endpoint:    representative,
				Method:      "GET",
				ParamName:   "redirect_uri",
				PayloadHint: "https://evil.example.com/callback",
				Category:    "open_redirect",
				Rationale:   "Open redirect in scope; OAuth/OIDC callback parameter may be unsecured.",
			})
			break
		}
	}

	// Rule 3: API endpoint present but no IDOR confirmed — propose IDOR probe.
	hasIDOR := false
	for _, f := range findings {
		if strings.Contains(f.CWE, "639") || strings.Contains(strings.ToLower(f.Category), "idor") {
			hasIDOR = true
			break
		}
	}
	if !hasIDOR {
		for _, ep := range endpoints {
			if strings.Contains(ep, "/api/") {
				hs = append(hs, VulnerabilityHypothesis{
					ID:          "local-hyp-api-idor",
					Endpoint:    ep,
					Method:      "GET",
					ParamName:   "id",
					PayloadHint: "1",
					Category:    "idor",
					Rationale:   "API endpoint present without confirmed IDOR testing; object-level auth check needed.",
				})
				break
			}
		}
	}

	// Rule 4: No SQL injection confirmed — propose SQLi probe on key parameter.
	if !knownCategories["sqli"] {
		hs = append(hs, VulnerabilityHypothesis{
			ID:          "local-hyp-sqli",
			Endpoint:    representative,
			Method:      "GET",
			ParamName:   "id",
			PayloadHint: `' OR '1'='1`,
			Category:    "sqli",
			Rationale:   "No SQL injection confirmed; baseline injection test not yet run for key parameters.",
		})
	}

	// Rule 5: CORS misconfiguration present — propose credentialed cross-origin probe.
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Category), "cors") {
			hs = append(hs, VulnerabilityHypothesis{
				ID:          "local-hyp-cors-credential",
				Endpoint:    f.AffectedURL,
				Method:      "GET",
				PayloadHint: "Origin: https://evil.example.com",
				Category:    "cors",
				Rationale:   "CORS misconfiguration found; credential-bearing cross-origin request may expose authenticated data.",
			})
			break
		}
	}

	if len(hs) > 5 {
		hs = hs[:5]
	}
	return hs
}
