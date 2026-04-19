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
