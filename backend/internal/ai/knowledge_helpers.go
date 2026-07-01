package ai

import (
	"fmt"
	"strings"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

func knowledgeCategoriesForFindings(findings []model.Finding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat == "" {
			continue
		}
		if _, ok := seen[cat]; ok {
			continue
		}
		seen[cat] = struct{}{}
		out = append(out, cat)
	}
	return out
}

func knowledgeCategoriesForFinding(finding model.Finding) []string {
	if cat := strings.ToLower(strings.TrimSpace(finding.Category)); cat != "" {
		return []string{cat}
	}
	return nil
}

func knowledgeCategoriesForFindingSet(findingSet []map[string]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(findingSet))
	for _, f := range findingSet {
		cat := strings.ToLower(strings.TrimSpace(f["category"]))
		if cat == "" {
			continue
		}
		if _, ok := seen[cat]; ok {
			continue
		}
		seen[cat] = struct{}{}
		out = append(out, cat)
	}
	return out
}

func knowledgeCategoriesForAgentAdvice(checks []string, findings []model.Finding) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(checks)+len(findings))
	add := func(raw string) {
		value := strings.ToLower(strings.TrimSpace(raw))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, check := range checks {
		add(check)
	}
	for _, finding := range findings {
		add(finding.Category)
	}
	return out
}

func agentAdviceKnowledgeQuery(agentName, target string, checks []string, findings []model.Finding, blackboard string) string {
	return fmt.Sprintf(
		"agent=%s target=%s checks=%s findings=%s context=%s",
		agentName,
		target,
		strings.Join(limitStrings(checks, 8), ", "),
		strings.Join(limitStrings(findingTitlesForKnowledge(findings, 5), 5), " | "),
		truncateKnowledgeText(blackboard, 240),
	)
}

func hypothesisKnowledgeQuery(target string, findings []model.Finding, endpoints []string) string {
	return fmt.Sprintf(
		"target=%s findings=%s endpoints=%s",
		target,
		strings.Join(limitStrings(findingTitlesForKnowledge(findings, 5), 5), " | "),
		strings.Join(limitStrings(endpoints, 6), ", "),
	)
}

func reflectKnowledgeQuery(target string, findings []model.Finding, probeResults []model.ProbeResult) string {
	probeHints := make([]string, 0, len(probeResults))
	for _, pr := range probeResults {
		hint := strings.TrimSpace(pr.Category + " " + pr.Endpoint + " " + pr.ParamName)
		if hint != "" {
			probeHints = append(probeHints, hint)
		}
		if len(probeHints) >= 6 {
			break
		}
	}
	return fmt.Sprintf(
		"target=%s findings=%s probes=%s",
		target,
		strings.Join(limitStrings(findingTitlesForKnowledge(findings, 5), 5), " | "),
		strings.Join(probeHints, " | "),
	)
}

func techniqueAdaptationKnowledgeQuery(target, findingTitle, findingEvidence string) string {
	return fmt.Sprintf(
		"target=%s finding=%s evidence=%s",
		target,
		strings.TrimSpace(findingTitle),
		truncateKnowledgeText(findingEvidence, 240),
	)
}

func chainSynthesisKnowledgeQuery(target string, findingSet []map[string]string, goals []model.ImpactGoal) string {
	titles := make([]string, 0, len(findingSet))
	for _, f := range findingSet {
		title := strings.TrimSpace(f["title"])
		if title != "" {
			titles = append(titles, title)
		}
		if len(titles) >= 6 {
			break
		}
	}
	return fmt.Sprintf(
		"target=%s findings=%s goals=%s",
		target,
		strings.Join(titles, " | "),
		impact.GoalPrompt(goals),
	)
}

func openHackKnowledgeQuery(stage string, finding model.Finding) string {
	return fmt.Sprintf(
		"stage=%s finding=%s evidence=%s",
		stage,
		strings.TrimSpace(finding.Title),
		truncateKnowledgeText(finding.Evidence, 240),
	)
}

func findingTitlesForKnowledge(findings []model.Finding, max int) []string {
	out := make([]string, 0, minInt(max, len(findings)))
	for _, f := range findings {
		title := strings.TrimSpace(f.Title)
		if title == "" {
			continue
		}
		out = append(out, title)
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func limitStrings(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}

func truncateKnowledgeText(value string, max int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max] + "…"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
