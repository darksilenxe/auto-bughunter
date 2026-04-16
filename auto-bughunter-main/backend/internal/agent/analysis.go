package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

type AnalysisAgent struct {
	enabled bool
}

func NewAnalysisAgent(enabled bool) *AnalysisAgent {
	return &AnalysisAgent{enabled: enabled}
}

func (a *AnalysisAgent) Name() string {
	return "analysis"
}

func (a *AnalysisAgent) Enabled() bool {
	return a.enabled
}

func (a *AnalysisAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	allFindings := input.Previous.Findings
	if len(allFindings) == 0 {
		output.DebugNotes = "No findings to analyze"
		return output, nil
	}

	deduped := deduplicateFindings(allFindings)
	scored := scoreAndRankFindings(deduped)

	output.Findings = scored
	output.Metadata["original_count"] = fmt.Sprintf("%d", len(allFindings))
	output.Metadata["deduped_count"] = fmt.Sprintf("%d", len(deduped))
	output.Metadata["high_severity"] = fmt.Sprintf("%d", countBySeverity(scored, model.SeverityHigh))
	output.Metadata["medium_severity"] = fmt.Sprintf("%d", countBySeverity(scored, model.SeverityMedium))

	output.DebugNotes = fmt.Sprintf("Deduplicated %d findings to %d unique issues; scored and ranked by severity and category.", len(allFindings), len(deduped))

	return output, nil
}

func deduplicateFindings(findings []model.Finding) []model.Finding {
	seen := make(map[string]struct{})
	deduped := make([]model.Finding, 0, len(findings))

	for _, f := range findings {
		key := fmt.Sprintf("%s:%s", f.Category, f.Title)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, f)
	}

	return deduped
}

func scoreAndRankFindings(findings []model.Finding) []model.Finding {
	type scored struct {
		finding model.Finding
		score   int
	}

	scoredList := make([]scored, 0, len(findings))
	for _, f := range findings {
		score := severityScore(f.Severity) * 1000
		score += categoryScore(f.Category) * 100
		scoredList = append(scoredList, scored{finding: f, score: score})
	}

	sort.SliceStable(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})

	ranked := make([]model.Finding, 0, len(scoredList))
	for _, s := range scoredList {
		ranked = append(ranked, s.finding)
	}

	return ranked
}

func severityScore(s model.Severity) int {
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

func categoryScore(cat string) int {
	cat = strings.ToLower(strings.TrimSpace(cat))
	scores := map[string]int{
		"security":       10,
		"authentication": 9,
		"authorization":  9,
		"injection":      8,
		"xss":            7,
		"csrf":           7,
		"encryption":     8,
		"tls":            6,
		"headers":        5,
		"cookies":        5,
		"discovery":      2,
		"reconnaissance": 1,
	}
	if score, ok := scores[cat]; ok {
		return score
	}
	return 3
}

func countBySeverity(findings []model.Finding, severity model.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}
