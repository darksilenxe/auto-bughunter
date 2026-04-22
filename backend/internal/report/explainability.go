package report

import (
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/model"
)

// writeRankingRationaleMarkdown renders the per-finding ranking rationale into
// a Markdown report so operators can see exactly why each recommended finding
// was promoted to the top of the queue (severity, confidence, exploitability,
// drift, operator-feedback boost, program-payout boost). The section is
// silently skipped when no prioritized findings or rationales are available.
func writeRankingRationaleMarkdown(b *strings.Builder, job *model.ScanJob) {
	if job == nil || job.ModelRecommendations == nil || len(job.ModelRecommendations.PrioritizedFindings) == 0 {
		return
	}
	prioritized := job.ModelRecommendations.PrioritizedFindings
	hasRationale := false
	for _, p := range prioritized {
		if len(p.Rationale) > 0 {
			hasRationale = true
			break
		}
	}
	if !hasRationale {
		return
	}
	b.WriteString("## Why These Findings Ranked High\n\n")
	b.WriteString("Each prioritized finding's score is composed deterministically from the signals below. Positive components push the finding up the queue; negative components push it down.\n\n")
	b.WriteString("| Rank | Title | Score | Component breakdown |\n")
	b.WriteString("|-----:|-------|------:|---------------------|\n")
	for i, p := range prioritized {
		b.WriteString(fmt.Sprintf("| %d | %s | %.2f | %s |\n",
			i+1,
			mdEscapeCell(p.Title),
			p.Score,
			mdEscapeCell(rationaleSummary(p.Rationale)),
		))
	}
	b.WriteString("\n")
}

// writeAgentScheduleRationaleMarkdown renders the "why this agent ran" trace
// for each completed agent run, sourced from AgentRunTelemetry.Metadata
// (`orchestration_reason`). Skipped silently when no runs were recorded.
func writeAgentScheduleRationaleMarkdown(b *strings.Builder, job *model.ScanJob) {
	if job == nil || len(job.AgentRuns) == 0 {
		return
	}
	hasReason := false
	for _, r := range job.AgentRuns {
		if reason := strings.TrimSpace(r.Metadata["orchestration_reason"]); reason != "" {
			hasReason = true
			break
		}
	}
	if !hasReason {
		return
	}
	b.WriteString("## Why Each Agent Ran\n\n")
	b.WriteString("Agents are scheduled by the orchestrator's planner. The reason recorded below is the planner's justification at scheduling time.\n\n")
	b.WriteString("| Agent | Status | Duration (ms) | Findings | Why it ran |\n")
	b.WriteString("|-------|--------|--------------:|---------:|------------|\n")
	for _, r := range job.AgentRuns {
		reason := strings.TrimSpace(r.Metadata["orchestration_reason"])
		if reason == "" {
			reason = "—"
		}
		findings := r.Metadata["findings"]
		if findings == "" {
			findings = "0"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
			mdEscapeCell(r.AgentName),
			mdEscapeCell(r.Status),
			r.DurationMs,
			mdEscapeCell(findings),
			mdEscapeCell(reason),
		))
	}
	b.WriteString("\n")
}

// rationaleSummary serialises a rationale map deterministically (keys sorted
// alphabetically, signed two-decimal values) so the rendered output is stable
// across runs and easy to diff.
func rationaleSummary(rationale map[string]float64) string {
	if len(rationale) == 0 {
		return ""
	}
	keys := make([]string, 0, len(rationale))
	for k := range rationale {
		if k == "score" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%+0.2f", k, rationale[k]))
	}
	return strings.Join(parts, ", ")
}
