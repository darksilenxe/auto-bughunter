package agent

import (
	"context"
	"fmt"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

type ReportingAgent struct {
	enabled bool
}

func NewReportingAgent(enabled bool) *ReportingAgent {
	return &ReportingAgent{enabled: enabled}
}

func (a *ReportingAgent) Name() string {
	return "reporting"
}

func (a *ReportingAgent) Enabled() bool {
	return a.enabled
}

func (a *ReportingAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	allFindings := input.AllFindings
	if len(allFindings) == 0 {
		allFindings = input.Previous.Findings
	}
	if len(allFindings) == 0 {
		output.DebugNotes = "No findings to report"
		return output, nil
	}

	goals := impact.GoalsOrDefault(input.Options)
	allFindings = impact.RankFindings(allFindings, goals)
	executiveSummary := buildExecutiveSummary(allFindings)
	topRisks := identifyTopRisks(allFindings)

	output.Metadata["summary"] = executiveSummary
	output.Metadata["impact_goals"] = impact.GoalPrompt(goals)
	output.Metadata["top_risk_1"] = fmt.Sprintf("%d", topRisks[0])
	if len(topRisks) > 1 {
		output.Metadata["top_risk_2"] = fmt.Sprintf("%d", topRisks[1])
	}
	if len(topRisks) > 2 {
		output.Metadata["top_risk_3"] = fmt.Sprintf("%d", topRisks[2])
	}

	output.Findings = allFindings

	output.DebugNotes = fmt.Sprintf("Report generated: %d findings processed, %d top risks identified.", len(allFindings), len(topRisks))
	return output, nil
}

func buildExecutiveSummary(findings []model.Finding) string {
	if len(findings) == 0 {
		return "No findings"
	}

	severities := map[model.Severity]int{}
	demonstratedImpact := 0
	for _, f := range findings {
		severities[f.Severity]++
		if f.ProofState == model.ProofStateImpactDemonstrated || f.ProofState == model.ProofStateSubmissionReady {
			demonstratedImpact++
		}
	}

	return fmt.Sprintf(
		"Assessment identified %d findings: %d high, %d medium, %d low, %d info. %d finding(s) include demonstrated or submission-ready impact evidence. Recommend immediate remediation of the highest bounty-value items first.",
		len(findings),
		severities[model.SeverityHigh],
		severities[model.SeverityMedium],
		severities[model.SeverityLow],
		severities[model.SeverityInfo],
		demonstratedImpact,
	)
}

func identifyTopRisks(findings []model.Finding) []int {
	topRisks := make([]int, 0, 3)
	for i := range findings {
		topRisks = append(topRisks, i)
		if len(topRisks) == 3 {
			break
		}
	}
	return topRisks
}
