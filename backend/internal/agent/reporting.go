package agent

import (
	"context"
	"fmt"

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

	allFindings := input.Previous.Findings
	if len(allFindings) == 0 {
		output.DebugNotes = "No findings to report"
		return output, nil
	}

	executiveSummary := buildExecutiveSummary(allFindings)
	topRisks := identifyTopRisks(allFindings)

	output.Metadata["summary"] = executiveSummary
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
	for _, f := range findings {
		severities[f.Severity]++
	}

	return fmt.Sprintf(
		"Assessment identified %d findings: %d high, %d medium, %d low, %d info. Recommend immediate remediation of high-severity items.",
		len(findings),
		severities[model.SeverityHigh],
		severities[model.SeverityMedium],
		severities[model.SeverityLow],
		severities[model.SeverityInfo],
	)
}

func identifyTopRisks(findings []model.Finding) []int {
	topRisks := make([]int, 0, 3)
	counted := make(map[int]struct{})

	for _, f := range findings {
		if f.Severity == model.SeverityHigh {
			idx := findingIndex(&findings, f)
			if idx >= 0 && len(topRisks) < 3 {
				if _, seen := counted[idx]; !seen {
					topRisks = append(topRisks, idx)
					counted[idx] = struct{}{}
				}
			}
		}
	}

	for _, f := range findings {
		if len(topRisks) >= 3 {
			break
		}
		if f.Severity == model.SeverityMedium {
			idx := findingIndex(&findings, f)
			if idx >= 0 {
				if _, seen := counted[idx]; !seen {
					topRisks = append(topRisks, idx)
					counted[idx] = struct{}{}
				}
			}
		}
	}

	if len(topRisks) == 0 {
		topRisks = append(topRisks, 0)
	}

	return topRisks
}

func findingIndex(findings *[]model.Finding, target model.Finding) int {
	for i, f := range *findings {
		if f.ID == target.ID {
			return i
		}
	}
	return -1
}
