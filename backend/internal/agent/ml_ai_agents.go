package agent

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
)

type MLTriageAgent struct {
	ml      *ml.Service
	enabled bool
}

// mlTriageChecks lists the logical phases this agent performs. An AI advisor
// provides pre-run focus and writes a post-run lesson to the blackboard.
var mlTriageChecks = []string{
	"false_positive_triage",
	"confidence_calibration",
}

func NewMLTriageAgent(mlService *ml.Service, enabled bool) *MLTriageAgent {
	return &MLTriageAgent{ml: mlService, enabled: enabled}
}

func (a *MLTriageAgent) Name() string {
	return "ml_triage"
}

func (a *MLTriageAgent) Enabled() bool {
	return a.enabled
}

func (a *MLTriageAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	_ = ctx
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UseMLTriageAgent {
		output.DebugNotes = "ML triage agent disabled by scan options"
		return output, nil
	}
	if a.ml == nil {
		output.DebugNotes = "ML service not configured"
		return output, nil
	}

	source := input.AllFindings
	if len(source) == 0 {
		output.DebugNotes = "No findings available for ML triage"
		return output, nil
	}

	scored := a.ml.ScoreFindings(source)
	if len(scored) == 0 {
		output.DebugNotes = "No findings scored by ML triage"
		return output, nil
	}

	limit := 3
	if len(scored) < limit {
		limit = len(scored)
	}
	for i := 0; i < limit; i++ {
		sf := scored[i]
		output.Findings = append(output.Findings, model.Finding{
			ID:       fmt.Sprintf("ml-triage-%d", i+1),
			Category: "ml_ai",
			Severity: toSeverity(sf.Score),
			Title:    fmt.Sprintf("ML triage priority %d: %s", i+1, sf.Finding.Title),
			Description: fmt.Sprintf(
				"Deterministic ML scoring ranked this issue with risk score %.2f, confidence %.2f, exploitability=%s.",
				sf.Score,
				sf.Confidence,
				sf.Exploitability,
			),
			Evidence:       fmt.Sprintf("category=%s severity=%s", sf.Finding.Category, sf.Finding.Severity),
			Recommendation: "Prioritize validation and remediation for this issue in the next sprint window.",
		})
	}

	output.Metadata["scored_total"] = strconv.Itoa(len(scored))
	output.Metadata["top_score"] = fmt.Sprintf("%.2f", scored[0].Score)
	output.DebugNotes = "ML triage generated prioritized risk insights."
	return output, nil
}

type AttackPathAgent struct {
	ml      *ml.Service
	enabled bool
}

// attackPathChecks lists the logical phases this agent performs. An AI advisor
// provides pre-run focus and writes a post-run lesson to the blackboard.
var attackPathChecks = []string{
	"path_analysis",
	"chain_detection",
}

func NewAttackPathAgent(mlService *ml.Service, enabled bool) *AttackPathAgent {
	return &AttackPathAgent{ml: mlService, enabled: enabled}
}

func (a *AttackPathAgent) Name() string {
	return "attack_path"
}

func (a *AttackPathAgent) Enabled() bool {
	return a.enabled
}

func (a *AttackPathAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	_ = ctx
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UseAttackPathAgent {
		output.DebugNotes = "Attack path agent disabled by scan options"
		return output, nil
	}
	if a.ml == nil {
		output.DebugNotes = "ML service not configured"
		return output, nil
	}

	paths := a.ml.BuildAttackPaths(input.AllFindings)
	if len(paths) == 0 {
		output.DebugNotes = "No attack paths inferred"
		return output, nil
	}

	for i, path := range paths {
		output.Findings = append(output.Findings, model.Finding{
			ID:             fmt.Sprintf("ml-attack-path-%d", i+1),
			Category:       "ml_ai",
			Severity:       model.SeverityMedium,
			Title:          fmt.Sprintf("Potential attack path %d", i+1),
			Description:    path,
			Evidence:       "Built from cross-category finding correlation",
			Recommendation: "Break this chain early by remediating the earliest exposed weakness first.",
		})
	}

	output.Metadata["path_count"] = strconv.Itoa(len(paths))
	output.DebugNotes = "AI attack-path synthesis completed."
	return output, nil
}

type FalsePositiveReviewAgent struct {
	ml      *ml.Service
	enabled bool
}

// falsePositiveReviewChecks lists the check this agent performs. An AI advisor
// provides pre-run focus and writes a post-run lesson to the blackboard.
var falsePositiveReviewChecks = []string{
	"fp_review",
}

func NewFalsePositiveReviewAgent(mlService *ml.Service, enabled bool) *FalsePositiveReviewAgent {
	return &FalsePositiveReviewAgent{ml: mlService, enabled: enabled}
}

func (a *FalsePositiveReviewAgent) Name() string {
	return "false_positive_review"
}

func (a *FalsePositiveReviewAgent) Enabled() bool {
	return a.enabled
}

func (a *FalsePositiveReviewAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	_ = ctx
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UseFalsePositiveReview {
		output.DebugNotes = "False positive review agent disabled by scan options"
		return output, nil
	}
	if a.ml == nil {
		output.DebugNotes = "ML service not configured"
		return output, nil
	}

	candidates := a.ml.FindPotentialFalsePositives(input.AllFindings)
	if len(candidates) == 0 {
		output.DebugNotes = "No low-confidence findings suggested for manual false-positive review"
		return output, nil
	}

	titles := make([]string, 0, len(candidates))
	for _, c := range candidates {
		titles = append(titles, c.Finding.Title)
	}

	output.Findings = append(output.Findings, model.Finding{
		ID:             "ml-fp-review",
		Category:       "ml_ai",
		Severity:       model.SeverityInfo,
		Title:          "Manual false-positive review suggested",
		Description:    "ML confidence scoring identified a subset of findings that should be manually validated before escalation.",
		Evidence:       strings.Join(titles, " | "),
		Recommendation: "Validate these findings with targeted reproduction steps and retain evidence for analyst sign-off.",
	})

	output.Metadata["review_candidates"] = strconv.Itoa(len(candidates))
	output.DebugNotes = "False-positive review queue created from ML confidence signals."
	return output, nil
}

type RemediationPlannerAgent struct {
	ml      *ml.Service
	enabled bool
}

// remediationPlannerChecks lists the check this agent performs. An AI advisor
// provides pre-run focus and writes a post-run lesson to the blackboard.
var remediationPlannerChecks = []string{
	"remediation_planning",
}

func NewRemediationPlannerAgent(mlService *ml.Service, enabled bool) *RemediationPlannerAgent {
	return &RemediationPlannerAgent{ml: mlService, enabled: enabled}
}

func (a *RemediationPlannerAgent) Name() string {
	return "remediation_planner"
}

func (a *RemediationPlannerAgent) Enabled() bool {
	return a.enabled
}

func (a *RemediationPlannerAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	_ = ctx
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	if !input.Options.UseRemediationPlanner {
		output.DebugNotes = "Remediation planner agent disabled by scan options"
		return output, nil
	}
	if a.ml == nil {
		output.DebugNotes = "ML service not configured"
		return output, nil
	}

	plan := a.ml.BuildRemediationPlan(input.AllFindings, 5)
	if len(plan) == 0 {
		output.DebugNotes = "No remediation plan generated"
		return output, nil
	}

	output.Findings = append(output.Findings, model.Finding{
		ID:             "ml-remediation-plan",
		Category:       "ml_ai",
		Severity:       model.SeverityInfo,
		Title:          "AI-assisted remediation plan",
		Description:    "Prioritized remediation sequence generated from severity, exploitability, and category concentration signals.",
		Evidence:       strings.Join(plan, " -> "),
		Recommendation: "Execute steps in order, then rerun scan to verify residual risk reduction.",
	})

	output.Metadata["plan_steps"] = strconv.Itoa(len(plan))
	output.DebugNotes = "AI remediation planning completed."
	return output, nil
}

func toSeverity(score float64) model.Severity {
	if score >= 0.8 {
		return model.SeverityHigh
	}
	if score >= 0.6 {
		return model.SeverityMedium
	}
	if score >= 0.4 {
		return model.SeverityLow
	}
	return model.SeverityInfo
}
