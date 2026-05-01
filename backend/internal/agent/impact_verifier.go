package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/impact"
	"auto-bughunter/backend/internal/model"
)

type ImpactVerifierAgent struct {
	enabled bool
}

func NewImpactVerifierAgent(enabled bool) *ImpactVerifierAgent {
	return &ImpactVerifierAgent{enabled: enabled}
}

func (a *ImpactVerifierAgent) Name() string  { return "impact_verifier" }
func (a *ImpactVerifierAgent) Enabled() bool { return a.enabled }

func (a *ImpactVerifierAgent) Run(ctx context.Context, input AgentInput) (AgentOutput, error) {
	_ = ctx
	output := AgentOutput{
		AgentName: a.Name(),
		Findings:  make([]model.Finding, 0),
		Metadata:  make(map[string]string),
		Status:    "completed",
	}

	source := input.AllFindings
	if len(source) == 0 {
		source = input.Previous.Findings
	}
	if len(source) == 0 {
		output.DebugNotes = "ImpactVerifierAgent: no findings to verify"
		return output, nil
	}

	goals := impact.GoalsOrDefault(input.Options)
	promoted := make([]model.Finding, 0, len(source))
	for _, finding := range source {
		if strings.HasPrefix(strings.TrimSpace(finding.ID), "impact-verify-") {
			continue
		}
		enriched := impact.EnrichFinding(finding, goals)
		if !shouldPromoteImpactFinding(enriched) {
			continue
		}
		promoted = append(promoted, buildImpactVerificationFinding(enriched))
	}
	promoted = impact.RankFindings(promoted, goals)
	output.Findings = promoted
	output.Metadata["impact_goals"] = impact.GoalPrompt(goals)
	output.Metadata["playbooks"] = impact.PlaybookPrompt(goals)
	output.Metadata["verified_findings"] = fmt.Sprintf("%d", len(promoted))
	output.DebugNotes = fmt.Sprintf("ImpactVerifierAgent: promoted %d findings into impact-focused proof packages.", len(promoted))
	return output, nil
}

func shouldPromoteImpactFinding(f model.Finding) bool {
	if f.ProofState == model.ProofStateImpactDemonstrated || f.ProofState == model.ProofStateSubmissionReady {
		return true
	}
	if f.BountyScore >= 0.72 && (len(f.ProofArtifacts) >= 2 || len(f.ReproductionSteps) >= 2) {
		return true
	}
	if f.ImpactScore >= 0.78 && strings.TrimSpace(f.Impact) != "" {
		return true
	}
	return false
}

func buildImpactVerificationFinding(source model.Finding) model.Finding {
	goalParts := make([]string, 0, len(source.ImpactGoals))
	for _, goal := range source.ImpactGoals {
		goalParts = append(goalParts, strings.ReplaceAll(string(goal), "_", " "))
	}
	sort.Strings(goalParts)
	titleSuffix := "demonstrated impact"
	if len(goalParts) > 0 {
		titleSuffix = goalParts[0]
	}
	description := "Impact verifier converted a scanner finding into a bug-bounty-oriented proof package. " +
		"The output focuses on exploitability, business effect, and evidence quality instead of only the raw vulnerability class."
	if strings.TrimSpace(source.Impact) != "" {
		description += "\n\nImpact hypothesis: " + source.Impact
	}
	evidence := fmt.Sprintf(
		"Source finding: %s | proof_state=%s | impact_score=%.2f | bounty_score=%.2f",
		source.ID,
		source.ProofState,
		source.ImpactScore,
		source.BountyScore,
	)
	if len(source.ProofArtifacts) > 0 {
		artifactLabels := make([]string, 0, len(source.ProofArtifacts))
		for _, artifact := range source.ProofArtifacts {
			label := strings.TrimSpace(artifact.Label)
			if label == "" {
				label = artifact.Type
			}
			if label != "" {
				artifactLabels = append(artifactLabels, label)
			}
		}
		if len(artifactLabels) > 0 {
			evidence += " | artifacts=" + strings.Join(artifactLabels, ", ")
		}
	}
	fields := map[string]string{
		"sourceFindingID": source.ID,
		"proofState":      string(source.ProofState),
		"impactScore":     fmt.Sprintf("%.2f", source.ImpactScore),
		"bountyScore":     fmt.Sprintf("%.2f", source.BountyScore),
	}
	for k, v := range source.EvidenceFields {
		fields[k] = v
	}
	return model.Finding{
		ID:                "impact-verify-" + source.ID,
		Category:          "impact",
		Severity:          promotedSeverity(source),
		Title:             fmt.Sprintf("Impact verification: %s (%s)", source.Title, titleSuffix),
		Description:       description,
		Evidence:          evidence,
		Recommendation:    source.Recommendation,
		Confidence:        impact.MaxFloat(source.Confidence, source.BountyScore),
		Sources:           appendUnique(source.Sources, "impact-verifier"),
		EvidenceFields:    fields,
		BusinessTags:      appendUnique(source.BusinessTags, "impact:verified"),
		Exploitability:    source.Exploitability,
		AffectedURL:       source.AffectedURL,
		AffectedParameter: source.AffectedParameter,
		ReproductionSteps: append([]string(nil), source.ReproductionSteps...),
		Impact:            source.Impact,
		ImpactScore:       source.ImpactScore,
		BountyScore:       source.BountyScore,
		ProofState:        source.ProofState,
		ImpactGoals:       append([]model.ImpactGoal(nil), source.ImpactGoals...),
		ProofArtifacts:    append([]model.ProofArtifact(nil), source.ProofArtifacts...),
		References:        append([]string(nil), source.References...),
		PoC:               source.PoC,
		CWE:               source.CWE,
		OWASPCategory:     source.OWASPCategory,
		CVSSVector:        source.CVSSVector,
		CVSSScore:         source.CVSSScore,
	}
}

func promotedSeverity(source model.Finding) model.Severity {
	if source.BountyScore >= 0.8 || source.ImpactScore >= 0.85 {
		return model.SeverityHigh
	}
	if source.Severity == model.SeverityCritical || source.Severity == model.SeverityHigh {
		return model.SeverityHigh
	}
	return model.SeverityMedium
}
