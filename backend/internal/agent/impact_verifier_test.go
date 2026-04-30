package agent

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestImpactVerifierAgentPromotesDemonstratedImpact(t *testing.T) {
	agent := NewImpactVerifierAgent(true)
	out, err := agent.Run(context.Background(), AgentInput{
		Options: model.ScanOptions{
			ImpactGoals: []model.ImpactGoal{model.ImpactGoalCrossTenantAccess},
		},
		AllFindings: []model.Finding{
			{
				ID:          "idor-tenant-1",
				Category:    "access_control",
				Severity:    model.SeverityHigh,
				Title:       "Cross-tenant order access",
				Impact:      "Cross-tenant order data disclosure.",
				Evidence:    "roleDiff=tenantA->tenantB",
				AffectedURL: "https://example.com/api/orders/42",
				ReproductionSteps: []string{
					"Login as tenant A.",
					"Request tenant B order ID.",
				},
				PoC: "curl https://example.com/api/orders/42",
				EvidenceFields: map[string]string{
					"responseDiff": "tenant_id changed from A to B",
				},
				Exploitability: &model.Exploitability{
					Reachable:      true,
					VerifiedStatus: "demonstrated",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 promoted finding, got %d", len(out.Findings))
	}
	got := out.Findings[0]
	if got.Category != "impact" {
		t.Fatalf("Category = %q, want impact", got.Category)
	}
	if got.ProofState != model.ProofStateSubmissionReady {
		t.Fatalf("ProofState = %q, want submission_ready", got.ProofState)
	}
	if got.ImpactScore <= 0 || got.BountyScore <= 0 {
		t.Fatalf("expected positive scores, got impact=%.2f bounty=%.2f", got.ImpactScore, got.BountyScore)
	}
	if got.EvidenceFields["sourceFindingID"] != "idor-tenant-1" {
		t.Fatalf("sourceFindingID = %q, want idor-tenant-1", got.EvidenceFields["sourceFindingID"])
	}
}
