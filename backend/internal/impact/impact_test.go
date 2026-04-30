package impact

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestEnrichFindingAssignsScoresProofStateAndGoals(t *testing.T) {
	finding := model.Finding{
		ID:          "idor-1",
		Category:    "access_control",
		Severity:    model.SeverityHigh,
		Title:       "Cross-account invoice access via IDOR",
		Description: "An attacker can read invoices belonging to another customer.",
		Evidence:    "responseDiff=other_customer_invoice",
		Impact:      "Unauthorized invoice access and cross-account billing data disclosure.",
		ReproductionSteps: []string{
			"Authenticate as tenant A.",
			"Request /api/invoices/tenant-b-invoice-id.",
		},
		PoC:         "curl -H 'Authorization: Bearer ...' https://example.com/api/invoices/123",
		AffectedURL: "https://example.com/api/invoices/123",
		EvidenceFields: map[string]string{
			"responseDiff": "invoice_owner=tenant-b",
			"recordCount":  "1",
		},
		Exploitability: &model.Exploitability{
			Reachable:      true,
			VerifiedStatus: "demonstrated",
		},
	}

	enriched := EnrichFinding(finding, []model.ImpactGoal{model.ImpactGoalCrossTenantAccess})
	if enriched.ProofState != model.ProofStateSubmissionReady {
		t.Fatalf("ProofState = %q, want %q", enriched.ProofState, model.ProofStateSubmissionReady)
	}
	if enriched.ImpactScore <= 0.8 {
		t.Fatalf("ImpactScore = %.2f, want > 0.8", enriched.ImpactScore)
	}
	if enriched.BountyScore <= 0.8 {
		t.Fatalf("BountyScore = %.2f, want > 0.8", enriched.BountyScore)
	}
	if len(enriched.ImpactGoals) == 0 || enriched.ImpactGoals[0] != model.ImpactGoalCrossTenantAccess {
		t.Fatalf("ImpactGoals = %#v, want cross-tenant access", enriched.ImpactGoals)
	}
	if len(enriched.ProofArtifacts) < 3 {
		t.Fatalf("ProofArtifacts = %d, want at least 3", len(enriched.ProofArtifacts))
	}
}

func TestShouldStopForDemonstratedImpact(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "impact-1",
			Title:       "Account takeover via password reset poisoning",
			Severity:    model.SeverityHigh,
			Impact:      "Account takeover against any user who follows a poisoned reset link.",
			ProofState:  model.ProofStateImpactDemonstrated,
			BountyScore: 0.91,
		},
	}
	stop, reason := ShouldStopForDemonstratedImpact(findings, nil)
	if !stop {
		t.Fatal("expected stop for demonstrated impact")
	}
	if reason == "" {
		t.Fatal("expected non-empty stop reason")
	}
}
