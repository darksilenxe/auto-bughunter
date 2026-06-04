package ml

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestFindPotentialFalsePositivesFlagsWeakLowSignalFindings(t *testing.T) {
	svc := &Service{}
	findings := []model.Finding{
		{
			ID:          "f-weak",
			Category:    "information_disclosure",
			Severity:    model.SeverityInfo,
			Title:       "Possible information disclosure",
			Description: "This may indicate exposure but no direct evidence was collected.",
			Confidence:  0.22,
		},
	}

	out := svc.FindPotentialFalsePositives(findings)
	if len(out) != 1 {
		t.Fatalf("expected 1 false-positive candidate, got %d", len(out))
	}
	if out[0].Finding.ID != "f-weak" {
		t.Fatalf("unexpected candidate id %q", out[0].Finding.ID)
	}
	if out[0].Score < 0.52 {
		t.Fatalf("candidate score should clear threshold, got %.2f", out[0].Score)
	}
}

func TestFindPotentialFalsePositivesIgnoresValidatedFindings(t *testing.T) {
	svc := &Service{}
	findings := []model.Finding{
		{
			ID:          "f-validated",
			Category:    "xss",
			Severity:    model.SeverityHigh,
			Title:       "Potential reflected XSS",
			Description: "Potentially exploitable input reflection.",
			Confidence:  0.48,
			ProofState:  model.ProofStateValidated,
			ReproductionSteps: []string{
				"Send payload in q param",
				"Observe unsanitized response",
			},
			PoC:                 "<script>alert(1)</script>",
			EvidenceQualityTier: "high",
			Exploitability: &model.Exploitability{
				Reachable:      true,
				VerifiedStatus: "validated",
			},
		},
	}

	out := svc.FindPotentialFalsePositives(findings)
	if len(out) != 0 {
		t.Fatalf("expected validated finding to be excluded from false-positive queue, got %d entries", len(out))
	}
}

func TestFindPotentialFalsePositivesAnnotatesProofPolicyGaps(t *testing.T) {
	svc := &Service{}
	findings := []model.Finding{
		{
			ID:          "f-sqli-weak",
			Category:    "sqli",
			Severity:    model.SeverityInfo,
			Title:       "Possible SQL injection",
			Description: "May indicate SQL issue with limited proof.",
			Confidence:  0.2,
		},
	}
	out := svc.FindPotentialFalsePositives(findings)
	if len(out) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(out))
	}
	fields := out[0].Finding.EvidenceFields
	if fields["proofPolicyCategory"] != "sqli" {
		t.Fatalf("expected proof policy category to be sqli, got %q", fields["proofPolicyCategory"])
	}
	if fields["proofPolicyMissing"] == "" {
		t.Fatalf("expected proof policy missing obligations to be recorded")
	}
}

func TestScoreFindingsUsesCalibratedConfidenceSignals(t *testing.T) {
	svc := &Service{}
	findings := []model.Finding{
		{
			ID:          "f-low-signal",
			Category:    "headers",
			Severity:    model.SeverityInfo,
			Title:       "Possible weak header policy",
			Description: "May indicate missing hardening.",
			Confidence:  0,
			DriftStatus: "resolved",
		},
		{
			ID:          "f-verified",
			Category:    "sqli",
			Severity:    model.SeverityMedium,
			Title:       "SQL injection",
			Description: "Server returned SQL error and bypass observed.",
			Confidence:  0,
			ProofState:  model.ProofStateExploited,
			ReproductionSteps: []string{
				"Inject payload in id parameter",
			},
			PoC: "id=1' OR '1'='1",
			Exploitability: &model.Exploitability{
				Reachable:      true,
				VerifiedStatus: "exploited",
			},
		},
	}

	scored := svc.ScoreFindings(findings)
	if len(scored) != 2 {
		t.Fatalf("expected 2 scored findings, got %d", len(scored))
	}

	var weakConf, strongConf float64
	for _, sf := range scored {
		switch sf.Finding.ID {
		case "f-low-signal":
			weakConf = sf.Confidence
		case "f-verified":
			strongConf = sf.Confidence
		}
	}
	if strongConf <= weakConf {
		t.Fatalf("expected verified finding confidence to exceed weak-signal confidence (verified=%.2f weak=%.2f)", strongConf, weakConf)
	}
}

func TestFalsePositiveThresholdForFindingPrefersCategoryPolicy(t *testing.T) {
	highInfoDisclosure := model.Finding{
		Category: "information_disclosure",
		Severity: model.SeverityHigh,
	}
	if got := falsePositiveThresholdForFinding(highInfoDisclosure); got != 0.48 {
		t.Fatalf("expected category threshold override 0.48, got %.2f", got)
	}

	highUnknown := model.Finding{
		Category: "custom_category",
		Severity: model.SeverityHigh,
	}
	if got := falsePositiveThresholdForFinding(highUnknown); got != 0.72 {
		t.Fatalf("expected severity fallback threshold 0.72, got %.2f", got)
	}
}
