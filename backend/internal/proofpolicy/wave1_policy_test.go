package proofpolicy

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestEvaluateFinding_HighSeverityRaisesMinCoverage verifies that a high-severity
// finding with XSS category requires 1.0 min coverage (not 0.66).
func TestEvaluateFinding_HighSeverityRaisesMinCoverage(t *testing.T) {
	t.Parallel()
	// A medium-severity XSS finding should use the standard 0.66 threshold.
	medResult := EvaluateFinding(model.Finding{
		Category: "xss",
		Severity: model.SeverityMedium,
		PoC:      "alert(1)",
		Evidence: "reflected payload appears in response",
		AffectedURL: "https://example.com",
	})
	if medResult.MinCoverage != 0.66 {
		t.Fatalf("expected medium XSS MinCoverage=0.66, got %f", medResult.MinCoverage)
	}

	// A high-severity XSS finding should use the stricter 1.0 threshold.
	highResult := EvaluateFinding(model.Finding{
		Category: "xss",
		Severity: model.SeverityHigh,
		PoC:      "alert(1)",
		Evidence: "reflected payload appears in response",
		AffectedURL: "https://example.com",
	})
	if highResult.MinCoverage != 1.0 {
		t.Fatalf("expected high XSS MinCoverage=1.0, got %f", highResult.MinCoverage)
	}
}

// TestEvaluateFinding_CriticalSeverityRaisesMinCoverage verifies that critical
// severity uses the strict coverage table for all medium categories.
func TestEvaluateFinding_CriticalSeverityRaisesMinCoverage(t *testing.T) {
	t.Parallel()
	categories := []string{"idor", "path_traversal", "open_redirect", "cors", "csrf", "authentication"}
	for _, cat := range categories {
		result := EvaluateFinding(model.Finding{
			Category: cat,
			Severity: model.SeverityCritical,
			Evidence: "test evidence",
		})
		if result.MinCoverage != 1.0 {
			t.Errorf("expected critical %s MinCoverage=1.0, got %f", cat, result.MinCoverage)
		}
	}
}

// TestEvaluateFinding_LowSeverityKeepsBaseThreshold verifies that low-severity
// findings retain the standard coverage thresholds.
func TestEvaluateFinding_LowSeverityKeepsBaseThreshold(t *testing.T) {
	t.Parallel()
	result := EvaluateFinding(model.Finding{
		Category: "headers",
		Severity: model.SeverityLow,
		Evidence: "X-Frame-Options missing",
	})
	if result.MinCoverage != 0.50 {
		t.Fatalf("expected low-severity headers MinCoverage=0.50, got %f", result.MinCoverage)
	}
}

// TestEvaluateFinding_SeverityUpgradeDoesNotAffectAlreadyStrictCategories
// verifies that categories already at 1.0 stay at 1.0 regardless of severity.
func TestEvaluateFinding_SeverityUpgradeDoesNotAffectAlreadyStrictCategories(t *testing.T) {
	t.Parallel()
	for _, sev := range []model.Severity{model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical} {
		result := EvaluateFinding(model.Finding{
			Category: "sqli",
			Severity: sev,
			Evidence: "sql injection payload",
		})
		if result.MinCoverage != 1.0 {
			t.Errorf("expected sqli MinCoverage=1.0 for severity %s, got %f", sev, result.MinCoverage)
		}
	}
}
