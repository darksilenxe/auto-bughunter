package api

import (
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

// TestEnrichFindingsShadowPreReportPopulatesMetrics verifies the shadow
// pre-report verification pass records metrics for every enriched finding
// without mutating the returned findings.
func TestEnrichFindingsShadowPreReportPopulatesMetrics(t *testing.T) {
	scanner.ResetVerificationMetrics()
	before := scanner.GetVerificationMetrics()
	if before.Total != 0 {
		t.Fatalf("expected reset metrics; got total=%d", before.Total)
	}

	in := []model.Finding{
		{
			ID:       "fp-1",
			Category: "xss",
			Title:    "reflected xss",
			Severity: model.Severity("Medium"),
			EvidenceFields: map[string]string{
				"reflectedMarker":     "abh_xss_marker",
				"responseBodySnippet": "<svg/onload=…>",
			},
		},
		{
			ID:       "fp-2",
			Category: "ssrf",
			Title:    "internal fetch",
			Severity: model.Severity("High"),
			EvidenceFields: map[string]string{
				"oobInteraction":       "dns",
				"timingDifferentialMs": "2400",
				"responseBodySnippet":  "169.254.169.254 …",
			},
		},
	}

	out := enrichFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}

	after := scanner.GetVerificationMetrics()
	if after.Total < 2 {
		t.Errorf("expected shadow verifier to record ≥2 candidates; got %d", after.Total)
	}

	// The shadow pass must not have mutated evidence fields on the emitted
	// findings — only the shared verifier's in-memory copy is annotated.
	for _, f := range out {
		if _, ok := f.EvidenceFields["preReport.verified"]; ok {
			t.Errorf("shadow verifier must not mutate emitted finding %q", f.ID)
		}
	}
}
