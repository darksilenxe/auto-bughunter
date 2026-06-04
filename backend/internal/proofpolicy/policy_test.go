package proofpolicy

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestEvaluateFindingSatisfiedXSSPolicy(t *testing.T) {
	f := model.Finding{
		Category:          "xss",
		Title:             "Reflected XSS in q parameter",
		Evidence:          "Payload reflected unsanitized and script executed in DOM.",
		AffectedURL:       "https://example.com/search?q=test",
		AffectedParameter: "q",
		PoC:               "<script>alert(1)</script>",
	}
	out := EvaluateFinding(f)
	if out.Category != "xss" {
		t.Fatalf("expected xss category, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("expected no missing obligations, got %+v", out.Missing)
	}
	if out.Coverage != 1 {
		t.Fatalf("expected full coverage, got %.2f", out.Coverage)
	}
}

func TestEvaluateFindingMissingSQLiPolicySignals(t *testing.T) {
	f := model.Finding{
		Category: "sqli",
		Title:    "Possible SQL injection",
		Evidence: "May indicate an issue.",
	}
	out := EvaluateFinding(f)
	if out.Category != "sqli" {
		t.Fatalf("expected sqli category, got %q", out.Category)
	}
	if len(out.Missing) == 0 {
		t.Fatalf("expected missing obligations, got %+v", out)
	}
	if out.Coverage >= 1 {
		t.Fatalf("expected partial coverage, got %.2f", out.Coverage)
	}
}

func TestEvaluateFindingUnsupportedCategory(t *testing.T) {
	out := EvaluateFinding(model.Finding{Category: "csrf"})
	if len(out.Required) != 0 || out.Category != "" {
		t.Fatalf("expected empty result for unsupported category, got %+v", out)
	}
}
