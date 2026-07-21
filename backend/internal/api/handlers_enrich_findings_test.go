package api

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestEnrichFindings_AssignsSyntheticIDWhenMissing(t *testing.T) {
	input := []model.Finding{
		{
			Category:  "xss",
			Title:     "Reflected XSS in search",
			Severity:  model.SeverityMedium,
			AffectedURL: "https://example.test/search",
		},
	}

	out := enrichFindings(input)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if strings.TrimSpace(out[0].ID) == "" {
		t.Fatalf("expected synthetic ID to be assigned")
	}
	if !strings.HasPrefix(out[0].ID, "finding-") {
		t.Fatalf("expected synthetic ID prefix, got %q", out[0].ID)
	}
}

func TestEnrichFindings_NormalizesAgentSetID(t *testing.T) {
	// Agent-assigned positional IDs (e.g. "hypothesis-1-sqli") must be
	// replaced with a content-based synthetic ID so that the same finding
	// always gets the same ID across scans, regardless of agent ordering.
	input := []model.Finding{
		{
			ID:       "hypothesis-1-sqli",
			Category: "sqli",
			Title:    "SQL Injection in login",
			Severity: model.SeverityHigh,
		},
	}
	out := enrichFindings(input)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].ID == "hypothesis-1-sqli" {
		t.Fatalf("expected agent-set positional ID to be replaced with synthetic ID, got %q", out[0].ID)
	}
	if !strings.HasPrefix(out[0].ID, "finding-") {
		t.Fatalf("expected synthetic ID prefix 'finding-', got %q", out[0].ID)
	}
}

func TestEnrichFindings_SameContentSameIDAcrossScans(t *testing.T) {
	// Two findings with identical content but different agent-assigned IDs
	// must both produce the same synthetic ID, ensuring cross-scan rejection
	// filtering works correctly.
	f1 := model.Finding{ID: "hypothesis-1-xss", Category: "xss", Title: "Reflected XSS in search", AffectedURL: "https://example.test/search"}
	f2 := model.Finding{ID: "hypothesis-3-xss", Category: "xss", Title: "Reflected XSS in search", AffectedURL: "https://example.test/search"}
	out1 := enrichFindings([]model.Finding{f1})
	out2 := enrichFindings([]model.Finding{f2})
	if out1[0].ID != out2[0].ID {
		t.Fatalf("same content produced different IDs: %q vs %q", out1[0].ID, out2[0].ID)
	}
}

