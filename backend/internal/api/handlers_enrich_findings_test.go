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

func TestEnrichFindings_PreservesExistingIDAcrossDedupMerge(t *testing.T) {
	input := []model.Finding{
		{
			ID:       "explicit-id",
			Category: "xss",
			Title:    "Reflected XSS in search",
			Severity: model.SeverityLow,
		},
		{
			Category: "xss",
			Title:    "Reflected XSS in search",
			Severity: model.SeverityMedium,
		},
	}

	out := enrichFindings(input)
	if len(out) != 1 {
		t.Fatalf("expected deduped single finding, got %d", len(out))
	}
	if out[0].ID != "explicit-id" {
		t.Fatalf("expected existing ID to win, got %q", out[0].ID)
	}
}
