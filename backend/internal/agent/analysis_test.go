package agent

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestDeduplicateFindings_ClustersByCWEAndHost(t *testing.T) {
	in := []model.Finding{
		{
			ID: "active-xss-reflected", Category: "input-validation", CWE: "CWE-79",
			Severity: model.SeverityHigh, Confidence: 0.8,
			Title: "XSS on /a", AffectedURL: "https://example.com/a", AffectedParameter: "q",
		},
		{
			ID: "active-xss-reflected", Category: "input-validation", CWE: "CWE-79",
			Severity: model.SeverityHigh, Confidence: 0.95,
			Title: "XSS on /b", AffectedURL: "https://example.com/b", AffectedParameter: "q",
		},
		{
			ID: "active-sqli-error-based", Category: "input-validation", CWE: "CWE-89",
			Severity: model.SeverityHigh, AffectedURL: "https://example.com/c", AffectedParameter: "id",
		},
	}

	out := deduplicateFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 deduped clusters (XSS x2 collapsed + SQLi), got %d: %+v", len(out), out)
	}

	// The XSS representative must be the higher-confidence one and must
	// carry a clusteredUrls / affectedCount annotation.
	var xss *model.Finding
	for i := range out {
		if out[i].CWE == "CWE-79" {
			xss = &out[i]
			break
		}
	}
	if xss == nil {
		t.Fatal("expected an XSS representative in the deduped list")
	}
	if xss.Confidence != 0.95 {
		t.Errorf("expected highest-confidence representative (0.95), got %v", xss.Confidence)
	}
	if got := xss.EvidenceFields["affectedCount"]; got != "2" {
		t.Errorf("expected affectedCount=2, got %q", got)
	}
	if !strings.Contains(xss.Evidence, "Cluster: 2 affected endpoints") {
		t.Errorf("expected cluster annotation in evidence, got %q", xss.Evidence)
	}
}

func TestDeduplicateFindings_KeepsDistinctParameters(t *testing.T) {
	in := []model.Finding{
		{ID: "a", Category: "x", CWE: "CWE-1", AffectedURL: "https://h/", AffectedParameter: "p1"},
		{ID: "a", Category: "x", CWE: "CWE-1", AffectedURL: "https://h/", AffectedParameter: "p2"},
	}
	out := deduplicateFindings(in)
	if len(out) != 2 {
		t.Fatalf("findings on different parameters must not collapse, got %d", len(out))
	}
}

func TestDeduplicateFindings_FallsBackToTitleWhenNoMetadata(t *testing.T) {
	in := []model.Finding{
		{Title: "Same title"},
		{Title: "Same title"},
	}
	out := deduplicateFindings(in)
	if len(out) != 1 {
		t.Fatalf("expected fallback to dedupe by title, got %d", len(out))
	}
}
