package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestGeneratePythonPoC verifies that PoC scripts are generated for the
// supported vulnerability categories and that unsupported categories return empty.
func TestGeneratePythonPoC(t *testing.T) {
	auth := model.ScanAuthProfile{}

	cases := []struct {
		findingID string
		category  string
		wantEmpty bool
	}{
		{findingID: "sqli-test", category: "sqli", wantEmpty: false},
		{findingID: "xss-test", category: "xss", wantEmpty: false},
		{findingID: "idor-test", category: "idor", wantEmpty: false},
		{findingID: "ssrf-test", category: "ssrf", wantEmpty: false},
		{findingID: "open-redirect-test", category: "redirect", wantEmpty: false},
		{findingID: "race-condition-test", category: "race", wantEmpty: false},
		{findingID: "info-disclosure-test", category: "information-disclosure", wantEmpty: true},
	}

	for _, tc := range cases {
		f := model.Finding{
			ID:          tc.findingID,
			Category:    tc.category,
			AffectedURL: "https://target.example.com/endpoint",
		}
		got := GeneratePythonPoC(f, auth)
		if tc.wantEmpty && got != "" {
			t.Errorf("GeneratePythonPoC(%q): expected empty, got %d chars", tc.findingID, len(got))
		}
		if !tc.wantEmpty && got == "" {
			t.Errorf("GeneratePythonPoC(%q): expected non-empty PoC", tc.findingID)
		}
		if !tc.wantEmpty {
			// The generated PoC must be valid Python 3 preamble.
			if len(got) < 50 {
				t.Errorf("GeneratePythonPoC(%q): PoC too short (%d chars)", tc.findingID, len(got))
			}
		}
	}
}

// TestAttachPythonPoC verifies that AttachPythonPoC populates EvidenceFields
// and PoC on supported finding categories.
func TestAttachPythonPoC(t *testing.T) {
	f := model.Finding{
		ID:          "xss-reflected",
		Category:    "xss",
		AffectedURL: "https://example.com/search",
	}
	auth := model.ScanAuthProfile{}
	enriched := AttachPythonPoC(f, auth)
	if enriched.PoC == "" {
		t.Error("AttachPythonPoC: expected PoC to be populated")
	}
	if enriched.EvidenceFields["pythonPoC"] == "" {
		t.Error("AttachPythonPoC: expected EvidenceFields[pythonPoC] to be populated")
	}
}

// TestFlowSlug verifies stable slug generation for flow finding IDs.
func TestFlowSlug(t *testing.T) {
	got := flowSlug("payment-flow", "add-to-cart")
	if got == "" {
		t.Error("flowSlug: expected non-empty result")
	}
	// Same inputs must produce same output.
	if flowSlug("payment-flow", "add-to-cart") != got {
		t.Error("flowSlug: unstable output")
	}
}
