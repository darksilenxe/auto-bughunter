package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestAnalyzeStorageJSON_TokenKeyPattern(t *testing.T) {
	ep := "https://example.com"
	storageJSON := `{"localStorage":{"auth_token":"some-value"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	findings := analyzeStorageJSON(ep, storageJSON, emitted)
	if len(findings) == 0 {
		t.Fatal("expected finding for token key pattern in localStorage")
	}
}

func TestAnalyzeStorageJSON_JWTValuePattern(t *testing.T) {
	ep := "https://example.com"
	// Use a neutral key name ("pref") with a JWT-format value (eyJ prefix) to test
	// the value-based detection path in analyzeStorageJSON.
	storageJSON := `{"localStorage":{"pref":"eyJhbGciOiJIUzI1NiJ9.eyJzdWI6InVzZXIxIn0.sig"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	findings := analyzeStorageJSON(ep, storageJSON, emitted)
	hasJWT := false
	for _, f := range findings {
		if f.CWE == "CWE-312" && f.Severity == model.SeverityHigh {
			hasJWT = true
		}
	}
	if !hasJWT {
		t.Fatal("expected high-severity finding for JWT value in localStorage")
	}
}

func TestAnalyzeStorageJSON_CleanStorage(t *testing.T) {
	ep := "https://example.com"
	storageJSON := `{"localStorage":{"theme":"dark","language":"en"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	findings := analyzeStorageJSON(ep, storageJSON, emitted)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for clean storage data, got %d", len(findings))
	}
}

func TestAnalyzeStorageJSON_Deduplication(t *testing.T) {
	ep := "https://example.com"
	storageJSON := `{"localStorage":{"auth_token":"abc"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	// First call
	findings1 := analyzeStorageJSON(ep, storageJSON, emitted)
	// Second call with same emitted map should produce no duplicates
	findings2 := analyzeStorageJSON(ep, storageJSON, emitted)
	if len(findings1) == 0 {
		t.Fatal("expected findings on first call")
	}
	if len(findings2) != 0 {
		t.Fatal("expected deduplication to prevent re-emitting the same finding")
	}
}
