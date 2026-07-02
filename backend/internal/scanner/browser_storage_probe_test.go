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

// TestAnalyzeStorageJSON_NonSensitiveGenericKeys guards against a previous
// false-positive source: bare "key", "user", "email", and "address" patterns
// matched routine, non-sensitive UI state (cache keys, display usernames,
// contact emails, IP addresses) and were removed from the key-pattern list.
func TestAnalyzeStorageJSON_NonSensitiveGenericKeys(t *testing.T) {
	ep := "https://example.com"
	storageJSON := `{"localStorage":{"cache_key":"v3","user_theme":"dark","contact_email":"a@b.com","ip_address":"1.2.3.4"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	findings := analyzeStorageJSON(ep, storageJSON, emitted)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-sensitive generic keys, got %d: %+v", len(findings), findings)
	}
}

// TestAnalyzeStorageJSON_Base64JSONIsNotJWT guards against a previous
// false-positive source: any base64-encoded JSON blob starts with "eyJ" (the
// base64 encoding of `{"`), so a bare prefix check flagged non-token data as
// a High-severity JWT leak. Only a genuine three-segment JWT should match.
func TestAnalyzeStorageJSON_Base64JSONIsNotJWT(t *testing.T) {
	ep := "https://example.com"
	// base64("{"locale":"en-US","theme":"dark"}") - a plain base64-encoded
	// JSON blob with no dot-separated segments, so it is not a JWT.
	storageJSON := `{"localStorage":{"prefs":"eyJsb2NhbGUiOiJlbi1VUyIsInRoZW1lIjoiZGFyayJ9"},"sessionStorage":{},"indexedDB":[]}`
	emitted := map[string]bool{}
	findings := analyzeStorageJSON(ep, storageJSON, emitted)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for non-JWT base64 JSON blob, got %d: %+v", len(findings), findings)
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
