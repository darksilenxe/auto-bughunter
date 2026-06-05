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

// ──────────────────────────────────────────────────────────────────────────────
// New category tests added for SSRF, SSTI, XXE, NoSQLi, path traversal,
// open redirect and tiered coverage thresholds.
// ──────────────────────────────────────────────────────────────────────────────

func TestSSRFPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:          "SSRF",
		AffectedParameter: "url",
		Evidence:          "Request reached 169.254.169.254 with 200 response; out-of-band DNS interaction confirmed via interactsh callback.",
		EvidenceFields: map[string]string{
			"internalEndpointReached": "169.254.169.254",
			"oobInteraction":          "dns.interactsh.com",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "ssrf" {
		t.Fatalf("expected ssrf, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
	if out.BelowMinCoverage {
		t.Fatal("full coverage should not be below minimum")
	}
}

func TestSSRFPolicyMissingFields(t *testing.T) {
	f := model.Finding{Category: "ssrf", Evidence: "might be ssrf"}
	out := EvaluateFinding(f)
	if len(out.Missing) == 0 {
		t.Fatal("expected missing fields for weak SSRF evidence")
	}
	if !out.BelowMinCoverage {
		t.Fatal("partial coverage should be below minimum for ssrf (requires 100%)")
	}
}

func TestSSTIPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:          "ssti",
		AffectedParameter: "name",
		Evidence:          "Template expression {{7*7}} evaluated to 49 in response body.",
		EvidenceFields: map[string]string{
			"templateExecutionSignal": "49",
		},
		PoC: "{{7*7}}",
	}
	out := EvaluateFinding(f)
	if out.Category != "ssti" {
		t.Fatalf("expected ssti, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
}

func TestXXEPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:    "XXE",
		AffectedURL: "https://example.com/api/xml",
		Evidence:    "External entity resolved; file contents of /etc/passwd appeared in response. XML parser libxml2 identified.",
		EvidenceFields: map[string]string{
			"entityResolutionSignal": "/etc/passwd content present",
			"affectedParser":         "libxml2",
		},
		PoC: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
	}
	out := EvaluateFinding(f)
	if out.Category != "xxe" {
		t.Fatalf("expected xxe, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
}

func TestNoSQLiPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category: "nosqli",
		Evidence: "Operator injection with $gt bypassed authentication filter; all user records returned.",
		EvidenceFields: map[string]string{
			"operatorInjectionBehavior": "$gt bypass",
			"filterBypassEvidence":      "all records returned",
			"affectedCollection":        "users",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "nosqli" {
		t.Fatalf("expected nosqli, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
}

func TestPathTraversalPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:    "path traversal",
		AffectedURL: "https://example.com/download?file=../../../../etc/passwd",
		Evidence:    "../../../../etc/passwd returned root:x:0:0 in response body.",
		EvidenceFields: map[string]string{
			"fileContentInResponse": "root:x:0:0",
		},
		PoC: "../../../../etc/passwd",
	}
	out := EvaluateFinding(f)
	if out.Category != "path_traversal" {
		t.Fatalf("expected path_traversal, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
}

func TestOpenRedirectPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:          "open redirect",
		AffectedParameter: "return",
		Evidence:          "Open redirect: Location header pointed to https://evil.example.com. 302 response observed.",
		EvidenceFields: map[string]string{
			"destinationURLControl": "https://evil.example.com",
			"locationHeaderValue":   "https://evil.example.com",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "open_redirect" {
		t.Fatalf("expected open_redirect, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("unexpected missing fields: %v", out.Missing)
	}
	if out.BelowMinCoverage {
		t.Fatal("full coverage should not be below minimum")
	}
}

func TestOpenRedirectPartialCoverageAboveMinimum(t *testing.T) {
	// open_redirect min coverage is 0.66; satisfying only 1 of 3 fields puts
	// coverage at ~0.33, which is below 0.66 so BelowMinCoverage should be true.
	// Only affected_parameter fires via AffectedParameter; the other two rules
	// require redirect keywords or mechanism signals that are not present.
	f := model.Finding{
		Category:          "open redirect",
		AffectedParameter: "next",
		// No redirect keywords → redirect_destination_controlled and
		// redirect_mechanism_identified should both miss.
		Evidence: "This endpoint accepts a next parameter.",
	}
	out := EvaluateFinding(f)
	if out.Coverage >= 1 {
		t.Fatal("expected partial coverage")
	}
	if !out.BelowMinCoverage {
		t.Fatalf("partial coverage %.2f should be below minimum 0.66", out.Coverage)
	}
}

func TestSQLiBelowMinCoverageFlag(t *testing.T) {
	// sqli min coverage is 1.0; any unsatisfied field triggers BelowMinCoverage.
	f := model.Finding{
		Category: "sqli",
		Evidence: "May indicate an issue.",
	}
	out := EvaluateFinding(f)
	if !out.BelowMinCoverage {
		t.Fatal("partial sqli coverage should set BelowMinCoverage=true (min=1.0)")
	}
}
