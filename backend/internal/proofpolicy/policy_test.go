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
	out := EvaluateFinding(model.Finding{Category: "totally-fake-category"})
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

// ──────────────────────────────────────────────────────────────────────────────
// CORS proof policy tests
// ──────────────────────────────────────────────────────────────────────────────

func TestCORSPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:    "cors",
		AffectedURL: "https://api.example.com/user/data",
		Evidence:    "Access-Control-Allow-Origin reflected attacker-controlled origin; Access-Control-Allow-Credentials: true observed.",
		EvidenceFields: map[string]string{
			"reflectedOrigin":     "https://abh-cors-canary.invalid",
			"allowOriginResponse": "https://abh-cors-canary.invalid",
			"credentialsAllowed":  "true",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "cors" {
		t.Fatalf("expected cors category, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("expected full coverage, missing: %v", out.Missing)
	}
	if out.BelowMinCoverage {
		t.Fatalf("full coverage should not be below minimum")
	}
}

func TestCORSPolicyMissingOriginReflectionEvidence(t *testing.T) {
	// A finding with no explicit CORS reflection evidence should fail the
	// origin_reflection_evidence requirement and surface as below-min-coverage.
	f := model.Finding{
		Category:    "cors",
		AffectedURL: "https://api.example.com/user/data",
		Evidence:    "Cross-origin read may be possible.",
	}
	out := EvaluateFinding(f)
	if out.Category != "cors" {
		t.Fatalf("expected cors category, got %q", out.Category)
	}
	if out.Coverage >= 1 {
		t.Fatalf("expected partial coverage, got %.2f", out.Coverage)
	}
	if !out.BelowMinCoverage {
		t.Fatalf("partial cors coverage should be below minimum (0.66)")
	}
}

func TestCORSCategoryNormalisation(t *testing.T) {
	for _, cat := range []string{"cors", "cors_redirect", "cors_misconfiguration", "CORS"} {
		out := EvaluateFinding(model.Finding{
			Category:    cat,
			AffectedURL: "https://api.example.com/",
			Evidence:    "Access-Control-Allow-Origin reflected origin; credentials allowed.",
			EvidenceFields: map[string]string{
				"reflectedOrigin":    "https://evil.example",
				"credentialsAllowed": "true",
			},
		})
		if out.Category != "cors" {
			t.Fatalf("category %q: expected canonical 'cors', got %q", cat, out.Category)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Clickjacking proof policy tests
// ──────────────────────────────────────────────────────────────────────────────

func TestClickjackingPolicySatisfied(t *testing.T) {
	f := model.Finding{
		Category:    "clickjacking",
		AffectedURL: "https://app.example.com/dashboard",
		Evidence:    "HTML page rendered in iframe; X-Frame-Options absent; frame-ancestors CSP directive not set.",
		EvidenceFields: map[string]string{
			"xFrameOptions": "",
			"csp":           "",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "clickjacking" {
		t.Fatalf("expected clickjacking category, got %q", out.Category)
	}
	if len(out.Missing) != 0 {
		t.Fatalf("expected full coverage, missing: %v", out.Missing)
	}
}

func TestClickjackingPolicyMissingAffectedURL(t *testing.T) {
	// Without an affected URL the finding cannot be reproduced; it should fail
	// the affected_url requirement and surface as below-min-coverage.
	f := model.Finding{
		Category: "clickjacking",
		Evidence: "X-Frame-Options missing on HTML page.",
		EvidenceFields: map[string]string{
			"xFrameOptions": "",
		},
	}
	out := EvaluateFinding(f)
	if out.Category != "clickjacking" {
		t.Fatalf("expected clickjacking category, got %q", out.Category)
	}
	if !out.BelowMinCoverage {
		t.Fatalf("missing affected_url should push coverage below minimum")
	}
}

func TestClickjackingCategoryNormalisation(t *testing.T) {
	for _, cat := range []string{"clickjacking", "ui_redress", "ui_redressing", "Clickjacking"} {
		out := EvaluateFinding(model.Finding{
			Category:    cat,
			AffectedURL: "https://app.example.com/",
			Evidence:    "HTML page; X-Frame-Options absent.",
			EvidenceFields: map[string]string{
				"xFrameOptions": "",
			},
		})
		if out.Category != "clickjacking" {
			t.Fatalf("category %q: expected canonical 'clickjacking', got %q", cat, out.Category)
		}
	}
}

func TestAccessControlHyphenCategoryNormalisation(t *testing.T) {
	out := EvaluateFinding(model.Finding{
		Category:          "access-control",
		AffectedURL:       "https://example.com/api/users/2",
		AffectedParameter: "userId",
		Evidence:          "Broken access control allowed another account data access.",
	})
	if out.Category != "idor" {
		t.Fatalf("expected canonical 'idor', got %q", out.Category)
	}
}

func TestAuthenticationPolicySatisfied(t *testing.T) {
	out := EvaluateFinding(model.Finding{
		Category:    "authentication",
		AffectedURL: "https://example.com/oauth/token",
		Evidence:    "OAuth refresh token replay accepted while invalid_grant control token was rejected.",
		EvidenceFields: map[string]string{
			"controlTokenRejected": "true",
		},
	})
	if out.Category != "authentication" {
		t.Fatalf("expected canonical 'authentication', got %q", out.Category)
	}
	// screenshot_state_change is an optional bonus rule added by browser
	// validation. A finding without it should still satisfy the minimum
	// coverage threshold (0.66 ≤ 3/4 = 0.75).
	if out.BelowMinCoverage {
		t.Fatalf("authentication finding with 3/4 rules satisfied should not be below min coverage (%.2f >= %.2f)", out.Coverage, out.MinCoverage)
	}
	// The three core rules must all be satisfied; only screenshot_state_change
	// is expected to be missing.
	coreRequired := []string{"auth_flow_or_token_surface", "control_bypass_signal", "control_rejection_baseline"}
	for _, req := range coreRequired {
		satisfied := false
		for _, s := range out.Satisfied {
			if s == req {
				satisfied = true
				break
			}
		}
		if !satisfied {
			t.Errorf("expected core rule %q to be satisfied; satisfied=%v", req, out.Satisfied)
		}
	}
}

func TestAuthenticationPolicySatisfied_WithScreenshotEvidence(t *testing.T) {
	// When browser validation evidence is present, all 4 rules including
	// screenshot_state_change should be satisfied.
	out := EvaluateFinding(model.Finding{
		Category:    "authentication",
		AffectedURL: "https://example.com/oauth/token",
		Evidence:    "OAuth refresh token replay accepted while invalid_grant control token was rejected.",
		EvidenceFields: map[string]string{
			"controlTokenRejected":          "true",
			"browserValidation.htmlChanged": "true",
		},
	})
	if out.BelowMinCoverage {
		t.Fatalf("expected above min coverage; got coverage=%.2f minCoverage=%.2f", out.Coverage, out.MinCoverage)
	}
	for _, missing := range out.Missing {
		if missing == "screenshot_state_change" {
			t.Errorf("expected screenshot_state_change to be satisfied when browserValidation.htmlChanged=true")
		}
	}
}
