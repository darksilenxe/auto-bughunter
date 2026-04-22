package ai

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestSelectDomainProfile verifies that domain profile packs are selected
// for the correct target URL patterns.
func TestSelectDomainProfile(t *testing.T) {
	cases := []struct {
		url      string
		wantName string
	}{
		{"https://pay.example.com", "fintech"},
		{"https://bank.example.com/api", "fintech"},
		{"https://hospital.health.example.com", "healthcare"},
		{"https://patient-ehr.example.com", "healthcare"},
		{"https://app.saas-company.com", "saas"},
		{"https://api.example.com/v2", "api-first"},
		{"https://random-blog.example.com", ""},
	}
	for _, tc := range cases {
		got := SelectDomainProfile(tc.url)
		if tc.wantName == "" {
			if got != nil {
				t.Errorf("SelectDomainProfile(%q) = %q, want nil", tc.url, got.Name)
			}
			continue
		}
		if got == nil {
			t.Errorf("SelectDomainProfile(%q) = nil, want %q", tc.url, tc.wantName)
			continue
		}
		if got.Name != tc.wantName {
			t.Errorf("SelectDomainProfile(%q) = %q, want %q", tc.url, got.Name, tc.wantName)
		}
	}
}

// TestBuildLocalNarrativeReport verifies the rule-based narrative report
// generator returns a non-empty executive summary.
func TestBuildLocalNarrativeReport(t *testing.T) {
	findings := []model.Finding{
		{
			ID:             "sqli-1",
			Category:       "sqli",
			Severity:       model.SeverityHigh,
			Title:          "SQL Injection in /search",
			AffectedURL:    "https://target.example.com/search",
			Recommendation: "Use parameterized queries",
		},
		{
			ID:          "idor-1",
			Category:    "idor",
			Severity:    model.SeverityHigh,
			Title:       "IDOR on /api/user/:id",
			AffectedURL: "https://target.example.com/api/user/123",
		},
	}

	report := buildLocalNarrativeReport("https://target.example.com", findings)
	if report.ExecutiveSummary == "" {
		t.Error("buildLocalNarrativeReport: empty ExecutiveSummary")
	}
	if report.ComplianceFramework == "" {
		t.Error("buildLocalNarrativeReport: empty ComplianceFramework")
	}
}

// TestBuildLocalNarrativeReportEmpty verifies the no-findings case.
func TestBuildLocalNarrativeReportEmpty(t *testing.T) {
	report := buildLocalNarrativeReport("https://example.com", nil)
	if report.ExecutiveSummary == "" {
		t.Error("buildLocalNarrativeReport (empty): expected non-empty ExecutiveSummary")
	}
}

// TestComplianceFrameworkForTarget verifies domain → compliance framework
// mapping.
func TestComplianceFrameworkForTarget(t *testing.T) {
	cases := []struct {
		url   string
		want  string
	}{
		{"https://pay.example.com", "PCI-DSS"},
		{"https://hospital-ehr.health.org", "HIPAA"},
		{"https://random.example.com", "SOC2"},
	}
	for _, tc := range cases {
		got := complianceFrameworkForTarget(tc.url)
		if got != tc.want {
			t.Errorf("complianceFrameworkForTarget(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// TestBuildPlannerSystemPromptInjectsDomainContext verifies that the domain
// context is injected into the planner system prompt for matching targets.
func TestBuildPlannerSystemPromptInjectsDomainContext(t *testing.T) {
	fintechPrompt := buildPlannerSystemPrompt("https://pay.example.com/checkout")
	if !contains(fintechPrompt, "fintech") {
		t.Errorf("buildPlannerSystemPrompt for fintech target: expected 'fintech' in prompt, got: %s", fintechPrompt)
	}

	genericPrompt := buildPlannerSystemPrompt("https://unknown.example.com")
	if contains(genericPrompt, "DOMAIN CONTEXT") {
		t.Errorf("buildPlannerSystemPrompt for generic target: did not expect domain context injection, got: %s", genericPrompt)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		(len(s) > 0 && len(sub) > 0 && indexString(s, sub) >= 0))
}

func indexString(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
