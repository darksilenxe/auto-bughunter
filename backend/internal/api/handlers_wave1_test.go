package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestValidatePolicyPackBudgets_SafeProfileRejectsExploitAttempts(t *testing.T) {
	err := validatePolicyPackBudgets(model.AutomationPolicyPack{
		AutomationMode:           "safe",
		MaxExploitAttempts:       2,
		MaxAutomationConcurrency: 1,
		MaxPerTargetConcurrency:  1,
		DailyScanLimit:           5,
		DailyRuntimeLimitMinutes: 60,
		DailyProbeLimit:          100,
	})
	if err == nil || !strings.Contains(err.Error(), "maxExploitAttempts") {
		t.Fatalf("expected maxExploitAttempts validation error for safe profile, got %v", err)
	}
}

func TestValidatePolicyPackBudgets_AggressiveRequiresMinimumExploitAttempts(t *testing.T) {
	err := validatePolicyPackBudgets(model.AutomationPolicyPack{
		AutomationMode:           "aggressive",
		MaxExploitAttempts:       1,
		MaxAutomationConcurrency: 4,
		MaxPerTargetConcurrency:  3,
		DailyScanLimit:           20,
		DailyRuntimeLimitMinutes: 240,
		DailyProbeLimit:          5000,
		MinExpectedROIUSD:        100,
	})
	if err == nil || !strings.Contains(err.Error(), "maxExploitAttempts") {
		t.Fatalf("expected maxExploitAttempts validation error for aggressive profile, got %v", err)
	}
}

func TestValidatePolicyPackBudgets_AutonomousAcceptsValidPack(t *testing.T) {
	err := validatePolicyPackBudgets(model.AutomationPolicyPack{
		AutomationMode:           "autonomous",
		MaxExploitAttempts:       2,
		MaxAutomationConcurrency: 2,
		MaxPerTargetConcurrency:  2,
		DailyScanLimit:           20,
		DailyRuntimeLimitMinutes: 120,
		DailyProbeLimit:          1000,
		MinExpectedROIUSD:        50,
	})
	if err != nil {
		t.Fatalf("expected valid autonomous pack, got %v", err)
	}
}

func TestValidatePolicyPackBudgets_AutonomousRequiresDailyScanLimit(t *testing.T) {
	err := validatePolicyPackBudgets(model.AutomationPolicyPack{
		AutomationMode:           "autonomous",
		MaxExploitAttempts:       1,
		MaxAutomationConcurrency: 1,
		MaxPerTargetConcurrency:  1,
		// DailyScanLimit deliberately omitted (0) — must be set.
		DailyRuntimeLimitMinutes: 60,
		DailyProbeLimit:          500,
	})
	if err == nil || !strings.Contains(err.Error(), "dailyScanLimit") {
		t.Fatalf("expected dailyScanLimit must-be-set error, got %v", err)
	}
}

func TestPolicyProfileDefaultsEndpoint(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/automation/policy-profile-defaults", nil)
	srv.handlePolicyProfileDefaults(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, mode := range []string{"safe", "autonomous", "aggressive", "canary"} {
		if !strings.Contains(body, mode) {
			t.Fatalf("expected %s mode in defaults response, got %s", mode, body)
		}
	}
}

func TestEvaluatePolicyGate_BlocksUncorroboratedHigh(t *testing.T) {
	s := &Server{gateHighBlock: 5, gateMedBlock: 5}
	result := s.evaluatePolicyGate([]model.Finding{
		{Title: "Maybe XSS", Category: "input-validation", Severity: model.SeverityHigh, Sources: []string{"scanner"}},
	}, "internal")
	if result.Status != "blocked" {
		t.Fatalf("expected uncorroborated high finding to block, got %s", result.Status)
	}
	if len(result.UncorroboratedHighFindings) != 1 {
		t.Fatalf("expected one uncorroborated high entry, got %+v", result.UncorroboratedHighFindings)
	}
}

func TestEvaluatePolicyGate_AllowsCorroboratedHigh(t *testing.T) {
	s := &Server{gateHighBlock: 5, gateMedBlock: 5}
	result := s.evaluatePolicyGate([]model.Finding{
		{
			Title:    "Confirmed SQLi",
			Severity: model.SeverityHigh,
			Sources:  []string{"scanner", "burp"},
		},
	}, "internal")
	if result.Status != "pass" {
		t.Fatalf("expected multi-source corroborated high to pass, got %s reason=%s", result.Status, result.Reason)
	}
}

func TestEvaluatePolicyGate_AllowsHighWithVerifiedExploitability(t *testing.T) {
	s := &Server{gateHighBlock: 5, gateMedBlock: 5}
	result := s.evaluatePolicyGate([]model.Finding{
		{
			Title:          "Reachable SSRF",
			Severity:       model.SeverityHigh,
			Sources:        []string{"scanner"},
			Exploitability: &model.Exploitability{VerifiedStatus: "verified"},
		},
	}, "internal")
	if result.Status != "pass" {
		t.Fatalf("expected verified-exploitability high to pass, got %s reason=%s", result.Status, result.Reason)
	}
}

func TestIsAllowedFindingTransition(t *testing.T) {
	cases := []struct {
		from, to string
		ok       bool
	}{
		{"", "verified", true},
		{"new", "verified", true},
		{"new", "rejected", true},
		{"new", "remediated", false},
		{"verified", "accepted", true},
		{"verified", "remediated", true},
		{"accepted", "remediated", true},
		{"accepted", "verified", false},
		{"remediated", "verified", true},
		{"suppressed", "accepted", false},
		{"confirmed", "accepted", true}, // legacy alias
	}
	for _, c := range cases {
		if got := isAllowedFindingTransition(c.from, c.to); got != c.ok {
			t.Errorf("isAllowedFindingTransition(%q,%q) = %v, want %v", c.from, c.to, got, c.ok)
		}
	}
}

func TestApplyStrictReportingFilter_FiltersLowConfidence(t *testing.T) {
	job := &model.ScanJob{
		Options: model.ScanOptions{StrictReporting: true, MinReportConfidence: 0.8},
		Findings: []model.Finding{
			{ID: "1", Confidence: 0.9, Severity: model.SeverityMedium, Title: "kept"},
			{ID: "2", Confidence: 0.4, Severity: model.SeverityMedium, Title: "dropped"},
			// exploitability "verified" is no longer exempt from strict reporting:
			// a verified finding with 0.2 confidence must still be suppressed when
			// MinReportConfidence is 0.8 (Fix 3 — exploit-verified bypass removed).
			{ID: "3", Confidence: 0.2, Severity: model.SeverityHigh, Title: "verified-dropped",
				Exploitability: &model.Exploitability{VerifiedStatus: "verified"}},
			{ID: "4", Confidence: 0.0, Severity: model.SeverityInfo, Title: "ops-kept", Category: "operations"},
		},
	}
	filtered, suppressed, threshold, applied := applyStrictReportingFilter(job, nil)
	if !applied || filtered == nil {
		t.Fatal("expected strict filter to apply")
	}
	if suppressed != 2 {
		t.Fatalf("expected 2 suppressed (dropped + verified-dropped), got %d", suppressed)
	}
	if threshold != 0.8 {
		t.Fatalf("expected threshold 0.8, got %f", threshold)
	}
	if len(filtered.Findings) != 2 {
		t.Fatalf("expected 2 findings to remain (kept + ops-kept), got %d", len(filtered.Findings))
	}
}

func TestApplyStrictReportingFilter_QueryOverrideEnables(t *testing.T) {
	job := &model.ScanJob{
		Options: model.ScanOptions{},
		Findings: []model.Finding{
			{ID: "1", Confidence: 0.9, Severity: model.SeverityMedium},
			{ID: "2", Confidence: 0.3, Severity: model.SeverityMedium},
		},
	}
	req := httptest.NewRequest("GET", "/api/report/abc?strict=true&minConfidence=0.6", nil).
		WithContext(context.Background())
	filtered, suppressed, threshold, applied := applyStrictReportingFilter(job, req)
	if !applied {
		t.Fatal("expected strict filter to be applied via query string")
	}
	if suppressed != 1 || len(filtered.Findings) != 1 {
		t.Fatalf("expected 1 suppressed and 1 kept, got suppressed=%d kept=%d", suppressed, len(filtered.Findings))
	}
	if threshold != 0.6 {
		t.Fatalf("expected threshold 0.6, got %f", threshold)
	}
}

func TestFindingHasHighSeverityCorroboration(t *testing.T) {
	if !findingHasHighSeverityCorroboration(model.Finding{Category: "governance"}) {
		t.Fatal("governance findings must be exempt from corroboration gate")
	}
	if !findingHasHighSeverityCorroboration(model.Finding{Sources: []string{"scanner", "burp"}}) {
		t.Fatal("two-source finding must be corroborated")
	}
	if findingHasHighSeverityCorroboration(model.Finding{Sources: []string{"scanner"}}) {
		t.Fatal("single-source finding without exploitability must not be corroborated")
	}
	if !findingHasHighSeverityCorroboration(model.Finding{Exploitability: &model.Exploitability{Reachable: true}}) {
		t.Fatal("reachable exploitability must satisfy corroboration")
	}
}
