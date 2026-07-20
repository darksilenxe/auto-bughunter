package api

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestValidateAuthProfileAllowsUnauthenticatedScan(t *testing.T) {
	if err := validateAuthProfile(model.ScanAuthProfile{}); err != nil {
		t.Fatalf("expected empty auth profile to be allowed, got %v", err)
	}
}

func TestValidateAuthProfileRequiresUsernameAndPasswordTogether(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{Username: "alice"})
	if err == nil {
		t.Fatal("expected error for incomplete standard auth credentials")
	}
	if !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAuthProfileRejectsInvalidLoginStep(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{
		Username: "alice",
		Password: "secret",
		LoginSteps: []model.ScanAuthLoginStep{
			{Action: "fill", Selector: "#email"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid login step")
	}
	if !strings.Contains(err.Error(), "requires value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAuthProfileAllowsCustomLoginSteps(t *testing.T) {
	err := validateAuthProfile(model.ScanAuthProfile{
		Username: "alice",
		Password: "secret",
		LoginSteps: []model.ScanAuthLoginStep{
			{Action: "fill", Selector: "#email", Value: "{{username}}"},
			{Action: "fill", Selector: "#password", Value: "{{password}}"},
			{Action: "click", Selector: "button[type=submit]"},
			{Action: "wait", WaitMillis: 1200},
		},
	})
	if err != nil {
		t.Fatalf("expected login steps to be valid, got %v", err)
	}
}

// TestFilterDismissedFindings_RemovesRejectedFinding verifies that a finding
// previously marked "rejected" is filtered out of subsequent scan results.
func TestFilterDismissedFindings_RemovesRejectedFinding(t *testing.T) {
	findings := []model.Finding{
		{ID: "finding-aaa", Title: "XSS in search"},
		{ID: "finding-bbb", Title: "SQLi in login"},
	}
	verifs := []model.FindingVerification{
		{FindingID: "finding-aaa", Status: "rejected"},
	}

	got, dismissed := filterDismissedFindings(findings, verifs)
	if dismissed != 1 {
		t.Fatalf("expected 1 dismissed finding, got %d", dismissed)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 remaining finding, got %d", len(got))
	}
	if got[0].ID != "finding-bbb" {
		t.Fatalf("expected remaining finding to be finding-bbb, got %q", got[0].ID)
	}
}

// TestFilterDismissedFindings_RemovesSuppressedFinding verifies that a finding
// previously marked "suppressed" is also filtered out of subsequent scan
// results — the same treatment as rejected findings.
func TestFilterDismissedFindings_RemovesSuppressedFinding(t *testing.T) {
	findings := []model.Finding{
		{ID: "finding-aaa", Title: "Open Redirect"},
		{ID: "finding-bbb", Title: "SSRF"},
	}
	verifs := []model.FindingVerification{
		{FindingID: "finding-aaa", Status: "suppressed"},
	}

	got, dismissed := filterDismissedFindings(findings, verifs)
	if dismissed != 1 {
		t.Fatalf("expected 1 dismissed finding, got %d", dismissed)
	}
	if len(got) != 1 || got[0].ID != "finding-bbb" {
		t.Fatalf("unexpected remaining findings: %v", got)
	}
}

// TestFilterDismissedFindings_NoMatchLeaveFindingsIntact verifies that findings
// with no matching dismissal records are returned unchanged.
func TestFilterDismissedFindings_NoMatchLeaveFindingsIntact(t *testing.T) {
	findings := []model.Finding{
		{ID: "finding-aaa"},
		{ID: "finding-bbb"},
	}
	verifs := []model.FindingVerification{
		{FindingID: "finding-ccc", Status: "rejected"},
	}

	got, dismissed := filterDismissedFindings(findings, verifs)
	if dismissed != 0 {
		t.Fatalf("expected 0 dismissed, got %d", dismissed)
	}
	if len(got) != 2 {
		t.Fatalf("expected all findings to remain, got %d", len(got))
	}
}

// TestFilterDismissedFindings_EmptyVerifsIsNoop verifies that passing no
// verifications returns the original slice with no dismissals.
func TestFilterDismissedFindings_EmptyVerifsIsNoop(t *testing.T) {
	findings := []model.Finding{
		{ID: "finding-aaa"},
	}

	got, dismissed := filterDismissedFindings(findings, nil)
	if dismissed != 0 {
		t.Fatalf("expected 0 dismissed, got %d", dismissed)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding to remain, got %d", len(got))
	}
}

