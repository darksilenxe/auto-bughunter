package scanner

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunSMTPInjectionProbe_PassiveOnly(t *testing.T) {
	svc := NewService(Config{})
	got := svc.runSMTPInjectionProbe(context.Background(), RunInput{
		Target:  "https://example.com",
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable probe, got %d findings", len(got))
	}
}

func TestRunSMTPInjectionProbe_SMTPErrorDetected(t *testing.T) {
	// Test detection logic directly using matchSMTPErrors helper.
	cases := []struct {
		body    string
		wantHit bool
	}{
		{"smtp error: cannot send", true},
		{"mail(): Failed to connect to mailserver", true},
		{"phpmailer: could not instantiate", true},
		{"Thank you for contacting us!", false},
		{"", false},
	}
	for _, tc := range cases {
		matched := matchSMTPErrors(tc.body)
		if tc.wantHit && matched == "" {
			t.Errorf("expected SMTP error match for body %q, got none", tc.body)
		}
		if !tc.wantHit && matched != "" {
			t.Errorf("unexpected SMTP error match %q for body %q", matched, tc.body)
		}
	}
}

func TestBuildSMTPFinding(t *testing.T) {
	f := buildSMTPFinding("https://example.com/contact", "email",
		"attacker@example.com\r\nBCC:spy@example.com", "smtp error", "error-based",
		"smtp-injection-email-abc123")
	if f.CWE != "CWE-93" {
		t.Errorf("expected CWE-93, got %s", f.CWE)
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("expected medium severity, got %s", f.Severity)
	}
}

