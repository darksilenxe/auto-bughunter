package scanner

import (
	"context"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func TestCandidateLoginURLsPrefersConfiguredLoginURL(t *testing.T) {
	scanScope := scope.Normalize("https://example.com/app", model.ScanScope{IncludeHosts: []string{"example.com"}})
	profile := model.ScanAuthProfile{LoginURL: "/custom-login"}

	got := candidateLoginURLs("https://example.com/app", profile, scanScope)
	if len(got) == 0 {
		t.Fatal("expected candidate login URLs")
	}
	if got[0] != "https://example.com/custom-login" {
		t.Fatalf("expected configured login URL first, got %q", got[0])
	}
}

func TestBootstrapStandardAuthProfileRejectsIncompleteCredentials(t *testing.T) {
	profile := model.ScanAuthProfile{Username: "alice"}

	_, findings := bootstrapStandardAuthProfile(context.Background(), "https://example.com", profile, scope.Normalize("https://example.com", model.ScanScope{}), nil)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Title), "incomplete") {
		t.Fatalf("expected incomplete credentials finding, got %q", findings[0].Title)
	}
}
