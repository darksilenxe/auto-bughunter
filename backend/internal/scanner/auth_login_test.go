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

func TestResolveLoginStepValueReplacesCredentialPlaceholders(t *testing.T) {
	got := resolveLoginStepValue("user={{username}}&pass={{password}}", "alice@example.com", "s3cr3t")
	if got != "user=alice@example.com&pass=s3cr3t" {
		t.Fatalf("unexpected resolved value: %q", got)
	}
}

func TestLoginBootstrapInitialDelayUsesDefaultForLegacyFlow(t *testing.T) {
	delay := loginBootstrapInitialDelay(model.ScanAuthProfile{})
	if delay != loginBootstrapLoadDelay {
		t.Fatalf("expected default load delay %s, got %s", loginBootstrapLoadDelay, delay)
	}
}

func TestLoginBootstrapInitialDelaySkipsWarmupForCustomSteps(t *testing.T) {
	delay := loginBootstrapInitialDelay(model.ScanAuthProfile{
		LoginSteps: []model.ScanAuthLoginStep{{Action: "click", Selector: "#accept-cookies"}},
	})
	if delay != loginBootstrapNoDelay {
		t.Fatalf("expected no initial delay for custom login steps, got %s", delay)
	}
}
