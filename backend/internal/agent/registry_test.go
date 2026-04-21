package agent

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestOrchestrateGlobalAdaptiveRules(t *testing.T) {
	r := NewRegistry()
	findings := []model.Finding{
		{Category: "access_control", Severity: model.SeverityHigh, Title: "Authentication bypass risk"},
		{Category: "ssrf", Severity: model.SeverityMedium, Title: "SSRF vector", Evidence: "param=fetch"},
		{Category: "remote_code_execution", Severity: model.SeverityMedium, Title: "RCE indicator"},
	}

	spawned := r.orchestrate(context.Background(), "wordlist", AgentOutput{}, findings)
	for _, expected := range []string{"attack_path", "auth_bypass", "ssrf", "metasploit"} {
		if !containsAgentName(spawned, expected) {
			t.Fatalf("expected %q to be spawned, got %v", expected, spawned)
		}
	}
}

func TestOrchestrateDeduplicatesSpawnedAgents(t *testing.T) {
	r := NewRegistry()
	findings := []model.Finding{
		{Category: "ssrf", Severity: model.SeverityHigh, Title: "Server-side request forgery"},
	}

	spawned := r.orchestrate(context.Background(), "api_security", AgentOutput{}, findings)
	ssrfCount := 0
	for _, item := range spawned {
		if item == "ssrf" {
			ssrfCount++
		}
	}
	if ssrfCount != 1 {
		t.Fatalf("expected deduplicated ssrf spawn exactly once, got %d in %v", ssrfCount, spawned)
	}
}

func containsAgentName(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
