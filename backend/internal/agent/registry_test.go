package agent

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRegistryOrchestrateAppliesGlobalAdaptiveRules(t *testing.T) {
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

func containsAgentName(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
