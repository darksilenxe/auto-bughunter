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

type registryTestAgent struct {
	name     string
	enabled  bool
	findings []model.Finding
}

func (a *registryTestAgent) Name() string  { return a.name }
func (a *registryTestAgent) Enabled() bool { return a.enabled }
func (a *registryTestAgent) Run(context.Context, AgentInput) (AgentOutput, error) {
	return AgentOutput{AgentName: a.name, Findings: append([]model.Finding(nil), a.findings...)}, nil
}

func TestRunAllSpawnsFactoryOnlyAgents(t *testing.T) {
	r := NewRegistry()
	r.Register(&registryTestAgent{
		name:    "scanning",
		enabled: true,
		findings: []model.Finding{
			{Category: "ssrf", Severity: model.SeverityMedium, Title: "SSRF indicator", Evidence: "param=fetch"},
		},
	})
	r.RegisterFactory(newTestFactory(map[string]Agent{
		"ssrf": &registryTestAgent{name: "ssrf", enabled: true},
	}))

	outputs, _, err := r.RunAll(context.Background(), AgentInput{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected scanning + spawned ssrf outputs, got %d", len(outputs))
	}
	if outputs[1].AgentName != "ssrf" {
		t.Fatalf("expected spawned ssrf agent via factory, got %+v", outputs[1])
	}
}
