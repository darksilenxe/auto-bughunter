package api

import (
	"testing"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

func TestMergeAutonomyMemoryUpdatesPreferredAndSuppressed(t *testing.T) {
	initial := model.AutonomyMemory{
		AgentStats: map[string]model.AutonomyAgentStat{
			"bad": {Runs: 2, Errors: 2, Findings: 0},
		},
	}
	outputs := []agent.AgentOutput{
		{
			AgentName:  "good",
			DurationMs: 1000,
			Findings: []model.Finding{
				{Severity: model.SeverityHigh, Confidence: 0.95},
				{Severity: model.SeverityMedium, Confidence: 0.90},
			},
		},
		{
			AgentName: "bad",
			Status:    "error",
			Error:     "failed",
		},
	}

	merged := mergeAutonomyMemory(initial, outputs)

	if len(merged.PreferredAgents) == 0 || merged.PreferredAgents[0] != "good" {
		t.Fatalf("expected good to be preferred, got %v", merged.PreferredAgents)
	}
	if len(merged.SuppressedAgents) == 0 || merged.SuppressedAgents[0] != "bad" {
		t.Fatalf("expected bad to be suppressed, got %v", merged.SuppressedAgents)
	}
}
