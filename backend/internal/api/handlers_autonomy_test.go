package api

import (
	"testing"
	"time"

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

	merged := mergeAutonomyMemory(initial, outputs, 30, nil)

	if len(merged.PreferredAgents) == 0 || merged.PreferredAgents[0] != "good" {
		t.Fatalf("expected good to be preferred, got %v", merged.PreferredAgents)
	}
	if len(merged.SuppressedAgents) == 0 || merged.SuppressedAgents[0] != "bad" {
		t.Fatalf("expected bad to be suppressed, got %v", merged.SuppressedAgents)
	}
}

func TestMergeAutonomyMemoryAppliesOperatorFeedback(t *testing.T) {
	initial := model.AutonomyMemory{
		AgentStats: map[string]model.AutonomyAgentStat{
			"agent-a": {Runs: 4, Findings: 2},
		},
	}
	merged := mergeAutonomyMemory(initial, nil, 30, []model.ReportFeedback{
		{Category: "autonomy-action", Outcome: "accepted", Notes: "decision=approve;agent=agent-a;actionId=1"},
		{Category: "autonomy-action", Outcome: "rejected", Notes: "decision=reject;agent=agent-a;actionId=2"},
	})
	stat := merged.AgentStats["agent-a"]
	if stat.OperatorApprovals != 1 {
		t.Fatalf("expected 1 approval, got %d", stat.OperatorApprovals)
	}
	if stat.OperatorRejections != 1 {
		t.Fatalf("expected 1 rejection, got %d", stat.OperatorRejections)
	}
}

func TestMergeAutonomyMemoryIgnoresUnknownAgentFeedback(t *testing.T) {
	initial := model.AutonomyMemory{
		AgentStats: map[string]model.AutonomyAgentStat{
			"agent-a": {Runs: 2},
		},
	}
	merged := mergeAutonomyMemory(initial, nil, 30, []model.ReportFeedback{
		{Category: "autonomy-action", Outcome: "accepted", Notes: "agent=non-existent"},
	})
	if _, ok := merged.AgentStats["non-existent"]; ok {
		t.Fatal("expected unknown agent feedback to be ignored")
	}
}

func TestFilterRecentMemoryFeedbackHonorsRetentionWindow(t *testing.T) {
	now := time.Now().UTC()
	items := []model.ReportFeedback{
		{FindingID: "recent", CreatedAt: now.Add(-24 * time.Hour)},
		{FindingID: "stale", CreatedAt: now.Add(-40 * 24 * time.Hour)},
	}
	out := filterRecentMemoryFeedback(items, 30)
	if len(out) != 1 || out[0].FindingID != "recent" {
		t.Fatalf("expected only recent feedback to remain, got %+v", out)
	}
}
