package api

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

type staticAgent struct {
	name            string
	findings        []model.Finding
	surfaceSnapshot *model.SurfaceSnapshot
}

func (a staticAgent) Name() string  { return a.name }
func (a staticAgent) Enabled() bool { return true }
func (a staticAgent) Run(_ context.Context, _ agent.AgentInput) (agent.AgentOutput, error) {
	return agent.AgentOutput{
		AgentName:       a.name,
		Findings:        append([]model.Finding(nil), a.findings...),
		SurfaceSnapshot: a.surfaceSnapshot,
		Status:          "completed",
	}, nil
}

func TestRunWithAuthProfilesUsesAgentOutputsForSupplementalState(t *testing.T) {
	reg := agent.NewRegistry()
	reg.Register(staticAgent{
		name: "scanning",
		findings: []model.Finding{{
			ID:       "open-redirect",
			Category: "redirect",
			Title:    "Open redirect",
			Severity: model.SeverityMedium,
		}},
	})
	reg.Register(staticAgent{
		name: "advanced_coverage",
		findings: []model.Finding{{
			ID:       "coverage-extra",
			Category: "coverage",
			Title:    "Extra coverage",
			Severity: model.SeverityInfo,
		}},
		surfaceSnapshot: &model.SurfaceSnapshot{
			EndpointCount: 1,
		},
	})

	s := &Server{agentRegistry: reg}
	state := &model.PersistentScanState{}
	outputs, findings, err := s.runWithAuthProfiles(
		context.Background(),
		"scan-1",
		"https://example.com",
		model.ScanAuthProfile{},
		nil,
		model.ScanOptions{},
		model.ScanScope{},
		state,
		nil,
	)
	if err != nil {
		t.Fatalf("runWithAuthProfiles returned error: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 agent outputs, got %d", len(outputs))
	}
	if len(findings) != 2 {
		t.Fatalf("expected only agent-produced findings, got %d", len(findings))
	}
	for _, finding := range findings {
		if finding.ID == "chain-redirect-oauth-takeover" {
			t.Fatal("expected exploit-chain analysis to come from an agent, not an out-of-band handler pass")
		}
	}
	if state.SurfaceSnapshot == nil {
		t.Fatal("expected persisted surface snapshot to be updated from agent output")
	}
	if state.SurfaceSnapshot.EndpointCount != 1 {
		t.Fatalf("unexpected surface snapshot endpoint count: %d", state.SurfaceSnapshot.EndpointCount)
	}
}
