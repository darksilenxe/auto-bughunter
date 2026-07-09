package agent

import (
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scanner"
)

func TestAssessProbeStateChange_MaterialOnStatusDelta(t *testing.T) {
	msg, material := assessProbeStateChange(
		scanner.BaselineResponse{StatusCode: 200, BodyLength: 1200},
		model.ProbeResult{StatusCode: 302, ResponseBodyLength: 1210},
	)
	if !material {
		t.Fatal("expected material state change")
	}
	if !strings.Contains(msg, "material response delta") {
		t.Fatalf("expected material-state message, got %q", msg)
	}
}

func TestAssessProbeStateChange_MaterialOnBodyDelta(t *testing.T) {
	msg, material := assessProbeStateChange(
		scanner.BaselineResponse{StatusCode: 200, BodyLength: 800},
		model.ProbeResult{StatusCode: 200, ResponseBodyLength: 1100},
	)
	if !material {
		t.Fatal("expected material state change from body delta")
	}
	if !strings.Contains(msg, "delta=300") {
		t.Fatalf("expected delta in message, got %q", msg)
	}
}

func TestAssessProbeStateChange_NoMaterialDelta(t *testing.T) {
	msg, material := assessProbeStateChange(
		scanner.BaselineResponse{StatusCode: 200, BodyLength: 1000},
		model.ProbeResult{StatusCode: 200, ResponseBodyLength: 1040},
	)
	if material {
		t.Fatal("expected non-material state change")
	}
	if !strings.Contains(msg, "no material response delta") {
		t.Fatalf("expected no-material message, got %q", msg)
	}
}

func TestAdaptiveWriteMetadata_IncludesAttackPathCounters(t *testing.T) {
	agent := &AdaptiveProbeAgent{StepBudget: 7}
	out := &AgentOutput{Metadata: map[string]string{}}
	agent.writeMetadata(out, 5, 2, 1, 1, 3, true)

	if got := out.Metadata["adaptive_attack_path_guided"]; got != "3" {
		t.Fatalf("adaptive_attack_path_guided = %q, want 3", got)
	}
	if got := out.Metadata["adaptive_attack_path_enabled"]; got != "true" {
		t.Fatalf("adaptive_attack_path_enabled = %q, want true", got)
	}
	if got := out.Metadata["adaptive_budget"]; got != "7" {
		t.Fatalf("adaptive_budget = %q, want 7", got)
	}
}
