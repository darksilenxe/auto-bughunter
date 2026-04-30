package agent

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
)

type fakeAIToolCaller struct {
	decisions []*ai.ToolCallDecision
	generated *ai.GeneratedToolSpec
	planned   int
}

func (f *fakeAIToolCaller) PlanToolCall(_ context.Context, _ ai.ToolCallRequest) *ai.ToolCallDecision {
	if f.planned >= len(f.decisions) {
		return &ai.ToolCallDecision{Action: "stop", StopReason: "no more scripted decisions"}
	}
	decision := f.decisions[f.planned]
	f.planned++
	return decision
}

func (f *fakeAIToolCaller) AdaptTechniqueCommands(_ context.Context, _ []string, _ string, _ string, _ string) []ai.AdaptedCommand {
	return nil
}

func (f *fakeAIToolCaller) GenerateTool(_ context.Context, _ string, _ string, _ []string) *ai.GeneratedToolSpec {
	return f.generated
}

func TestAIToolCallingAgent_SkipsWhenNotOptedIn(t *testing.T) {
	agent := NewAIToolCallingAgent(&fakeAIToolCaller{}, true)
	out, err := agent.Run(context.Background(), AgentInput{
		Target:  "http://example.com",
		Options: model.ScanOptions{},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if out.DebugNotes == "" || out.DebugNotes != "AI tool-calling disabled for this scan" {
		t.Fatalf("unexpected debug notes: %q", out.DebugNotes)
	}
}

func TestAIToolCallingAgent_RejectsUnsafeCommand(t *testing.T) {
	agent := NewAIToolCallingAgent(&fakeAIToolCaller{
		decisions: []*ai.ToolCallDecision{
			{Action: "run_command", Binary: "bash", Args: []string{"-c", "id"}, Rationale: "unsafe"},
			{Action: "stop", StopReason: "done"},
		},
	}, true)

	out, err := agent.Run(context.Background(), AgentInput{
		Target: "http://example.com",
		Options: model.ScanOptions{
			UseAIToolCalling: true,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := out.Metadata["validation_failures"]; got != "1" {
		t.Fatalf("validation_failures = %q, want 1", got)
	}
	if len(out.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(out.Findings))
	}
}

func TestAIToolCallingAgent_GeneratedToolProducesFinding(t *testing.T) {
	agent := NewAIToolCallingAgent(&fakeAIToolCaller{
		decisions: []*ai.ToolCallDecision{
			{Action: "generate_tool", Task: "verify reflected impact", Rationale: "impact-first probe"},
			{Action: "stop", StopReason: "enough evidence"},
		},
		generated: &ai.GeneratedToolSpec{
			Name:      "impact_probe",
			Code:      "#!/usr/bin/env python3\nimport json\nprint(json.dumps({\"id\":\"1\",\"category\":\"impact\",\"severity\":\"high\",\"title\":\"Impact confirmed\",\"description\":\"Confirmed business impact\",\"evidence\":\"impact evidence\",\"recommendation\":\"fix it\"}))\n",
			Rationale: "confirm impact",
		},
	}, true)

	out, err := agent.Run(context.Background(), AgentInput{
		Target: "http://example.com",
		Options: model.ScanOptions{
			UseAIToolCalling: true,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	if out.Findings[0].Title != "Impact confirmed" {
		t.Fatalf("unexpected finding title: %q", out.Findings[0].Title)
	}
	if got := out.Metadata["generated_tool_actions"]; got != "1" {
		t.Fatalf("generated_tool_actions = %q, want 1", got)
	}
}
