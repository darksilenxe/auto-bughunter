package agent

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestOpenHackExpertAgentNoFindings(t *testing.T) {
	a := NewOpenHackExpertAgent(nil, nil, true)
	out, err := a.Run(context.Background(), AgentInput{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != "completed" {
		t.Errorf("status=%q want completed", out.Status)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(out.Findings))
	}
	if out.Metadata["findings_count"] != "0" {
		t.Errorf("findings_count metadata=%q", out.Metadata["findings_count"])
	}
}

func TestOpenHackExpertAgentLocalFallbackEnriches(t *testing.T) {
	a := NewOpenHackExpertAgent(nil, nil, true)
	input := AgentInput{
		AllFindings: []model.Finding{{
			ID:       "f1",
			Category: "injection",
			Title:    "SQL injection in id parameter",
			Evidence: "param=id payload=' OR 1=1--",
			Severity: model.SeverityHigh,
			CWE:      "CWE-89",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding back, got %d", len(out.Findings))
	}
	f := out.Findings[0]
	if got := f.EvidenceFields["openhackExpert"]; got != "injection" {
		t.Errorf("expected openhackExpert=injection, got %q", got)
	}
	if f.EvidenceFields["openhackFallback"] == "" {
		t.Error("expected openhackFallback marker in local fallback path")
	}
	if f.EvidenceFields["openhackQualityGate"] == "" {
		t.Error("expected openhackQualityGate reminder in local fallback path")
	}
	if out.Metadata["openhack_llm_calls"] != "0" {
		t.Errorf("expected zero LLM calls in fallback, got %q", out.Metadata["openhack_llm_calls"])
	}
	if out.Metadata["openhack_local_fallbacks"] != "1" {
		t.Errorf("expected 1 local fallback, got %q", out.Metadata["openhack_local_fallbacks"])
	}
}

func TestOpenHackTriageAgentLocalFallbackAccepts(t *testing.T) {
	a := NewOpenHackTriageAgent(nil, nil, true)
	input := AgentInput{
		AllFindings: []model.Finding{{
			ID:       "f1",
			Category: "access_control",
			Title:    "IDOR on profile",
			Severity: model.SeverityMedium,
			CWE:      "CWE-639",
		}},
	}
	out, err := a.Run(context.Background(), input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding kept in fallback, got %d", len(out.Findings))
	}
	if got := out.Findings[0].EvidenceFields["openhackTriageDecision"]; got != "accepted_local" {
		t.Errorf("expected accepted_local triage decision, got %q", got)
	}
	if out.Metadata["openhack_triage_accepted"] != "1" {
		t.Errorf("expected 1 accepted, got %q", out.Metadata["openhack_triage_accepted"])
	}
}

func TestOpenHackAgentsRegisteredInFactory(t *testing.T) {
	f := NewFactory(nil, nil)
	for _, name := range []string{"openhack_expert", "openhack_triage"} {
		a, err := f.Create(name)
		if err != nil {
			t.Errorf("factory missing %q: %v", name, err)
			continue
		}
		if a == nil || a.Name() != name {
			t.Errorf("factory produced wrong agent for %q", name)
		}
	}
}
