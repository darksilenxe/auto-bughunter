package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type captureDecisionProvider struct {
	lastMessages []Message
	response     string
}

func (p *captureDecisionProvider) Complete(ctx context.Context, model string, messages []Message, temperature float64, jsonMode bool) (string, error) {
	_ = ctx
	_ = model
	_ = temperature
	_ = jsonMode
	p.lastMessages = append([]Message(nil), messages...)
	return p.response, nil
}

func TestBuildAttackPathSignals_RanksHintedTransitions(t *testing.T) {
	findings := []model.Finding{
		{
			Category:    "xss",
			AffectedURL: "https://app.test/profile",
			Exploitability: &model.Exploitability{
				AttackPathHints: []string{"auth-bypass-checks"},
			},
		},
	}
	history := []model.ProbeResult{
		{Category: "xss", Endpoint: "https://app.test/profile", Outcome: model.ProbeConfirmed, Confirmed: true},
	}
	signals := buildAttackPathSignals(findings, history, []string{"https://app.test/profile"})
	if len(signals) == 0 {
		t.Fatal("expected ranked attack-path signals")
	}
	if signals[0].Category != "auth_bypass" {
		t.Fatalf("top category = %q, want auth_bypass; signals=%+v", signals[0].Category, signals)
	}
	if signals[0].Endpoint != "https://app.test/profile" {
		t.Fatalf("top endpoint = %q, want profile endpoint", signals[0].Endpoint)
	}
}

func TestDecideNextProbe_IncludesAttackPathSignalsInPayload(t *testing.T) {
	prov := &captureDecisionProvider{
		response: `{"action":"probe","category":"auth_bypass","endpoint":"https://app.test/profile","rationale":"follow chain signal"}`,
	}
	c := &Client{
		BaseURL:  "http://provider.test/v1",
		Model:    "test-model",
		provider: prov,
	}
	findings := []model.Finding{
		{
			Category:    "xss",
			AffectedURL: "https://app.test/profile",
			Exploitability: &model.Exploitability{
				AttackPathHints: []string{"auth-bypass-checks"},
			},
		},
	}
	_ = c.DecideNextProbe(
		context.Background(),
		"https://app.test",
		findings,
		nil,
		[]string{"https://app.test/profile"},
		3,
		nil,
		true,
	)
	if len(prov.lastMessages) < 2 {
		t.Fatalf("expected provider to receive system+user messages, got %d", len(prov.lastMessages))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(prov.lastMessages[1].Content), &payload); err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	if _, ok := payload["attackPathSignals"]; !ok {
		t.Fatalf("expected attackPathSignals in payload, got: %+v", payload)
	}
	instructions, _ := payload["instructions"].(string)
	if instructions == "" || !strings.Contains(instructions, "ATTACK-PATH PRIORITY") {
		t.Fatalf("expected attack-path instruction block, got: %q", instructions)
	}
}

func TestLocalProbeDecision_PrioritizesAttackPathSignalWhenEnabled(t *testing.T) {
	findings := []model.Finding{
		{
			Category:    "xss",
			AffectedURL: "https://app.test/profile",
			Exploitability: &model.Exploitability{
				AttackPathHints: []string{"auth-bypass-checks"},
			},
		},
	}
	endpoints := []string{"https://app.test/profile"}
	signals := buildAttackPathSignals(findings, nil, endpoints)

	decision := localProbeDecision(
		"https://app.test",
		findings,
		nil,
		endpoints,
		5,
		nil,
		true,
		signals,
	)
	if decision.Category != "auth_bypass" {
		t.Fatalf("category = %q, want auth_bypass", decision.Category)
	}
	if !decision.AttackPathInfluenced {
		t.Fatal("expected decision to be marked attack-path influenced")
	}

	fallback := localProbeDecision(
		"https://app.test",
		findings,
		nil,
		endpoints,
		5,
		nil,
		false,
		signals,
	)
	if fallback.Category != "xss" {
		t.Fatalf("fallback category = %q, want xss", fallback.Category)
	}
}
