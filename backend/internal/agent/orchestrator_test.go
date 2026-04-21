package agent

import (
	"context"
	"errors"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type fixedAgent struct {
	name     string
	enabled  bool
	findings []model.Finding
	err      error
}

func (a *fixedAgent) Name() string  { return a.name }
func (a *fixedAgent) Enabled() bool { return a.enabled }
func (a *fixedAgent) Run(_ context.Context, _ AgentInput) (AgentOutput, error) {
	if a.err != nil {
		return AgentOutput{AgentName: a.name}, a.err
	}
	return AgentOutput{AgentName: a.name, Findings: append([]model.Finding(nil), a.findings...)}, nil
}

func newTestFactory(agents map[string]Agent) *Factory {
	f := &Factory{builders: map[string]AgentBuilder{}}
	for name, ag := range agents {
		ag := ag
		f.Register(name, func() Agent { return ag })
	}
	return f
}

func TestStaticPlannerWalksOrder(t *testing.T) {
	p := NewStaticPlanner([]string{"a", "b", "c"})

	dec, err := p.Plan(context.Background(), AgentInput{}, nil)
	if err != nil || dec.IsDone || len(dec.Agents) != 1 || dec.Agents[0].Name != "a" {
		t.Fatalf("expected first agent a, got %+v err=%v", dec, err)
	}

	dec, _ = p.Plan(context.Background(), AgentInput{}, []AgentOutput{{AgentName: "a"}, {AgentName: "b"}})
	if dec.IsDone || len(dec.Agents) != 1 || dec.Agents[0].Name != "c" {
		t.Fatalf("expected agent c, got %+v", dec)
	}

	dec, _ = p.Plan(context.Background(), AgentInput{}, []AgentOutput{{AgentName: "a"}, {AgentName: "b"}, {AgentName: "c"}})
	if !dec.IsDone {
		t.Fatalf("expected done, got %+v", dec)
	}
}

func TestOrchestratorRunsAgentsAndStops(t *testing.T) {
	finding := model.Finding{ID: "f1", Category: "x", Severity: model.SeverityLow, Title: "t", Evidence: "e"}
	factory := newTestFactory(map[string]Agent{
		"a": &fixedAgent{name: "a", enabled: true, findings: []model.Finding{finding}},
		"b": &fixedAgent{name: "b", enabled: true},
	})
	planner := NewStaticPlanner([]string{"a", "b"})
	orch := NewOrchestrator(planner, factory, 5)

	outputs, findings, err := orch.Run(context.Background(), AgentInput{Target: "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(outputs) != 2 || outputs[0].AgentName != "a" || outputs[1].AgentName != "b" {
		t.Fatalf("unexpected outputs: %+v", outputs)
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestOrchestratorMissingAgentRecordsError(t *testing.T) {
	factory := newTestFactory(map[string]Agent{
		"known": &fixedAgent{name: "known", enabled: true},
	})
	plans := []PlannerDecision{
		{Agents: []AgentSpec{{Name: "missing", Reason: "test"}, {Name: "known"}}},
		{IsDone: true},
	}
	planner := &scriptedPlanner{decisions: plans}
	orch := NewOrchestrator(planner, factory, 5)

	outputs, _, err := orch.Run(context.Background(), AgentInput{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(outputs))
	}
	if outputs[0].Status != "error" || outputs[0].Error == "" {
		t.Fatalf("expected first output to be error, got %+v", outputs[0])
	}
	if outputs[1].AgentName != "known" || outputs[1].Status != "completed" {
		t.Fatalf("expected second output completed for known, got %+v", outputs[1])
	}
}

type scriptedPlanner struct {
	decisions []PlannerDecision
	idx       int
}

func (s *scriptedPlanner) Plan(_ context.Context, _ AgentInput, _ []AgentOutput) (PlannerDecision, error) {
	if s.idx >= len(s.decisions) {
		return PlannerDecision{IsDone: true}, nil
	}
	d := s.decisions[s.idx]
	s.idx++
	return d, nil
}

type errPlanner struct{ err error }

func (e *errPlanner) Plan(_ context.Context, _ AgentInput, _ []AgentOutput) (PlannerDecision, error) {
	return PlannerDecision{}, e.err
}

func TestOrchestratorPlannerError(t *testing.T) {
	factory := newTestFactory(map[string]Agent{})
	orch := NewOrchestrator(&errPlanner{err: errors.New("boom")}, factory, 5)
	if _, _, err := orch.Run(context.Background(), AgentInput{}); err == nil {
		t.Fatalf("expected planner error to propagate")
	}
}

type fakeCaller struct {
	specs []map[string]string
	done  bool
	err   error
}

func (f *fakeCaller) Plan(_ context.Context, _ string, _ []any, _ []map[string]string, _ []string) ([]map[string]string, bool, error) {
	return f.specs, f.done, f.err
}

func TestAIPlannerFiltersUnknownAgents(t *testing.T) {
	caller := &fakeCaller{specs: []map[string]string{{"name": "known", "reason": "r"}, {"name": "ghost"}}}
	fb := NewStaticPlanner([]string{"known"})
	p := NewAIPlanner(caller, []string{"known"}, fb)

	dec, err := p.Plan(context.Background(), AgentInput{}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(dec.Agents) != 1 || dec.Agents[0].Name != "known" {
		t.Fatalf("expected only known agent, got %+v", dec.Agents)
	}
}

func TestAIPlannerFallsBackOnError(t *testing.T) {
	caller := &fakeCaller{err: errors.New("oops")}
	fb := NewStaticPlanner([]string{"a"})
	p := NewAIPlanner(caller, []string{"a"}, fb)

	dec, err := p.Plan(context.Background(), AgentInput{}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(dec.Agents) != 1 || dec.Agents[0].Name != "a" {
		t.Fatalf("expected fallback to schedule a, got %+v", dec)
	}
}

func TestAIPlannerEmptyAgentsTriggersFallback(t *testing.T) {
	caller := &fakeCaller{specs: nil, done: false}
	fb := NewStaticPlanner([]string{"a"})
	p := NewAIPlanner(caller, []string{"a"}, fb)

	dec, err := p.Plan(context.Background(), AgentInput{}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(dec.Agents) != 1 || dec.Agents[0].Name != "a" {
		t.Fatalf("expected fallback agent, got %+v", dec)
	}
}

func TestAIPlannerBlocksSuppressedAgentsFromMemory(t *testing.T) {
	caller := &fakeCaller{specs: []map[string]string{{"name": "known", "reason": "low signal retry"}}, done: false}
	fb := NewStaticPlanner([]string{"other"})
	p := NewAIPlanner(caller, []string{"known", "other"}, fb)

	dec, err := p.Plan(context.Background(), AgentInput{
		AutonomyMemory: model.AutonomyMemory{SuppressedAgents: []string{"known"}},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(dec.Agents) != 1 || dec.Agents[0].Name != "other" {
		t.Fatalf("expected fallback to non-suppressed other agent, got %+v", dec)
	}
}

func TestOrchestratorStopsAfterConsecutiveNoNoveltyRounds(t *testing.T) {
	factory := newTestFactory(map[string]Agent{
		"a": &fixedAgent{name: "a", enabled: true, findings: nil},
	})
	plans := []PlannerDecision{
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
	}
	orch := NewOrchestrator(&scriptedPlanner{decisions: plans}, factory, 10)

	outputs, findings, err := orch.Run(context.Background(), AgentInput{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected early convergence stop after 2 rounds, got %d outputs", len(outputs))
	}
}

func TestOrchestratorStopsAfterConsecutiveFailureRounds(t *testing.T) {
	factory := newTestFactory(map[string]Agent{
		"a": &fixedAgent{name: "a", enabled: true, err: errors.New("timeout: deadline exceeded")},
	})
	plans := []PlannerDecision{
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
	}
	orch := NewOrchestrator(&scriptedPlanner{decisions: plans}, factory, 10)

	outputs, _, err := orch.Run(context.Background(), AgentInput{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected early stop after repeated failure rounds, got %d outputs", len(outputs))
	}
	if !outputs[0].TimedOut || !outputs[1].TimedOut {
		t.Fatalf("expected timeout classification for failure bumps, got %+v", outputs)
	}
}

func TestFactoryCreateUnknown(t *testing.T) {
	f := NewFactory(nil, nil)
	if _, err := f.Create("does_not_exist"); err == nil {
		t.Fatalf("expected error for unknown agent")
	}
	if _, err := f.Create("reconnaissance"); err != nil {
		t.Fatalf("expected reconnaissance to be creatable, got %v", err)
	}
}

func TestRegistryFactoryFallback(t *testing.T) {
	r := NewRegistry()
	r.RegisterFactory(NewFactory(nil, nil))
	if a := r.Get("reconnaissance"); a == nil {
		t.Fatalf("expected factory fallback to provide reconnaissance agent")
	}
	if a := r.Get("not_a_real_agent"); a != nil {
		t.Fatalf("expected nil for unknown agent")
	}
}
