package agent

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestOrchestratorEmitsLifecycleEvents(t *testing.T) {
	finding := model.Finding{ID: "f1", Category: "x", Severity: model.SeverityLow, Title: "t", Evidence: "e"}
	factory := newTestFactory(map[string]Agent{
		"a": &fixedAgent{name: "a", enabled: true, findings: []model.Finding{finding}},
		"b": &fixedAgent{name: "b", enabled: true},
	})
	planner := NewStaticPlanner([]string{"a", "b"})
	orch := NewOrchestrator(planner, factory, 5)

	var events []model.ScanEvent
	_, _, err := orch.Run(context.Background(), AgentInput{
		Target: "https://example.com",
		Emit: func(evt model.ScanEvent) {
			events = append(events, evt)
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	got := make([]string, 0, len(events))
	for _, evt := range events {
		got = append(got, string(evt.Type)+":"+evt.AgentName)
	}
	want := []string{
		"agent_start:a",
		"finding:a",
		"agent_complete:a",
		"agent_start:b",
		"agent_complete:b",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d events, got %d (%v)", len(want), len(got), got)
	}
	for i, expected := range want {
		if got[i] != expected {
			t.Fatalf("event %d mismatch: got %q want %q; all=%v", i, got[i], expected, got)
		}
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

func (f *fakeCaller) Plan(_ context.Context, _ string, _ []any, _ []map[string]string, _ []string, _ []model.ImpactGoal, _ string) ([]map[string]string, bool, error) {
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

func TestAIPlannerInjectsExplorationAgent(t *testing.T) {
	caller := &fakeCaller{specs: []map[string]string{{"name": "known", "reason": "known-path"}}, done: false}
	fb := NewStaticPlanner([]string{"known", "explore"})
	p := NewAIPlanner(caller, []string{"known", "explore"}, fb)
	p.ExplorationBudget = 100

	dec, err := p.Plan(context.Background(), AgentInput{}, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(dec.Agents) < 2 {
		t.Fatalf("expected exploration agent to be injected, got %+v", dec.Agents)
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

func TestOrchestratorStopsAfterLowMarginalScoreRounds(t *testing.T) {
	factory := newTestFactory(map[string]Agent{
		"a": &fixedAgent{name: "a", enabled: true, findings: nil},
	})
	plans := []PlannerDecision{
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
		{Agents: []AgentSpec{{Name: "a"}}},
	}
	orch := NewOrchestrator(&scriptedPlanner{decisions: plans}, factory, 10)
	orch.MaxNoNoveltyRounds = 10
	orch.MinMarginalScore = 0.25

	outputs, _, err := orch.Run(context.Background(), AgentInput{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(outputs) != 2 {
		t.Fatalf("expected early stop after low marginal rounds, got %d outputs", len(outputs))
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

// blockingAgent ignores ctx and blocks until unblock is closed, simulating an
// agent stuck on a slow external/AI call.
type blockingAgent struct {
	name    string
	unblock chan struct{}
	started chan struct{}
}

func (a *blockingAgent) Name() string  { return a.name }
func (a *blockingAgent) Enabled() bool { return true }
func (a *blockingAgent) Run(_ context.Context, _ AgentInput) (AgentOutput, error) {
	if a.started != nil {
		close(a.started)
	}
	<-a.unblock
	return AgentOutput{AgentName: a.name}, nil
}

func TestOrchestratorHonoursContextWhenAgentBlocks(t *testing.T) {
	unblock := make(chan struct{})
	started := make(chan struct{})
	defer close(unblock)
	factory := newTestFactory(map[string]Agent{
		"stuck": &blockingAgent{name: "stuck", unblock: unblock, started: started},
	})
	planner := NewStaticPlanner([]string{"stuck"})
	orch := NewOrchestrator(planner, factory, 3)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var outputs []AgentOutput
	var err error
	go func() {
		outputs, _, err = orch.Run(ctx, AgentInput{Target: "https://example.com"})
		close(done)
	}()

	<-started
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("orchestrator did not return after context cancellation while agent was blocked")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(outputs) != 1 || !outputs[0].TimedOut {
		t.Fatalf("expected one timed-out output, got %+v", outputs)
	}
}

// blockingPlanner ignores ctx and blocks in Plan until unblock is closed,
// simulating a planner stuck on a slow/unresponsive dependency (AI provider,
// knowledge retrieval, learner RPC) between agent runs.
type blockingPlanner struct {
	unblock chan struct{}
	started chan struct{}
}

func (p *blockingPlanner) Plan(_ context.Context, _ AgentInput, _ []AgentOutput) (PlannerDecision, error) {
	if p.started != nil {
		close(p.started)
	}
	<-p.unblock
	return PlannerDecision{IsDone: true}, nil
}

func TestOrchestratorHonoursContextWhenPlannerBlocks(t *testing.T) {
	unblock := make(chan struct{})
	started := make(chan struct{})
	defer close(unblock)
	factory := newTestFactory(map[string]Agent{})
	planner := &blockingPlanner{unblock: unblock, started: started}
	orch := NewOrchestrator(planner, factory, 3)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		_, _, err = orch.Run(ctx, AgentInput{Target: "https://example.com"})
		close(done)
	}()

	<-started
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("orchestrator did not return after context cancellation while planner was blocked")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// fakeSpawner is a test double for the Spawner interface.
type fakeSpawner struct {
	recs        []string
	calledWith  []string // source agent names passed to Recommend
}

func (s *fakeSpawner) Recommend(_ context.Context, sourceAgent string, _ []model.Finding, _ int, _ float64) []string {
	s.calledWith = append(s.calledWith, sourceAgent)
	return s.recs
}

// TestAIPlannerMergesQLearnerRecommendations verifies that when a Spawner is
// wired into an AIPlanner, its recommendations are included in the planning
// decision after the first agent completes.
func TestAIPlannerMergesQLearnerRecommendations(t *testing.T) {
	// AI planner returns "known"; the Q-learner recommends "learned".
	caller := &fakeCaller{specs: []map[string]string{{"name": "known", "reason": "ai-planned"}}}
	spawner := &fakeSpawner{recs: []string{"learned"}}
	fb := NewStaticPlanner([]string{"known", "learned"})
	p := NewAIPlanner(caller, []string{"known", "learned"}, fb)
	p.Spawner = spawner
	p.MaxAgentsPerRound = 0 // no cap — accept all candidates

	// history: one agent already ran so the spawner has a source to recommend from.
	history := []AgentOutput{{AgentName: "previous", Status: "completed"}}

	dec, err := p.Plan(context.Background(), AgentInput{}, history)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Both the AI-planned agent and the Q-learning recommendation must appear.
	names := make(map[string]bool, len(dec.Agents))
	for _, a := range dec.Agents {
		names[a.Name] = true
	}
	if !names["known"] {
		t.Errorf("expected AI-planned agent 'known' in decision, got %+v", dec.Agents)
	}
	if !names["learned"] {
		t.Errorf("expected Q-learning recommendation 'learned' in decision, got %+v", dec.Agents)
	}
	// Verify that the spawner was consulted for the last-completed agent.
	if len(spawner.calledWith) == 0 || spawner.calledWith[len(spawner.calledWith)-1] != "previous" {
		t.Errorf("expected spawner called with 'previous', got %v", spawner.calledWith)
	}
	// Verify the Q-learning agent carries the correct reason tag.
	for _, a := range dec.Agents {
		if a.Name == "learned" && a.Reason != "q-learning" {
			t.Errorf("expected reason 'q-learning' for Q-learner recommendation, got %q", a.Reason)
		}
	}
}

// TestAIPlannerQLearnerSkipsUnavailableAgents ensures that Q-learner
// recommendations for unknown (not-in-factory) agents are silently ignored.
func TestAIPlannerQLearnerSkipsUnavailableAgents(t *testing.T) {
	caller := &fakeCaller{specs: []map[string]string{{"name": "known", "reason": "r"}}}
	spawner := &fakeSpawner{recs: []string{"ghost", "known"}} // ghost is not registered
	fb := NewStaticPlanner([]string{"known"})
	p := NewAIPlanner(caller, []string{"known"}, fb)
	p.Spawner = spawner
	p.MaxAgentsPerRound = 0

	history := []AgentOutput{{AgentName: "prev", Status: "completed"}}
	dec, err := p.Plan(context.Background(), AgentInput{}, history)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	for _, a := range dec.Agents {
		if a.Name == "ghost" {
			t.Errorf("unregistered agent 'ghost' must not appear in decision, got %+v", dec.Agents)
		}
	}
}
