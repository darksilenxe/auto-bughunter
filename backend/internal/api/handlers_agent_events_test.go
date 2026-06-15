package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

type eventCaptureRepo struct {
	runJobTestRepo
	mu     sync.Mutex
	events map[string][]model.ScanEvent
}

func (r *eventCaptureRepo) SaveAgentEvent(_ context.Context, scanID string, event model.ScanEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.events == nil {
		r.events = map[string][]model.ScanEvent{}
	}
	r.events[scanID] = append(r.events[scanID], event)
	return nil
}

func (r *eventCaptureRepo) ListAgentEvents(_ context.Context, scanID string) ([]model.ScanEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.ScanEvent(nil), r.events[scanID]...), nil
}

type eventProbeAgent struct{}

func (eventProbeAgent) Name() string  { return "event-probe-agent" }
func (eventProbeAgent) Enabled() bool { return true }
func (eventProbeAgent) Run(_ context.Context, input agent.AgentInput) (agent.AgentOutput, error) {
	agent.Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventThinking,
		AgentName: "event-probe-agent",
		Message:   "thinking about next probe",
	})
	agent.Emit(input.Emit, model.ScanEvent{
		Type:      model.ScanEventDiscovery,
		AgentName: "event-probe-agent",
		Message:   "discovered candidate endpoint",
	})
	return agent.AgentOutput{
		AgentName: "event-probe-agent",
		Findings: []model.Finding{
			{ID: "f-1", Title: "Reflected XSS", Severity: model.SeverityHigh},
		},
	}, nil
}

func waitForAgentEvent(t *testing.T, repo *eventCaptureRepo, scanID string, want model.ScanEventType) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := repo.ListAgentEvents(context.Background(), scanID)
		for _, evt := range events {
			if evt.Type == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for persisted %q event", want)
}

func TestShouldPersistAgentEventIncludesThinkingAndDiscovery(t *testing.T) {
	if !shouldPersistAgentEvent(model.ScanEventThinking) {
		t.Fatal("expected thinking events to be persisted")
	}
	if !shouldPersistAgentEvent(model.ScanEventDiscovery) {
		t.Fatal("expected discovery events to be persisted")
	}
	if shouldPersistAgentEvent(model.ScanEventType("custom")) {
		t.Fatal("expected unknown event types to be ignored")
	}
}

func TestRunJobPersistsThinkingAndDiscoveryEvents(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-runjob-events",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "queued",
		StartedAt:   time.Now().UTC(),
	}
	repo := &eventCaptureRepo{
		runJobTestRepo: runJobTestRepo{
			reportTestRepo: reportTestRepo{
				jobs: map[string]*model.ScanJob{job.ID: job},
			},
		},
	}
	reg := agent.NewRegistry()
	reg.Register(eventProbeAgent{})
	s := &Server{
		repo:          repo,
		agentRegistry: reg,
		maxPerTarget:  1,
		targetSem:     map[string]chan struct{}{},
		globalSem:     make(chan struct{}, 1),
		targetLastRun: map[string]time.Time{},
		scanTimeout:   time.Minute,
		eventBus:      NewEventBus(),
		defaultMinROI: 75,
		cancelFuncs:   map[string]context.CancelFunc{},
	}

	s.runJob(job.ID, job.Target, model.ScanAuthProfile{}, nil, model.ScanOptions{}, model.ScanScope{})
	waitForAgentEvent(t, repo, job.ID, model.ScanEventThinking)
	waitForAgentEvent(t, repo, job.ID, model.ScanEventDiscovery)
}

func TestRunDispatchedAgentPersistsThinkingAndDiscoveryEvents(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-dispatch-events",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "queued",
		StartedAt:   time.Now().UTC(),
	}
	repo := &eventCaptureRepo{
		runJobTestRepo: runJobTestRepo{
			reportTestRepo: reportTestRepo{
				jobs: map[string]*model.ScanJob{job.ID: job},
			},
		},
	}
	reg := agent.NewRegistry()
	reg.Register(eventProbeAgent{})
	s := &Server{
		repo:          repo,
		agentRegistry: reg,
		eventBus:      NewEventBus(),
	}

	s.runDispatchedAgent(job.ID, "event-probe-agent", job.Target, model.ScanOptions{})
	waitForAgentEvent(t, repo, job.ID, model.ScanEventThinking)
	waitForAgentEvent(t, repo, job.ID, model.ScanEventDiscovery)
}
