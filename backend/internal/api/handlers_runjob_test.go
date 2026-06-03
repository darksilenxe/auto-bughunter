package api

import (
	"context"
	"sync"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

type runJobTestRepo struct {
	reportTestRepo
	updateStatuses []string
}

func (r *runJobTestRepo) UpdateJob(_ context.Context, job *model.ScanJob) error {
	r.jobs[job.ID] = job
	r.updateStatuses = append(r.updateStatuses, job.Status)
	return nil
}

func (r *runJobTestRepo) SaveAssets(context.Context, string, []model.ScanAsset) error {
	return nil
}

func (r *runJobTestRepo) AppendAuditEvent(context.Context, string, model.ScanAuditEvent) error {
	return nil
}

func (r *runJobTestRepo) ListActiveSuppressionRules(context.Context, string, time.Time) ([]model.SuppressionRule, error) {
	return nil, nil
}

func (r *runJobTestRepo) GetScanState(context.Context, string) (*model.PersistentScanState, error) {
	return nil, nil
}

func (r *runJobTestRepo) ListFeedback(context.Context, int) ([]model.ReportFeedback, error) {
	return nil, nil
}

func (r *runJobTestRepo) GetProgramROIOverride(context.Context, string, string) (*model.ProgramROIOverride, error) {
	return nil, nil
}

func (r *runJobTestRepo) UpsertScanState(context.Context, model.PersistentScanState) error {
	return nil
}

func TestRunJobFinalizesWhenEnrichmentBlocksBeyondBudget(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-enrich-block",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "queued",
		StartedAt:   time.Now().UTC(),
	}
	repo := &runJobTestRepo{
		reportTestRepo: reportTestRepo{
			jobs: map[string]*model.ScanJob{job.ID: job},
		},
	}

	// Block the enrichment goroutine well past the budget while ignoring ctx,
	// simulating an AI summary / ML step that hangs. The watchdog must abandon
	// it and still finalize the scan promptly. unblock lets the goroutine exit
	// after assertions so the test leaks nothing.
	unblock := make(chan struct{})
	defer close(unblock)
	hookEntered := make(chan struct{}, 1)

	s := &Server{
		repo:              repo,
		agentRegistry:     agent.NewRegistry(),
		maxPerTarget:      1,
		targetSem:         map[string]chan struct{}{},
		globalSem:         make(chan struct{}, 1),
		targetLastRun:     map[string]time.Time{},
		scanTimeout:       time.Minute,
		postProcessBudget: 50 * time.Millisecond,
		eventBus:          NewEventBus(),
		defaultMinROI:     75,
		cancelFuncs:       map[string]context.CancelFunc{},
		enrichmentHook: func(_ context.Context, _ string, _ []model.Finding, _ *model.ScanJob) enrichmentResult {
			select {
			case hookEntered <- struct{}{}:
			default:
			}
			<-unblock
			return enrichmentResult{aiSummary: "should be discarded"}
		},
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		s.runJob(job.ID, job.Target, model.ScanAuthProfile{}, nil, model.ScanOptions{}, model.ScanScope{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runJob did not finalize within 10s despite the enrichment watchdog budget")
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("runJob took %s to finalize; watchdog should bound the enrichment phase near its 50ms budget", elapsed)
	}

	select {
	case <-hookEntered:
	default:
		t.Fatal("enrichment hook was never entered; test did not exercise the watchdog path")
	}

	stored, err := repo.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetJob returned error: %v", err)
	}
	if stored.Status != "completed" {
		t.Fatalf("expected completed status after enrichment timeout, got %q", stored.Status)
	}
	if stored.AISummary == "should be discarded" {
		t.Fatal("expected partial (empty) AI summary; the abandoned enrichment result must not be applied")
	}
	if len(repo.updateStatuses) == 0 || repo.updateStatuses[len(repo.updateStatuses)-1] != "completed" {
		t.Fatalf("expected final persisted status to be completed, got %v", repo.updateStatuses)
	}
	if len(repo.updateStatuses) < 2 {
		t.Fatalf("expected running -> finalizing -> completed updates, got %v", repo.updateStatuses)
	}
	if repo.updateStatuses[0] != "running" || repo.updateStatuses[len(repo.updateStatuses)-2] != "finalizing" || repo.updateStatuses[len(repo.updateStatuses)-1] != "completed" {
		t.Fatalf("unexpected update status sequence %v", repo.updateStatuses)
	}
}

type panicAttackGraphStore struct{}

func (panicAttackGraphStore) SaveAttackGraph(context.Context, string, string, *model.AttackGraphData) error {
	panic("attack graph store panic")
}

func (panicAttackGraphStore) LoadAttackGraph(context.Context, string) (*model.AttackGraphData, error) {
	return nil, nil
}

type captureAttackGraphStore struct {
	mu    sync.Mutex
	saves []model.AttackGraphData
}

func (s *captureAttackGraphStore) SaveAttackGraph(_ context.Context, _ string, _ string, graph *model.AttackGraphData) error {
	if graph == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, *graph)
	return nil
}

func (s *captureAttackGraphStore) LoadAttackGraph(context.Context, string) (*model.AttackGraphData, error) {
	return nil, nil
}

func (s *captureAttackGraphStore) LastStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saves) == 0 {
		return ""
	}
	return s.saves[len(s.saves)-1].Status
}

func TestRunJobMarksScanFailedWhenPostProcessingPanics(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-1",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "queued",
		StartedAt:   time.Now().UTC(),
	}

	func TestRunJobPersistsFinalAttackGraphStatus(t *testing.T) {
		job := &model.ScanJob{
			ID:          "scan-graph-final-status",
			Target:      "https://example.com",
			WorkspaceID: "default",
			Status:      "queued",
			StartedAt:   time.Now().UTC(),
		}
		repo := &runJobTestRepo{
			reportTestRepo: reportTestRepo{
				jobs: map[string]*model.ScanJob{job.ID: job},
			},
		}
		graphStore := &captureAttackGraphStore{}
		s := &Server{
			repo:          repo,
			agentRegistry: agent.NewRegistry(),
			maxPerTarget:  1,
			targetSem:     map[string]chan struct{}{},
			globalSem:     make(chan struct{}, 1),
			targetLastRun: map[string]time.Time{},
			scanTimeout:   time.Minute,
			eventBus:      NewEventBus(),
			attackGraphDB: graphStore,
			defaultMinROI: 75,
			cancelFuncs:   map[string]context.CancelFunc{},
		}

		s.runJob(job.ID, job.Target, model.ScanAuthProfile{}, nil, model.ScanOptions{}, model.ScanScope{})

		if got := graphStore.LastStatus(); got != "completed" {
			t.Fatalf("expected final persisted attack graph status completed, got %q", got)
		}
	}
	repo := &runJobTestRepo{
		reportTestRepo: reportTestRepo{
			jobs: map[string]*model.ScanJob{job.ID: job},
		},
	}
	s := &Server{
		repo:          repo,
		agentRegistry: agent.NewRegistry(),
		maxPerTarget:  1,
		targetSem:     map[string]chan struct{}{},
		globalSem:     make(chan struct{}, 1),
		targetLastRun: map[string]time.Time{},
		scanTimeout:   time.Minute,
		eventBus:      NewEventBus(),
		attackGraphDB: panicAttackGraphStore{},
		defaultMinROI: 75,
		cancelFuncs:   map[string]context.CancelFunc{},
	}

	s.runJob(job.ID, job.Target, model.ScanAuthProfile{}, nil, model.ScanOptions{}, model.ScanScope{})

	stored, err := repo.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetJob returned error: %v", err)
	}
	if stored.Status != "failed" {
		t.Fatalf("expected failed status after panic, got %q", stored.Status)
	}
	if stored.CompletedAt == nil {
		t.Fatal("expected completed timestamp to be set after panic recovery")
	}
	if !strings.Contains(stored.Error, "scan panicked: attack graph store panic") {
		t.Fatalf("expected panic error to be recorded, got %q", stored.Error)
	}
	if len(repo.updateStatuses) < 2 {
		t.Fatalf("expected running and failed updates, got %v", repo.updateStatuses)
	}
	if repo.updateStatuses[0] != "running" || repo.updateStatuses[len(repo.updateStatuses)-1] != "failed" {
		t.Fatalf("unexpected update status sequence %v", repo.updateStatuses)
	}
}
