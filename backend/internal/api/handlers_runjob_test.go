package api

import (
	"context"
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

type panicAttackGraphStore struct{}

func (panicAttackGraphStore) SaveAttackGraph(context.Context, string, string, *model.AttackGraphData) error {
	panic("attack graph store panic")
}

func (panicAttackGraphStore) LoadAttackGraph(context.Context, string) (*model.AttackGraphData, error) {
	return nil, nil
}

func TestRunJobMarksScanFailedWhenPostProcessingPanics(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-1",
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
