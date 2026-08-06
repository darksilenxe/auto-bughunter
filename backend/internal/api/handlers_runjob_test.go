package api

import (
	"context"
	"strings"
	"sync"
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

type blockingUpdateRepo struct {
	runJobTestRepo
	mu             sync.Mutex
	updateAttempts []string
}

func (r *blockingUpdateRepo) UpdateJob(ctx context.Context, job *model.ScanJob) error {
	r.mu.Lock()
	r.updateAttempts = append(r.updateAttempts, job.Status)
	r.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (r *blockingUpdateRepo) UpdateAttempts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.updateAttempts...)
}

func collapseConsecutive(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := []string{values[0]}
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

type flakyUpdateRepo struct {
	runJobTestRepo
	mu          sync.Mutex
	attempts    int
	failures    int
	lastContext context.Context
}

func (r *flakyUpdateRepo) UpdateJob(ctx context.Context, job *model.ScanJob) error {
	r.mu.Lock()
	r.attempts++
	r.lastContext = ctx
	remainingFailures := r.failures
	if r.failures > 0 {
		r.failures--
	}
	r.mu.Unlock()
	if remainingFailures > 0 {
		return context.DeadlineExceeded
	}
	return r.runJobTestRepo.UpdateJob(ctx, job)
}

func (r *flakyUpdateRepo) Attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

type blockingAttackGraphStore struct {
	mu      sync.Mutex
	attempt int
}

func (s *blockingAttackGraphStore) SaveAttackGraph(ctx context.Context, _ string, _ string, _ *model.AttackGraphData) error {
	s.mu.Lock()
	s.attempt++
	s.mu.Unlock()
	<-ctx.Done()
	return ctx.Err()
}

func (s *blockingAttackGraphStore) LoadAttackGraph(context.Context, string) (*model.AttackGraphData, error) {
	return nil, nil
}

func (s *blockingAttackGraphStore) Attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempt
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

func TestPersistJobRetriesTransientFailures(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-persist-retry",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "completed",
		StartedAt:   time.Now().UTC(),
	}
	repo := &flakyUpdateRepo{
		runJobTestRepo: runJobTestRepo{
			reportTestRepo: reportTestRepo{
				jobs: map[string]*model.ScanJob{job.ID: job},
			},
		},
		failures: 2,
	}
	s := &Server{
		repo:               repo,
		persistenceTimeout: 50 * time.Millisecond,
	}

	if err := s.persistJob(job); err != nil {
		t.Fatalf("persistJob returned error: %v", err)
	}
	if attempts := repo.Attempts(); attempts != 3 {
		t.Fatalf("expected 3 update attempts, got %d", attempts)
	}
	if len(repo.updateStatuses) != 1 || repo.updateStatuses[0] != "completed" {
		t.Fatalf("expected final successful persisted status, got %v", repo.updateStatuses)
	}
}

func TestRunJobFinalizesWhenJobPersistenceBlocksBeyondBudget(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-persist-block",
		Target:      "https://example.com",
		WorkspaceID: "default",
		Status:      "queued",
		StartedAt:   time.Now().UTC(),
	}
	repo := &blockingUpdateRepo{
		runJobTestRepo: runJobTestRepo{
			reportTestRepo: reportTestRepo{
				jobs: map[string]*model.ScanJob{job.ID: job},
			},
		},
	}
	s := &Server{
		repo:               repo,
		agentRegistry:      agent.NewRegistry(),
		maxPerTarget:       1,
		targetSem:          map[string]chan struct{}{},
		globalSem:          make(chan struct{}, 1),
		targetLastRun:      map[string]time.Time{},
		scanTimeout:        time.Minute,
		persistenceTimeout: 50 * time.Millisecond,
		eventBus:           NewEventBus(),
		defaultMinROI:      75,
		cancelFuncs:        map[string]context.CancelFunc{},
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
		t.Fatal("runJob did not finalize within 10s despite bounded SQL persistence")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("runJob took %s to finish; bounded SQL persistence should prevent hangs", elapsed)
	}
	attempts := repo.UpdateAttempts()
	if len(attempts) < 3 {
		t.Fatalf("expected multiple update attempts despite timeouts, got %v", attempts)
	}
	if collapsed := collapseConsecutive(attempts); len(collapsed) != 3 || collapsed[0] != "running" || collapsed[1] != "finalizing" || collapsed[2] != "completed" {
		t.Fatalf("unexpected update attempt sequence %v", attempts)
	}
}

func TestRunJobFinalizesWhenAttackGraphPersistenceBlocksBeyondBudget(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-graph-persist-block",
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
	graphStore := &blockingAttackGraphStore{}
	s := &Server{
		repo:               repo,
		agentRegistry:      agent.NewRegistry(),
		maxPerTarget:       1,
		targetSem:          map[string]chan struct{}{},
		globalSem:          make(chan struct{}, 1),
		targetLastRun:      map[string]time.Time{},
		scanTimeout:        time.Minute,
		persistenceTimeout: 50 * time.Millisecond,
		eventBus:           NewEventBus(),
		attackGraphDB:      graphStore,
		defaultMinROI:      75,
		cancelFuncs:        map[string]context.CancelFunc{},
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
		t.Fatal("runJob did not finalize within 10s despite bounded Neo4j persistence")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("runJob took %s to finish; bounded Neo4j persistence should prevent hangs", elapsed)
	}
	if attempts := graphStore.Attempts(); attempts < 2 {
		t.Fatalf("expected attack graph persistence attempts, got %d", attempts)
	}
	stored, err := repo.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetJob returned error: %v", err)
	}
	if stored.Status != "completed" {
		t.Fatalf("expected completed status after Neo4j timeout, got %q", stored.Status)
	}
}

func TestAppendAuditEventUsesBoundedPersistenceTimeout(t *testing.T) {
	blocked := make(chan struct{}, 1)
	repo := &auditBlockingRepo{blocked: blocked}
	s := &Server{
		repo:               repo,
		persistenceTimeout: 50 * time.Millisecond,
	}

	start := time.Now()
	s.appendAuditEvent("scan-audit", "running", "Scan execution started")
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("appendAuditEvent took %s; expected bounded persistence timeout", elapsed)
	}
	select {
	case <-blocked:
	default:
		t.Fatal("expected AppendAuditEvent to be invoked")
	}
}

func TestAttachDecisionTraceToFindings(t *testing.T) {
	options := model.ScanOptions{PolicyPack: "autonomous"}
	findings := []model.Finding{
		{
			ID:          "f-1",
			Category:    "xss",
			Sources:     []string{"scanning"},
			ImpactScore: 7.2,
		},
	}

	stamped := attachDecisionTraceToFindings(findings, options, "https://example.com/app", model.ScanScope{IncludeHosts: []string{"example.com"}})
	if len(stamped) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(stamped))
	}
	trace := stamped[0].AgentDecisionTrace
	if trace == nil {
		t.Fatal("expected finding decision trace")
	}
	if trace.PolicyProfile != "autonomous" {
		t.Fatalf("expected policy profile autonomous, got %q", trace.PolicyProfile)
	}
	if trace.ScopeCheck != "in_scope" {
		t.Fatalf("expected in_scope scope check, got %q", trace.ScopeCheck)
	}
	if trace.TriggeringSignal != "scanning" {
		t.Fatalf("expected trigger signal scanning, got %q", trace.TriggeringSignal)
	}
	if trace.ROIScore != 7.2 {
		t.Fatalf("expected ROI score 7.2, got %v", trace.ROIScore)
	}
	if trace.Timestamp.IsZero() {
		t.Fatal("expected non-zero trace timestamp")
	}
}

func TestBuildAgentTelemetryAttachesDecisionTrace(t *testing.T) {
	outputs := []agent.AgentOutput{
		{
			AgentName: "scanning",
			Metadata: map[string]string{
				"roi_score":      "88.5",
				"trigger_signal": "gap-requeue",
			},
			Telemetry: model.AgentRunTelemetry{
				StartedAt: time.Now().UTC(),
				Status:    "completed",
			},
		},
	}

	telemetry := buildAgentTelemetry(outputs, model.ScanOptions{PolicyPack: "safe"}, "https://example.com", model.ScanScope{IncludeHosts: []string{"example.com"}})
	if len(telemetry) != 1 {
		t.Fatalf("expected 1 telemetry record, got %d", len(telemetry))
	}
	trace := telemetry[0].AgentDecisionTrace
	if trace == nil {
		t.Fatal("expected telemetry decision trace")
	}
	if trace.PolicyProfile != "safe" {
		t.Fatalf("expected policy profile safe, got %q", trace.PolicyProfile)
	}
	if trace.TriggeringSignal != "gap-requeue" {
		t.Fatalf("expected trigger gap-requeue, got %q", trace.TriggeringSignal)
	}
	if trace.ROIScore != 88.5 {
		t.Fatalf("expected ROI score 88.5, got %v", trace.ROIScore)
	}
}

type auditBlockingRepo struct {
	reportTestRepo
	blocked chan struct{}
}

func (r *auditBlockingRepo) AppendAuditEvent(ctx context.Context, _ string, _ model.ScanAuditEvent) error {
	select {
	case r.blocked <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

// TestRunJobHonoursOperatorCancelDuringFinalizing verifies that when the
// operator calls stopScan while runJob is in the "finalizing" (post-processing)
// phase, the scan is ultimately marked "cancelled" rather than "completed".
func TestRunJobHonoursOperatorCancelDuringFinalizing(t *testing.T) {
	job := &model.ScanJob{
		ID:          "scan-cancel-finalizing",
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

	// hookEntered is signalled when the enrichment hook starts; the test then
	// cancels the scan context to simulate operator stop-during-finalizing.
	hookEntered := make(chan struct{})
	unblock := make(chan struct{})

	s := &Server{
		repo:              repo,
		agentRegistry:     agent.NewRegistry(),
		maxPerTarget:      1,
		targetSem:         map[string]chan struct{}{},
		globalSem:         make(chan struct{}, 1),
		targetLastRun:     map[string]time.Time{},
		scanTimeout:       time.Minute,
		postProcessBudget: 10 * time.Second,
		eventBus:          NewEventBus(),
		defaultMinROI:     75,
		cancelFuncs:       map[string]context.CancelFunc{},
		enrichmentHook: func(_ context.Context, _ string, _ []model.Finding, _ *model.ScanJob) enrichmentResult {
			close(hookEntered)
			<-unblock
			return enrichmentResult{}
		},
	}

	done := make(chan struct{})
	go func() {
		s.runJob(job.ID, job.Target, model.ScanAuthProfile{}, nil, model.ScanOptions{}, model.ScanScope{})
		close(done)
	}()

	// Wait until enrichment has started, then cancel via the registered func.
	select {
	case <-hookEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("enrichment hook was never entered")
	}
	s.cancelMu.Lock()
	cancelFn, ok := s.cancelFuncs[job.ID]
	s.cancelMu.Unlock()
	if !ok {
		t.Fatal("no cancel func registered for scan")
	}
	cancelFn()
	// Unblock the hook so runJob can proceed to check ctx.Err().
	close(unblock)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runJob did not finish within 10s after operator cancel")
	}

	stored, err := repo.GetJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if stored.Status != "cancelled" {
		t.Fatalf("expected cancelled status after operator stop during finalizing, got %q", stored.Status)
	}
	// The final persisted status must be "cancelled".
	if last := repo.updateStatuses[len(repo.updateStatuses)-1]; last != "cancelled" {
		t.Fatalf("expected last persisted status to be cancelled, got %q (all: %v)", last, repo.updateStatuses)
	}
}
