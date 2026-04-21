package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/agentlearner"
	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/attackgraph"
	"auto-bughunter/backend/internal/knowledge"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
)

type AgentConfig struct {
	EnableMLTriageAgent      bool
	EnableAttackPathAgent    bool
	EnableFalsePositiveAgent bool
	EnableRemediationAgent   bool
}

type Server struct {
	scanService                *scanner.Service
	aiClient                   *ai.Client
	repo                       Repository
	agentRegistry              *agent.Registry
	agentFactory               *agent.Factory
	autonomous                 bool
	maxRounds                  int
	proxyServer                *proxy.Server
	mlService                  *ml.Service
	knowledgeSvc               *knowledge.Client
	agentLearner               *agentlearner.Client
	agentConfig                AgentConfig
	maxPerTarget               int
	semMu                      sync.Mutex
	targetSem                  map[string]chan struct{}
	globalSem                  chan struct{}
	rateMu                     sync.Mutex
	targetLastRun              map[string]time.Time
	webhookURL                 string
	slackWebhook               string
	notifyMinConf              float64
	gateHighBlock              int
	gateMedBlock               int
	scanTimeout                time.Duration
	eventBus                   *EventBus
	oast                       *oast.Service
	attackGraphDB              AttackGraphStore
	apiRateLimiter             *apiRateLimiter
	defaultMinROI              float64
	campaignPoll               time.Duration
	defaultDailyScanLimit      int
	defaultDailyRuntimeMinutes int
	defaultDailyProbeLimit     int
}

const (
	coverageLowThreshold         = 70
	coverageLowCrawlBoostPages   = 200
	highROIMultiplierForDeepScan = 1.5
	lowROICrawlFloorPages        = 40
	lowROICrawlCeilingPages      = 120
	// High-confidence findings are already filtered by confidence/severity and
	// therefore counted as full novelty units while all findings contribute a
	// smaller background signal.
	autonomyNoveltyFindingWeight = 0.2
	autonomyPreferredMinScore    = 2.0
	autonomyPreferredMaxErrRate  = 0.5
	autonomySuppressMinRuns      = 3
	autonomySuppressErrRate      = 0.66
	autonomySuppressTimeouts     = 2
)

// SetOAST attaches an OAST service so its admin endpoints become active.
// Safe to call with nil to disable.
func (s *Server) SetOAST(o *oast.Service) { s.oast = o }

// SetAttackGraphStore attaches an optional graph database-backed attack graph store.
func (s *Server) SetAttackGraphStore(store AttackGraphStore) { s.attackGraphDB = store }

type AttackGraphStore interface {
	SaveAttackGraph(ctx context.Context, scanID, target string, graph *model.AttackGraphData) error
	LoadAttackGraph(ctx context.Context, scanID string) (*model.AttackGraphData, error)
}

type Repository interface {
	CreateJob(ctx context.Context, job *model.ScanJob) error
	UpdateJob(ctx context.Context, job *model.ScanJob) error
	GetJob(ctx context.Context, id string) (*model.ScanJob, error)
	GetLatestCompletedJobByTarget(ctx context.Context, target, excludeID string) (*model.ScanJob, error)
	SaveAssets(ctx context.Context, scanID string, assets []model.ScanAsset) error
	GetAssetsByScanID(ctx context.Context, scanID string) ([]model.ScanAsset, error)
	AppendAuditEvent(ctx context.Context, scanID string, event model.ScanAuditEvent) error
	ListAuditEvents(ctx context.Context, scanID string) ([]model.ScanAuditEvent, error)
	ListCompletedJobs(ctx context.Context, limit int) ([]*model.ScanJob, error)
	SaveFeedback(ctx context.Context, feedback model.ReportFeedback) error
	ListFeedback(ctx context.Context, limit int) ([]model.ReportFeedback, error)
	SaveFindingVerification(ctx context.Context, verification model.FindingVerification) error
	GetLatestFindingVerifications(ctx context.Context, scanID string) (map[string]model.FindingVerification, error)
	SaveSuppressionRule(ctx context.Context, rule model.SuppressionRule) error
	ListActiveSuppressionRules(ctx context.Context, target string, now time.Time) ([]model.SuppressionRule, error)
	GetScanState(ctx context.Context, target string) (*model.PersistentScanState, error)
	UpsertScanState(ctx context.Context, state model.PersistentScanState) error
	GetRecentJobByIdempotencyKey(ctx context.Context, key, target string, since time.Time) (*model.ScanJob, error)
	SaveIdempotencyRecord(ctx context.Context, key, target, scanID string, createdAt time.Time) error
	UpsertAutomationTicket(ctx context.Context, ticket model.AutomationTicket) error
	ResolveAutomationTicketsMissingFingerprints(ctx context.Context, target string, fingerprints []string, resolvedAt time.Time) (int64, error)
	ListOpenAutomationTickets(ctx context.Context, target string, limit int) ([]model.AutomationTicket, error)
	UpsertAutomationCampaign(ctx context.Context, campaign model.AutomationCampaign) error
	ListAutomationCampaigns(ctx context.Context, workspaceID string, activeOnly bool, limit int) ([]model.AutomationCampaign, error)
	ListDueAutomationCampaigns(ctx context.Context, now time.Time, limit int) ([]model.AutomationCampaign, error)
	UpdateAutomationCampaignRun(ctx context.Context, id string, lastRunAt, nextRunAt time.Time) error
	DeleteAutomationCampaign(ctx context.Context, id, workspaceID string) error
	TryLeaseAutomationCampaign(ctx context.Context, id string, leaseUntil time.Time) (bool, error)
	MarkAutomationCampaignDispatchFailure(ctx context.Context, id, lastError string, now time.Time, backoff time.Duration) error
	HeartbeatAutomationCampaignLease(ctx context.Context, id string, heartbeatAt, leaseUntil time.Time) (bool, error)
	ReclaimStaleAutomationCampaignLeases(ctx context.Context, staleBefore time.Time, limit int) (int64, error)
	UpdateAutomationCampaignQueueState(ctx context.Context, id, queueState, runIdempotencyKey string, heartbeatAt *time.Time) error
	GetProgramROIOverride(ctx context.Context, workspaceID, programName string) (*model.ProgramROIOverride, error)
	UpsertProgramROIOverride(ctx context.Context, item model.ProgramROIOverride) error
	ListProgramROIOverrides(ctx context.Context, workspaceID string, limit int) ([]model.ProgramROIOverride, error)
	GetWorkspaceDailyUsage(ctx context.Context, workspaceID string, day time.Time) (model.WorkspaceDailyUsage, error)
	GetAutomationPolicyPack(ctx context.Context, workspaceID, name string) (*model.AutomationPolicyPack, error)
	UpsertAutomationPolicyPack(ctx context.Context, item model.AutomationPolicyPack) error
	ListAutomationPolicyPacks(ctx context.Context, workspaceID string, limit int) ([]model.AutomationPolicyPack, error)
	AppendAutomationPolicyAudit(ctx context.Context, event model.AutomationPolicyAuditEvent) error
	ListAutomationPolicyAudit(ctx context.Context, workspaceID, policyPack string, limit int) ([]model.AutomationPolicyAuditEvent, error)
}

func NewServer(scanService *scanner.Service, aiClient *ai.Client, mlService *ml.Service, knowledgeSvc *knowledge.Client, agentLearner *agentlearner.Client, repo Repository, proxyStore proxy.Store, maxPerTarget, globalBudget int, agentCfg AgentConfig, scanTimeout time.Duration) *Server {
	reg := agent.NewRegistry()
	factory := agent.NewFactory(scanService, mlService)
	reg.RegisterFactory(factory)
	reg.Register(agent.NewReconnaissanceAgent(true))
	reg.Register(agent.NewScanningAgent(scanService, true))
	reg.Register(agent.NewInputValidationAgent(true))
	reg.Register(agent.NewInformationDisclosureAgent(true))
	reg.Register(agent.NewAccessControlAgent(true))
	reg.Register(agent.NewAPISecurityAgent(true))
	reg.Register(agent.NewCORSRedirectAgent(true))
	reg.Register(agent.NewWordlistAgent(true))
	reg.Register(agent.NewAnalysisAgent(true))
	reg.Register(agent.NewReportingAgent(true))

	autonomous := boolFromEnv("ENABLE_AUTONOMOUS_ORCHESTRATION", true)
	maxRounds := maxInt(1, intFromEnv("MAX_ORCHESTRATION_ROUNDS", 10))

	if globalBudget <= 0 {
		globalBudget = 5
	}
	if scanTimeout <= 0 {
		scanTimeout = 10 * time.Minute
	}
	s := &Server{
		scanService:                scanService,
		aiClient:                   aiClient,
		repo:                       repo,
		agentRegistry:              reg,
		agentFactory:               factory,
		autonomous:                 autonomous,
		maxRounds:                  maxRounds,
		proxyServer:                proxy.NewServer(proxyStore),
		mlService:                  mlService,
		knowledgeSvc:               knowledgeSvc,
		agentLearner:               agentLearner,
		agentConfig:                agentCfg,
		maxPerTarget:               maxInt(1, maxPerTarget),
		targetSem:                  map[string]chan struct{}{},
		globalSem:                  make(chan struct{}, globalBudget),
		targetLastRun:              map[string]time.Time{},
		webhookURL:                 strings.TrimSpace(os.Getenv("SCAN_WEBHOOK_URL")),
		slackWebhook:               strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL")),
		notifyMinConf:              maxFloat(0.0, minFloat(1.0, floatFromEnv("NOTIFY_MIN_CONFIDENCE", 0.9))),
		gateHighBlock:              maxInt(0, intFromEnv("POLICY_GATE_HIGH_BLOCK", 1)),
		gateMedBlock:               maxInt(0, intFromEnv("POLICY_GATE_MEDIUM_BLOCK", 3)),
		scanTimeout:                scanTimeout,
		eventBus:                   NewEventBus(),
		apiRateLimiter:             newAPIRateLimiter(),
		defaultMinROI:              maxFloat(0, floatFromEnv("AUTOMATION_MIN_EXPECTED_ROI_USD", 75)),
		campaignPoll:               time.Duration(maxInt(15, intFromEnv("AUTOMATION_CAMPAIGN_POLL_SECONDS", 30))) * time.Second,
		defaultDailyScanLimit:      maxInt(0, intFromEnv("AUTOMATION_DAILY_SCAN_LIMIT", 30)),
		defaultDailyRuntimeMinutes: maxInt(0, intFromEnv("AUTOMATION_DAILY_RUNTIME_LIMIT_MINUTES", 240)),
		defaultDailyProbeLimit:     maxInt(0, intFromEnv("AUTOMATION_DAILY_PROBE_LIMIT", 5000)),
	}
	go s.runCampaignScheduler()
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scan", s.handleCreateScan)
	mux.HandleFunc("/api/scan/", s.handleScanOrEvents)
	mux.HandleFunc("/api/scans", s.handleListScans)
	// Proxy management endpoints.
	mux.HandleFunc("/api/proxy/requests", s.handleProxyRequests)
	mux.HandleFunc("/api/proxy/requests/", s.handleGetProxyRequest)
	mux.HandleFunc("/api/proxy/replay", s.handleProxyReplay)
	mux.HandleFunc("/api/ml/engagements", s.handleListMLEngagements)
	mux.HandleFunc("/api/ml/agent-weights", s.handleAgentWeights)
	mux.HandleFunc("/api/feedback", s.handleFeedback)
	mux.HandleFunc("/api/finding-verification", s.handleFindingVerification)
	mux.HandleFunc("/api/suppressions", s.handleSuppressions)
	mux.HandleFunc("/api/tools/health", s.handleToolsHealth)
	mux.HandleFunc("/api/tools/updates", s.handleToolsUpdates)
	mux.HandleFunc("/api/automation/event", s.handleAutomationEvent)
	mux.HandleFunc("/api/automation/report", s.handleAutomationReport)
	mux.HandleFunc("/api/automation/tickets", s.handleAutomationTickets)
	mux.HandleFunc("/api/automation/campaigns", s.handleAutomationCampaigns)
	mux.HandleFunc("/api/automation/roi-overrides", s.handleAutomationROIOverrides)
	mux.HandleFunc("/api/automation/policy-packs", s.handleAutomationPolicyPacks)
	mux.HandleFunc("/api/automation/policy-audit", s.handleAutomationPolicyAudit)
	mux.HandleFunc("/api/automation/metrics", s.handleAutomationMetrics)
	mux.HandleFunc("/api/automation/rebalance", s.handleAutomationRebalance)
	mux.HandleFunc("/api/automation/operator-feedback", s.handleAutomationOperatorFeedback)
	mux.HandleFunc("/api/burp/parse", s.handleBurpParse)
	mux.HandleFunc("/api/report/", s.handleScanReport)
	mux.HandleFunc("/api/compliance/evidence/", s.handleComplianceEvidence)
	mux.HandleFunc("/api/oast/tokens", s.handleOASTTokens)
	mux.HandleFunc("/api/oast/hits/", s.handleOASTHits)
	mux.HandleFunc("/api/admin/apikeys", s.handleAPIKeys)
	mux.HandleFunc("/api/admin/apikeys/", s.handleAPIKeyByID)
	return withCORS(s.authMiddleware(s.rateLimitMiddleware(mux)))
}

// handleScanOrEvents routes /api/scan/{id} and /api/scan/{id}/events.
func (s *Server) handleScanOrEvents(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/events") {
		s.handleScanEvents(w, r)
		return
	}
	s.handleGetScan(w, r)
}
func (s *Server) handleAgentWeights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.agentLearner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent learner service not configured"})
		return
	}
	weights, err := s.agentLearner.Weights(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "agent learner unreachable: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, weights)
}

// handleListScans returns a paginated list of completed scan jobs.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	limit := 50
	jobs, err := s.repo.ListCompletedJobs(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list scans"})
		return
	}
	// Return lightweight summaries (no full findings) to keep response size small.
	type scanSummary struct {
		ID           string     `json:"id"`
		Target       string     `json:"target"`
		Status       string     `json:"status"`
		CreatedAt    time.Time  `json:"createdAt"`
		CompletedAt  *time.Time `json:"completedAt"`
		FindingCount int        `json:"findingCount"`
		HighCount    int        `json:"highCount"`
	}
	summaries := make([]scanSummary, 0, len(jobs))
	for _, j := range jobs {
		if j == nil {
			continue
		}
		if !canAccessWorkspaceForRequest(r.Context(), j.WorkspaceID) {
			continue
		}
		var high int
		for _, f := range j.Findings {
			if f.Severity == model.SeverityHigh {
				high++
			}
		}
		summaries = append(summaries, scanSummary{
			ID:           j.ID,
			Target:       j.Target,
			Status:       j.Status,
			CreatedAt:    j.StartedAt,
			CompletedAt:  j.CompletedAt,
			FindingCount: len(j.Findings),
			HighCount:    high,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": summaries})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req model.ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	target, _, err := normalizeAndValidateTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target blocked by outbound safety policy"})
		return
	}
	req.Scope = applyProgramScope(req.Scope, req.ProgramScopeProfile)
	req.Options = enforceDisallowedTests(req.Options, req.DisallowedTestTypes, req.Scope.ProgramRules)
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
		return
	}
	if err := validateAuthProfile(req.AuthProfile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Options.RescanIntervalMinutes < 0 || req.Options.RescanIntervalMinutes > 10080 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rescanIntervalMinutes must be between 0 and 10080"})
		return
	}
	req.Options.AutomationMode = normalizeAutomationMode(req.Options.AutomationMode)
	req.Options = s.applySafetyModePolicy(req.Options)
	if req.Options.MinExpectedROIUSD < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "minExpectedRoiUsd must be >= 0"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), strings.TrimSpace(req.WorkspaceID), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	req.Options, _ = s.applyAutomationPolicyPack(r.Context(), workspaceID, defaultPolicyPack(), req.Options)
	idempotencyTarget := workspaceID + "::" + target
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	if req.IdempotencyKey != "" {
		if existing, err := s.repo.GetRecentJobByIdempotencyKey(r.Context(), req.IdempotencyKey, idempotencyTarget, time.Now().UTC().Add(-24*time.Hour)); err == nil && existing != nil {
			writeJSON(w, http.StatusAccepted, map[string]string{"id": existing.ID, "status": existing.Status, "deduplicated": "true"})
			return
		}
	}

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                   jobID,
		Target:               target,
		WorkspaceID:          workspaceID,
		RequestedBy:          requesterFromRequest(r),
		PolicyPack:           defaultPolicyPack(),
		Status:               "queued",
		StartedAt:            now,
		AuthProfileSummary:   model.SummarizeAuthProfile(req.AuthProfile),
		Options:              req.Options,
		Scope:                req.Scope,
		ProgramName:          strings.TrimSpace(req.ProgramName),
		ProgramPolicyVersion: strings.TrimSpace(req.ProgramPolicyVersion),
		DisallowedTestTypes:  append([]string(nil), req.DisallowedTestTypes...),
	}
	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist scan job"})
		return
	}
	if req.IdempotencyKey != "" {
		_ = s.repo.SaveIdempotencyRecord(r.Context(), req.IdempotencyKey, idempotencyTarget, jobID, now)
	}
	s.appendAuditEvent(jobID, "queued", "Scan job accepted and queued")
	if req.Options.AggressiveExploitation {
		s.appendAuditEvent(jobID, "exploitation", "Aggressive exploitation mode enabled for deeper Metasploit/Burp validation")
	}

	go s.runJob(jobID, target, req.AuthProfile, req.AuthProfiles, req.Options, req.Scope)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": jobID, "status": "queued"})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	job, err := s.repo.GetJob(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load scan"})
		return
	}

	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	if verifications, err := s.repo.GetLatestFindingVerifications(r.Context(), id); err == nil && len(verifications) > 0 {
		for i := range job.Findings {
			if v, ok := verifications[job.Findings[i].ID]; ok {
				if job.Findings[i].Exploitability == nil {
					job.Findings[i].Exploitability = &model.Exploitability{}
				}
				job.Findings[i].Exploitability.VerifiedStatus = v.Status
				job.Findings[i].Exploitability.VerifiedNotes = v.Notes
			}
		}
	}
	if s.attackGraphDB != nil {
		if graph, err := s.attackGraphDB.LoadAttackGraph(r.Context(), id); err == nil && graph != nil {
			job.AttackGraph = graph
		}
	}

	writeJSON(w, http.StatusOK, job)
}

func (s *Server) runJob(id, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope) {
	releaseGlobal := s.acquireGlobalSlot(options)
	defer releaseGlobal()
	s.enforceTargetRateLimit(target, options)
	release := s.acquireTargetSlot(target, options)
	defer release()

	emit := s.eventBus.EmitterFor(id)
	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: "Scan job started",
	})

	job, err := s.repo.GetJob(context.Background(), id)
	if err != nil || job == nil {
		return
	}
	previousJob, _ := s.repo.GetLatestCompletedJobByTarget(context.Background(), target, id)
	persistedState, _ := s.repo.GetScanState(context.Background(), target)
	if persistedState != nil && len(persistedState.KnownRuntimeEndpoints) > 0 {
		options.SeedRuntimeEndpoints = mergeActions(options.SeedRuntimeEndpoints, persistedState.KnownRuntimeEndpoints)
		s.appendAuditEvent(id, "state", fmt.Sprintf("Loaded %d persisted runtime endpoints", len(persistedState.KnownRuntimeEndpoints)))
	}
	options = s.applySafetyModePolicy(options)
	options = s.tuneScanOptions(options, persistedState, previousJob)
	options, disabledForHealth := applyHealthAwareExecutionGating(options)
	if len(disabledForHealth) > 0 {
		s.appendAuditEvent(id, "health-gate", "Disabled degraded integrations: "+strings.Join(disabledForHealth, ", "))
	}
	if options.AutonomyEmergencyStop || len(options.AutonomyForceRunAgents) > 0 || len(options.AutonomySuppressAgents) > 0 || strings.TrimSpace(options.AutonomyPlannerLock) != "" || options.AutonomyFallbackRerun {
		s.appendAuditEvent(id, "override", fmt.Sprintf("Operator overrides applied emergencyStop=%t plannerLock=%s force=%s suppress=%s fallbackRerun=%t",
			options.AutonomyEmergencyStop,
			strings.TrimSpace(options.AutonomyPlannerLock),
			strings.Join(limitStrings(options.AutonomyForceRunAgents, 8), ","),
			strings.Join(limitStrings(options.AutonomySuppressAgents, 8), ","),
			options.AutonomyFallbackRerun,
		))
	}

	job.Status = "running"
	_ = s.repo.UpdateJob(context.Background(), job)
	s.appendAuditEvent(id, "running", "Scan execution started")

	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
	defer cancel()

	outputs, findings, err := s.runWithAuthProfiles(ctx, target, authProfile, roleProfiles, options, scanScope, persistedState, emit)
	completed := time.Now().UTC()

	job.CompletedAt = &completed
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: "Scan failed: " + err.Error(),
		})
		s.appendAuditEvent(id, "failed", "Scan execution failed: "+err.Error())
		_ = s.repo.UpdateJob(context.Background(), job)
		return
	}

	job.Status = "completed"
	job.Findings = enrichFindings(findings)
	job.Findings = s.applyFeedbackConfidencePrioritization(context.Background(), job.Findings)
	job.Findings = redactSensitiveFindings(job.Findings)
	job.Findings = append(job.Findings, buildToolReadinessFindings(options)...)
	job.Findings = append(job.Findings, buildIntegrationHealthFinding(outputs)...)
	job.Findings = s.applySuppressions(target, job.Findings)
	job.Findings = s.applyAutoSuppressionHeuristics(context.Background(), job.Findings)
	job.AgentRuns = buildAgentTelemetry(outputs)
	s.appendAuditEvent(id, "analysis", fmt.Sprintf("Collected %d deduplicated findings", len(findings)))
	s.appendAuditEvent(id, "telemetry", fmt.Sprintf("Captured telemetry for %d agents", len(job.AgentRuns)))
	if previousJob != nil {
		newItems, changedItems, resolvedItems, deltaFindings := buildDeltaFindings(previousJob.Findings, job.Findings)
		job.Findings = append(job.Findings, deltaFindings...)
		s.appendAuditEvent(id, "monitoring", fmt.Sprintf("Drift states: new=%d, changed=%d, resolved=%d", newItems, changedItems, resolvedItems))
	}
	if len(job.Findings) > len(findings) {
		s.appendAuditEvent(id, "monitoring", "Monitoring delta finding generated from previous completed scan")
	}
	assets := extractAssets(target, job.Findings)
	if err := s.repo.SaveAssets(context.Background(), id, assets); err == nil {
		job.Assets = assets
		s.appendAuditEvent(id, "inventory", fmt.Sprintf("Persisted %d inventory assets", len(assets)))
		if previousJob != nil {
			newAssets := diffAssets(previousJob.Assets, assets)
			if len(newAssets) > 0 {
				job.Findings = append(job.Findings, model.Finding{
					ID:             "asset-change-detected",
					Category:       "monitoring",
					Severity:       model.SeverityInfo,
					Title:          fmt.Sprintf("New assets observed since previous scan (%d)", len(newAssets)),
					Description:    "Continuous asset discovery detected new hosts/paths/services in scope.",
					Evidence:       strings.Join(limitStrings(newAssets, 8), "; "),
					Recommendation: "Prioritize deeper verification on newly discovered assets.",
					Confidence:     0.92,
					DriftStatus:    "new",
					Sources:        []string{"monitoring"},
					EvidenceFields: map[string]string{
						"validationType": "safe-observation",
						"reproStep":      "compare current vs previous asset inventory",
					},
				})
				s.appendAuditEvent(id, "asset-monitoring", fmt.Sprintf("Detected %d new assets", len(newAssets)))
				if shouldTriggerEventDrivenRescan(options) {
					s.appendAuditEvent(id, "scheduling", "Triggered event-driven deep rescan from asset change detection")
					go s.scheduleRescan(target, job.WorkspaceID, job.RequestedBy, authProfile, options, scanScope, 5*time.Minute)
				}
			}
		}
	}
	job.AssetLinks = extractAssetLinks(target, job.Assets, job.Findings)
	if len(job.AssetLinks) > 0 {
		s.appendAuditEvent(id, "inventory-graph", fmt.Sprintf("Built %d asset relationship links", len(job.AssetLinks)))
	}
	if s.attackGraphDB != nil {
		graph := attackgraph.Build(job)
		if err := s.attackGraphDB.SaveAttackGraph(context.Background(), id, target, graph); err == nil {
			job.AttackGraph = graph
			s.appendAuditEvent(id, "attack-graph", fmt.Sprintf("Persisted attack graph nodes=%d edges=%d", len(graph.Nodes), len(graph.Edges)))
		}
	}
	job.Dashboard = buildDecisionDashboard(job)
	knowledgeCtx := (*model.SecurityKnowledgeContext)(nil)
	if s.knowledgeSvc != nil {
		knowledgeCtx = s.knowledgeSvc.RetrieveForJob(context.Background(), "ai-summary", job, 5)
		if knowledgeCtx != nil {
			s.appendAuditEvent(id, "security-knowledge", fmt.Sprintf("Retrieved %d curated references", len(knowledgeCtx.References)))
		}
	}
	job.AISummary = s.aiClient.SummarizeWithKnowledge(context.Background(), target, job.Findings, knowledgeCtx)
	job.NextActions = buildNextActions(job)
	if s.mlService != nil {
		job.ModelRecommendations = s.mlService.RecommendFromHistory(context.Background(), s.repo, s.proxyServer.Store(), job)
		if job.ModelRecommendations != nil {
			job.NextActions = mergeActions(job.NextActions, job.ModelRecommendations.Copilot.SuggestedActions)
			s.appendAuditEvent(id, "ml-inference", fmt.Sprintf("ML mode=%s tools=%d prioritized=%d", job.ModelRecommendations.ModelMode, len(job.ModelRecommendations.ToolSelection), len(job.ModelRecommendations.PrioritizedFindings)))
		}
	}
	if knowledgeCtx != nil {
		if job.ModelRecommendations == nil {
			job.ModelRecommendations = &model.ModelRecommendations{ModelMode: "knowledge-retrieval"}
		}
		job.ModelRecommendations.SecurityKnowledge = knowledgeCtx
		job.NextActions = mergeActions(job.NextActions, knowledgeCtx.SuggestedActions)
	}
	expectedROI, roiBasis := s.estimateExpectedROI(context.Background(), job)
	minROI := s.effectiveMinROI(context.Background(), job)
	meetsROIGate := expectedROI >= minROI
	if job.Dashboard == nil {
		job.Dashboard = &model.DecisionDashboard{}
	}
	job.Dashboard.ExpectedROIUSD = roundTo2(expectedROI)
	job.Dashboard.ExpectedROIBasis = roiBasis
	job.Dashboard.MeetsROIGate = meetsROIGate
	job.NextActions = mergeActions(job.NextActions, []string{
		fmt.Sprintf("Review ROI gate: expected=$%.2f threshold=$%.2f mode=%s", expectedROI, minROI, normalizeAutomationMode(job.Options.AutomationMode)),
	})
	s.appendAuditEvent(id, "roi", fmt.Sprintf("ROI estimate expected=$%.2f threshold=$%.2f meets=%t basis=%s", expectedROI, minROI, meetsROIGate, roiBasis))
	policyGate := s.evaluatePolicyGate(job.Findings, job.PolicyPack)
	if strings.EqualFold(policyGate.Status, "blocked") {
		job.Findings = append(job.Findings, model.Finding{
			ID:          "policy-gate-blocked-release",
			Category:    "governance",
			Severity:    model.SeverityHigh,
			Title:       "Policy gate blocked automated release progression",
			Description: "Policy-as-code gate evaluated findings and marked this scan as blocked for automatic progression.",
			Evidence:    policyGate.Reason,
			Confidence:  1.0,
			Sources:     []string{"policy"},
		})
	}
	ticketTarget := target
	if strings.TrimSpace(job.WorkspaceID) != "" {
		ticketTarget = job.WorkspaceID + "::" + target
	}
	openTickets := 0
	resolvedTickets := 0
	if meetsROIGate {
		openTickets, resolvedTickets = s.syncAutomationTickets(ticketTarget, job.Findings)
	} else {
		s.appendAuditEvent(id, "ticketing", "Skipped automation ticket updates because ROI gate did not pass")
	}
	if openTickets > 0 || resolvedTickets > 0 {
		job.Findings = append(job.Findings, model.Finding{
			ID:          "automation-ticket-lifecycle",
			Category:    "operations",
			Severity:    model.SeverityInfo,
			Title:       "Automated ticket lifecycle updated",
			Description: "Ticketing loop automatically upserted current risk items and closed resolved fingerprints.",
			Evidence:    fmt.Sprintf("open=%d resolved=%d gate=%s", openTickets, resolvedTickets, policyGate.Status),
			Confidence:  0.96,
			Sources:     []string{"ticketing"},
		})
	}
	job.AutomatedReport = generateAutomatedReport(job)
	s.persistScanState(target, job.Findings, outputs, options)
	s.appendAuditEvent(id, "ai-summary", "AI summary generated")
	s.appendAuditEvent(id, "report", "Automated penetration testing report generated")
	_ = s.repo.UpdateJob(context.Background(), job)
	s.notifyFindings(job)
	// Teach the neural agent learner from this scan's results so future
	// scans benefit from accumulated knowledge about which agent sequences
	// produce the best findings.
	if s.agentLearner != nil {
		agentSeq := make([]string, 0, len(job.AgentRuns))
		for _, run := range job.AgentRuns {
			agentSeq = append(agentSeq, run.AgentName)
		}
		var scanDurationMs int64
		if job.CompletedAt != nil {
			scanDurationMs = job.CompletedAt.Sub(job.StartedAt).Milliseconds()
		}
		s.agentLearner.Learn(context.Background(), job.ID, agentSeq, job.Findings, scanDurationMs, job.AgentRuns)
	}
	s.appendAuditEvent(id, "completed", "Scan execution completed successfully")
	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: fmt.Sprintf("Scan completed: %d findings", len(job.Findings)),
	})
	// Retain event history for a short window so late-joining SSE clients can still
	// replay events, then schedule cleanup to free memory.
	go func() {
		time.Sleep(5 * time.Minute)
		s.eventBus.Cleanup(id)
	}()
	if job.Options.RescanIntervalMinutes > 0 {
		if meetsROIGate {
			s.appendAuditEvent(id, "scheduling", fmt.Sprintf("Scheduled rescan in %d minutes", job.Options.RescanIntervalMinutes))
			go s.scheduleRescan(target, job.WorkspaceID, job.RequestedBy, authProfile, options, scanScope, time.Duration(job.Options.RescanIntervalMinutes)*time.Minute)
		} else {
			s.appendAuditEvent(id, "scheduling", "Skipped scheduled rescan because ROI gate did not pass")
		}
	}
}

func (s *Server) newRegistry(options model.ScanOptions) *agent.Registry {
	reg := agent.NewRegistry()

	reg.Register(agent.NewReconnaissanceAgent(true))
	reg.Register(agent.NewScanningAgent(s.scanService, true))
	reg.Register(agent.NewInputValidationAgent(true))
	reg.Register(agent.NewInformationDisclosureAgent(true))
	reg.Register(agent.NewAccessControlAgent(true))
	reg.Register(agent.NewAPISecurityAgent(true))
	reg.Register(agent.NewCORSRedirectAgent(true))
	reg.Register(agent.NewWordlistAgent(true))
	reg.Register(agent.NewAnalysisAgent(true))

	// Autonomous tool-building agents — run after core scanning so they have
	// rich findings context to work from.  DynamicCommandAgent composes and
	// executes validated CLI tool invocations; ToolBuilderAgent writes and
	// runs custom Python probes for specialised tasks.
	reg.Register(agent.NewDynamicCommandAgent(true))
	reg.Register(agent.NewToolBuilderAgent(true))

	mlTriageEnabled := s.agentConfig.EnableMLTriageAgent && options.UseMLTriageAgent
	attackPathEnabled := s.agentConfig.EnableAttackPathAgent && options.UseAttackPathAgent
	falsePositiveEnabled := s.agentConfig.EnableFalsePositiveAgent && options.UseFalsePositiveReview
	remediationEnabled := s.agentConfig.EnableRemediationAgent && options.UseRemediationPlanner

	reg.Register(agent.NewMLTriageAgent(s.mlService, mlTriageEnabled))
	reg.Register(agent.NewAttackPathAgent(s.mlService, attackPathEnabled))
	reg.Register(agent.NewFalsePositiveReviewAgent(s.mlService, falsePositiveEnabled))
	reg.Register(agent.NewRemediationPlannerAgent(s.mlService, remediationEnabled))
	reg.Register(agent.NewReportingAgent(true))

	// Attach the neural learner as the autonomous spawner so it can augment
	// the static orchestration rules with learned Q-values.
	if s.agentLearner != nil {
		reg.SetSpawner(s.agentLearner)
	}

	return reg
}

func normalizeAndValidateTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", errors.New("target must be a valid absolute URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", errors.New("target scheme must be http or https")
	}
	u.Fragment = ""
	return u.String(), strings.ToLower(u.Hostname()), nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-API-Key,X-Workspace-ID,Idempotency-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleProxyRequests handles GET (list all) and DELETE (clear all) on /api/proxy/requests.
func (s *Server) handleProxyRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		reqs, err := s.proxyServer.Store().ListProxyRequests(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list proxy requests"})
			return
		}
		if reqs == nil {
			reqs = []*model.ProxyRequest{}
		}
		writeJSON(w, http.StatusOK, reqs)

	case http.MethodDelete:
		if err := s.proxyServer.Store().ClearProxyRequests(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear proxy requests"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleGetProxyRequest handles GET /api/proxy/requests/{id}.
func (s *Server) handleGetProxyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/proxy/requests/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing request id"})
		return
	}
	pr, err := s.proxyServer.Store().GetProxyRequest(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy request not found"})
		return
	}
	writeJSON(w, http.StatusOK, pr)
}

// handleProxyReplay handles POST /api/proxy/replay.
// Body: { "requestId": "...", "overrideHeaders": {"X-Custom":"val"}, "overrideBody": "..." }
// Sends the original captured request to its destination, applying any overrides,
// and returns the new captured request+response pair.
func (s *Server) handleProxyReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req model.ProxyReplayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.RequestID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestId is required"})
		return
	}
	if req.Scope != nil {
		original, err := s.proxyServer.Store().GetProxyRequest(r.Context(), req.RequestID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy request not found"})
			return
		}
		if !scope.IsURLInScope(original.URL, scope.Normalize(original.URL, *req.Scope)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "request is out of configured scope profile"})
			return
		}
	}

	replayed, err := s.proxyServer.Replay(r.Context(), req.RequestID, req.OverrideHeaders, req.OverrideBody)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, replayed)
}

func (s *Server) handleListMLEngagements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.mlService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ml service is not enabled"})
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	dataset, err := s.mlService.BuildTrainingDataset(r.Context(), s.repo, s.proxyServer.Store(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to build ml engagement dataset"})
		return
	}
	writeJSON(w, http.StatusOK, dataset)
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.ReportFeedback
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.Outcome = strings.ToLower(strings.TrimSpace(req.Outcome))
	if req.ScanID == "" || req.FindingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanId and findingId are required"})
		return
	}
	if req.Outcome != "accepted" && req.Outcome != "rejected" && req.Outcome != "duplicate" && req.Outcome != "informative" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "outcome must be one of accepted, rejected, duplicate, informative"})
		return
	}
	req.ID = uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	if job, err := s.repo.GetJob(r.Context(), req.ScanID); err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	if err := s.repo.SaveFeedback(r.Context(), req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist feedback"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "status": "recorded"})
}

func (s *Server) handleAutomationOperatorFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		ScanID          string `json:"scanId"`
		ActionID        string `json:"actionId"`
		SuggestedAction string `json:"suggestedAction"`
		Decision        string `json:"decision"`
		AgentName       string `json:"agentName"`
		Notes           string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.ActionID = strings.TrimSpace(req.ActionID)
	req.SuggestedAction = strings.TrimSpace(req.SuggestedAction)
	req.Decision = strings.ToLower(strings.TrimSpace(req.Decision))
	req.AgentName = strings.TrimSpace(req.AgentName)
	req.Notes = strings.TrimSpace(req.Notes)
	if req.ScanID == "" || req.Decision == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanId and decision are required"})
		return
	}
	if req.Decision != "approve" && req.Decision != "reject" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "decision must be approve or reject"})
		return
	}
	job, err := s.repo.GetJob(r.Context(), req.ScanID)
	if err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	actionID := req.ActionID
	if actionID == "" {
		actionID = uuid.NewString()
	}
	outcome := "rejected"
	if req.Decision == "approve" {
		outcome = "accepted"
	}
	notesJSON, _ := json.Marshal(map[string]string{
		"decision":        req.Decision,
		"agent":           req.AgentName,
		"actionId":        actionID,
		"suggestedAction": req.SuggestedAction,
		"notes":           req.Notes,
	})
	feedback := model.ReportFeedback{
		ID:          uuid.NewString(),
		ScanID:      req.ScanID,
		FindingID:   "autonomy-action:" + actionID,
		Category:    "autonomy-action",
		Title:       firstNonEmpty(req.SuggestedAction, "autonomous operator decision"),
		Outcome:     outcome,
		Notes:       string(notesJSON),
		CreatedAt:   time.Now().UTC(),
		ProgramName: strings.TrimSpace(job.ProgramName),
	}
	if err := s.repo.SaveFeedback(r.Context(), feedback); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist operator feedback"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": feedback.ID, "status": "recorded"})
}

func (s *Server) handleFindingVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.FindingVerification
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))
	if req.ScanID == "" || req.FindingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanId and findingId are required"})
		return
	}
	if req.Status != "confirmed" && req.Status != "rejected" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be confirmed or rejected"})
		return
	}
	req.ID = uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	if job, err := s.repo.GetJob(r.Context(), req.ScanID); err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	if err := s.repo.SaveFindingVerification(r.Context(), req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save verification"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "status": "recorded"})
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.SuppressionRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.Category = strings.TrimSpace(req.Category)
	req.Title = strings.TrimSpace(req.Title)
	if req.FindingID == "" && req.Category == "" && req.Title == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "one of findingId/category/title is required"})
		return
	}
	req.ID = uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	req.CreatedBy = requesterFromRequest(r)
	if err := s.repo.SaveSuppressionRule(r.Context(), req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save suppression"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "status": "recorded"})
}

func (s *Server) handleToolsHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"checkedAt": time.Now().UTC(),
		"tools":     collectToolHealth(),
	})
}

// handleToolsUpdates serves the JSON report produced by the `tool-updater`
// compose sidecar on every `docker compose up`. The sidecar refreshes the
// nuclei templates volume and queries GitHub Releases for every pinned
// tool listed in sidecars/tool-updater/manifest.json, then writes the
// result to TOOL_UPDATES_REPORT_PATH (mounted read-only into this
// container). We stream the file straight through to the client so the
// API stays in lock-step with the sidecar's schema without needing a Go
// type that has to be kept in sync.
//
// Status semantics:
//   - 200: report is on disk and well-formed JSON — returned verbatim.
//   - 503: report is not yet present (sidecar hasn't run or is still
//     working). Includes a hint pointing at the sidecar service.
//   - 500: the report file exists but couldn't be read or parsed.
func (s *Server) handleToolsUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	path := strings.TrimSpace(os.Getenv("TOOL_UPDATES_REPORT_PATH"))
	if path == "" {
		path = "/var/lib/auto-bughunter/updates/report.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "tool update report is not yet available",
				"hint":  "the tool-updater compose sidecar runs on every `docker compose up`; trigger manually via `docker compose run --rm tool-updater`",
			})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read tool update report"})
		return
	}
	// Validate that the file is JSON before returning it as such, so a
	// truncated/corrupt report doesn't get content-typed as
	// application/json with garbage in the body.
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tool update report is not valid JSON"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleAutomationEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.AutomationEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Type = strings.ToLower(strings.TrimSpace(req.Type))
	if req.Type == "" {
		req.Type = "deploy"
	}
	target, _, err := normalizeAndValidateTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target blocked by outbound safety policy"})
		return
	}
	if err := validateAuthProfile(req.AuthProfile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
		return
	}
	req.Options.DeepScanOnHighSignal = true
	req.Options.RescanIntervalMinutes = 0
	req.Options.AutomationMode = normalizeAutomationMode(req.Options.AutomationMode)
	req.Options = s.applySafetyModePolicy(req.Options)
	req.Options.MinExpectedROIUSD = maxFloat(req.Options.MinExpectedROIUSD, s.defaultMinROI)
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	if blocked, reason := s.shouldDeferForDailyBudget(r.Context(), workspaceID, req.Options); blocked {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": reason})
		return
	}
	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
		WorkspaceID:        workspaceID,
		RequestedBy:        requesterFromRequest(r),
		PolicyPack:         defaultPolicyPack(),
		Status:             "queued",
		StartedAt:          now,
		AuthProfileSummary: model.SummarizeAuthProfile(req.AuthProfile),
		Options:            req.Options,
		Scope:              req.Scope,
		ProgramName:        strings.TrimSpace(req.ProgramName),
	}
	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist automation scan job"})
		return
	}
	s.appendAuditEvent(jobID, "automation-event", "Event-driven scan queued: "+req.Type)
	if len(req.Assets) > 0 {
		s.appendAuditEvent(jobID, "asset-discovery", fmt.Sprintf("Auto-enrolled %d externally discovered assets", len(req.Assets)))
	}
	go s.runJob(jobID, target, req.AuthProfile, nil, req.Options, req.Scope)
	writeJSON(w, http.StatusAccepted, map[string]string{"id": jobID, "status": "queued", "eventType": req.Type})
}

func (s *Server) handleAutomationCampaigns(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		activeOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("activeOnly")), "true")
		items, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, activeOnly, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation campaigns"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		var req model.AutomationCampaignUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		target, _, err := normalizeAndValidateTarget(req.Target)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.IntervalMin < 5 || req.IntervalMin > 10080 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "intervalMin must be between 5 and 10080"})
			return
		}
		req.ScheduleType = normalizeScheduleType(req.ScheduleType)
		if err := validateCampaignSchedule(req.ScheduleType, req.ScheduleValue, req.RunWindow, req.BlackoutWindows); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := validateAuthProfile(req.AuthProfile); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Scope = scope.Normalize(target, req.Scope)
		if !scope.IsURLInScope(target, req.Scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
			return
		}
		now := time.Now().UTC()
		if strings.TrimSpace(req.ID) == "" {
			req.ID = uuid.NewString()
		}
		if r.Method == http.MethodPost {
			req.Active = true
		}
		req.Options.AutomationMode = normalizeAutomationMode(req.Options.AutomationMode)
		req.Options = s.applySafetyModePolicy(req.Options)
		req.PolicyPack = normalizePolicyPackName(req.PolicyPack)
		policyVersion := 0
		req.Options, policyVersion = s.applyAutomationPolicyPack(r.Context(), workspaceID, req.PolicyPack, req.Options)
		req.Options.MinExpectedROIUSD = maxFloat(req.Options.MinExpectedROIUSD, s.defaultMinROI)
		nextRunAt := computeNextCampaignRun(now, req)
		item := model.AutomationCampaign{
			ID:              req.ID,
			Target:          target,
			WorkspaceID:     workspaceID,
			RequestedBy:     requesterFromRequest(r),
			PolicyPack:      req.PolicyPack,
			PolicyVersion:   policyVersion,
			Name:            strings.TrimSpace(req.Name),
			ProgramName:     strings.TrimSpace(req.ProgramName),
			IntervalMin:     req.IntervalMin,
			ScheduleType:    req.ScheduleType,
			ScheduleValue:   strings.TrimSpace(req.ScheduleValue),
			RunWindow:       strings.TrimSpace(req.RunWindow),
			BlackoutWindows: req.BlackoutWindows,
			NextRunAt:       nextRunAt,
			MaxAttempts:     maxInt(3, req.MaxAttempts),
			Active:          req.Active,
			AuthProfile:     req.AuthProfile,
			Options:         req.Options,
			Scope:           req.Scope,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if item.PolicyPack == "" {
			item.PolicyPack = defaultPolicyPack()
		}
		if !req.Active {
			item.NextRunAt = time.Time{}
		}
		if err := s.repo.UpsertAutomationCampaign(r.Context(), item); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save automation campaign"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"id": item.ID, "status": "saved"})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id query parameter is required"})
			return
		}
		if err := s.repo.DeleteAutomationCampaign(r.Context(), id, workspaceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete automation campaign"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	jobs, err := s.repo.ListCompletedJobs(r.Context(), 500)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load completed jobs"})
		return
	}
	feedback, _ := s.repo.ListFeedback(r.Context(), 1000)
	openTickets, _ := s.repo.ListOpenAutomationTickets(r.Context(), "", 1000)

	report := model.ExecutiveReport{
		GeneratedAt:            time.Now().UTC(),
		AgentAcceptedRate:      map[string]float64{},
		AgentPayoutPerScanHour: map[string]float64{},
		AgentFalsePositiveRate: map[string]float64{},
		ROISparkline:           []float64{},
	}
	agentRuns := map[string]int{}
	agentScanHours := map[string]float64{}
	for _, job := range jobs {
		if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
			continue
		}
		report.TotalCompletedScans++
		if job.Dashboard != nil {
			report.AverageExpectedROIUSD += maxFloat(0, job.Dashboard.ExpectedROIUSD)
			if job.Dashboard.MeetsROIGate {
				report.HighROICompletedScans++
			}
			report.ROISparkline = append(report.ROISparkline, roundTo2(job.Dashboard.ExpectedROIUSD))
		}
		if job.CompletedAt != nil {
			durationHours := maxFloat(0.05, job.CompletedAt.Sub(job.StartedAt).Hours())
			for _, run := range job.AgentRuns {
				name := strings.TrimSpace(run.AgentName)
				if name == "" {
					continue
				}
				agentRuns[name]++
				agentScanHours[name] += durationHours
			}
		}
		for _, finding := range job.Findings {
			switch strings.ToLower(strings.TrimSpace(finding.DriftStatus)) {
			case "new":
				report.NewFindings++
			case "changed":
				report.ChangedFindings++
			case "resolved":
				report.ResolvedFindings++
			}
			if finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityMedium {
				report.HighOrMediumFindings++
			}
		}
	}
	ws := workspaceFromRequest(r)
	if ws == "" {
		report.OpenAutomationTickets = len(openTickets)
	} else {
		for _, ticket := range openTickets {
			if strings.HasPrefix(ticket.Target, ws+"::") {
				report.OpenAutomationTickets++
			}
		}
	}
	for _, item := range feedback {
		switch strings.ToLower(strings.TrimSpace(item.Outcome)) {
		case "accepted":
			report.AcceptedFeedback++
		case "rejected":
			report.RejectedFeedback++
		case "duplicate":
			report.DuplicateFeedback++
		}
	}
	if report.TotalCompletedScans > 0 {
		report.AverageExpectedROIUSD /= float64(report.TotalCompletedScans)
	}
	acceptedPayout := 0.0
	for _, item := range feedback {
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			acceptedPayout += maxFloat(0, item.PayoutUSD)
		}
	}
	if report.TotalCompletedScans > 0 {
		report.AcceptedPayoutPerScanUSD = acceptedPayout / float64(report.TotalCompletedScans)
	}
	acceptedRate := 0.0
	if totalReviewed := report.AcceptedFeedback + report.RejectedFeedback + report.DuplicateFeedback; totalReviewed > 0 {
		acceptedRate = float64(report.AcceptedFeedback) / float64(totalReviewed)
	}
	totalReviewed := report.AcceptedFeedback + report.RejectedFeedback + report.DuplicateFeedback
	if totalReviewed > 0 {
		report.FalsePositiveRate = float64(report.RejectedFeedback+report.DuplicateFeedback) / float64(totalReviewed)
	}
	for agentName, runs := range agentRuns {
		hours := maxFloat(0.1, agentScanHours[agentName])
		report.AgentAcceptedRate[agentName] = roundTo2(acceptedRate)
		report.AgentPayoutPerScanHour[agentName] = roundTo2(acceptedPayout / hours)
		report.AgentFalsePositiveRate[agentName] = roundTo2(report.FalsePositiveRate)
		if runs == 0 {
			delete(report.AgentAcceptedRate, agentName)
			delete(report.AgentPayoutPerScanHour, agentName)
			delete(report.AgentFalsePositiveRate, agentName)
		}
	}
	_ = openTickets
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAutomationROIOverrides(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.repo.ListProgramROIOverrides(r.Context(), workspaceID, 500)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list roi overrides"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		var req struct {
			ProgramName       string  `json:"programName"`
			MinExpectedROIUSD float64 `json:"minExpectedRoiUsd"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if strings.TrimSpace(req.ProgramName) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "programName is required"})
			return
		}
		item := model.ProgramROIOverride{
			WorkspaceID:       workspaceID,
			ProgramName:       strings.TrimSpace(req.ProgramName),
			MinExpectedROIUSD: maxFloat(0, req.MinExpectedROIUSD),
			UpdatedAt:         time.Now().UTC(),
		}
		if err := s.repo.UpsertProgramROIOverride(r.Context(), item); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save roi override"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "saved"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationTickets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if ws := workspaceFromRequest(r); ws != "" && target != "" {
		target = ws + "::" + target
	}
	tickets, err := s.repo.ListOpenAutomationTickets(r.Context(), target, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation tickets"})
		return
	}
	if ws := workspaceFromRequest(r); ws != "" {
		filtered := make([]model.AutomationTicket, 0, len(tickets))
		for _, ticket := range tickets {
			if strings.HasPrefix(ticket.Target, ws+"::") {
				ticket.Target = strings.TrimPrefix(ticket.Target, ws+"::")
				filtered = append(filtered, ticket)
			}
		}
		writeJSON(w, http.StatusOK, filtered)
		return
	}
	writeJSON(w, http.StatusOK, tickets)
}

func normalizePolicyPackName(raw string) string {
	pack := strings.ToLower(strings.TrimSpace(raw))
	if pack == "" {
		return defaultPolicyPack()
	}
	return pack
}

func (s *Server) applyAutomationPolicyPack(ctx context.Context, workspaceID, packName string, options model.ScanOptions) (model.ScanOptions, int) {
	packName = normalizePolicyPackName(packName)
	pack, err := s.repo.GetAutomationPolicyPack(ctx, firstNonEmpty(workspaceID, "default"), packName)
	if err != nil || pack == nil {
		return options, 0
	}
	if mode := normalizeAutomationMode(pack.AutomationMode); mode != "" {
		options.AutomationMode = mode
	}
	options.MinExpectedROIUSD = maxFloat(options.MinExpectedROIUSD, pack.MinExpectedROIUSD)
	if pack.MaxAutomationConcurrency > 0 {
		if options.MaxAutomationConcurrency <= 0 {
			options.MaxAutomationConcurrency = pack.MaxAutomationConcurrency
		} else {
			options.MaxAutomationConcurrency = minInt(options.MaxAutomationConcurrency, pack.MaxAutomationConcurrency)
		}
	}
	if pack.MaxPerTargetConcurrency > 0 {
		if options.MaxPerTargetConcurrency <= 0 {
			options.MaxPerTargetConcurrency = pack.MaxPerTargetConcurrency
		} else {
			options.MaxPerTargetConcurrency = minInt(options.MaxPerTargetConcurrency, pack.MaxPerTargetConcurrency)
		}
	}
	if pack.MaxExploitAttempts >= 0 {
		if options.MaxExploitAttempts <= 0 {
			options.MaxExploitAttempts = pack.MaxExploitAttempts
		} else {
			options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, pack.MaxExploitAttempts)
		}
	}
	if pack.DailyScanLimit > 0 {
		if options.DailyScanLimit <= 0 {
			options.DailyScanLimit = pack.DailyScanLimit
		} else {
			options.DailyScanLimit = minInt(options.DailyScanLimit, pack.DailyScanLimit)
		}
	}
	if pack.DailyRuntimeLimitMinutes > 0 {
		if options.DailyRuntimeLimitMinutes <= 0 {
			options.DailyRuntimeLimitMinutes = pack.DailyRuntimeLimitMinutes
		} else {
			options.DailyRuntimeLimitMinutes = minInt(options.DailyRuntimeLimitMinutes, pack.DailyRuntimeLimitMinutes)
		}
	}
	if pack.DailyProbeLimit > 0 {
		if options.DailyProbeLimit <= 0 {
			options.DailyProbeLimit = pack.DailyProbeLimit
		} else {
			options.DailyProbeLimit = minInt(options.DailyProbeLimit, pack.DailyProbeLimit)
		}
	}
	options = applyGovernancePolicy(options, pack.GovernanceProfile)
	return options, maxInt(1, pack.StrategyVersion)
}

func applyGovernancePolicy(options model.ScanOptions, governance model.AutonomyGovernanceProfile) model.ScanOptions {
	if governance.FailureHandling.MaxNoNoveltyRounds > 0 {
		options.AutonomyMaxNoNoveltyRounds = governance.FailureHandling.MaxNoNoveltyRounds
	}
	if governance.FailureHandling.MaxConsecutiveFailureRounds > 0 {
		options.AutonomyMaxConsecutiveFailRounds = governance.FailureHandling.MaxConsecutiveFailureRounds
	}
	if governance.FailureHandling.BackoffMillis > 0 {
		options.BackoffMillis = maxInt(options.BackoffMillis, governance.FailureHandling.BackoffMillis)
	}
	if governance.FailureHandling.AutoRetryOnFailure {
		options.AutonomyFallbackRerun = true
	}
	if lock := strings.ToLower(strings.TrimSpace(governance.FailureHandling.FallbackPlanner)); lock == "static" || lock == "fallback" || lock == "ai" {
		if strings.TrimSpace(options.AutonomyPlannerLock) == "" {
			options.AutonomyPlannerLock = lock
		}
	}
	if governance.MemoryPolicy.RetentionDays > 0 {
		options.AutonomyMemoryRetentionDays = governance.MemoryPolicy.RetentionDays
	}
	if governance.RiskMatrix.RetryLimit > 0 {
		if options.MaxRetries <= 0 {
			options.MaxRetries = governance.RiskMatrix.RetryLimit
		} else {
			options.MaxRetries = minInt(options.MaxRetries, governance.RiskMatrix.RetryLimit)
		}
	}
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	if stage == "" {
		stage = "dev"
	}
	if criteria, ok := governance.SuccessCriteria[stage]; ok {
		marginal := criteria.NovelFindingsRateMin
		if criteria.FalsePositiveRateMax > 0 {
			marginal *= maxFloat(0.1, 1.0-criteria.FalsePositiveRateMax*0.5)
		}
		if marginal > 0 {
			options.AutonomyMinMarginalScore = maxFloat(options.AutonomyMinMarginalScore, minFloat(0.95, marginal))
		}
	}
	if governance.RolloutControl.CanaryPercentByStage != nil {
		if p, ok := governance.RolloutControl.CanaryPercentByStage[stage]; ok {
			p = maxInt(0, minInt(100, p))
			if p == 0 {
				options.MaxAutomationConcurrency = 1
				options.AutonomyExplorationBudgetPercent = 0
			} else {
				options.AutonomyExplorationBudgetPercent = maxInt(options.AutonomyExplorationBudgetPercent, minInt(25, maxInt(5, p/4)))
			}
		}
	}
	if !governance.OperatorOverride.AllowForceRun {
		options.AutonomyForceRunAgents = nil
	}
	if !governance.OperatorOverride.AllowSuppress {
		options.AutonomySuppressAgents = nil
	}
	if !governance.OperatorOverride.AllowPlannerLock {
		options.AutonomyPlannerLock = ""
	}
	if !governance.OperatorOverride.AllowFallbackRerun {
		options.AutonomyFallbackRerun = false
	}
	if !governance.OperatorOverride.AllowEmergencyStop {
		options.AutonomyEmergencyStop = false
	}
	return options
}

func validateGovernanceProfile(profile model.AutonomyGovernanceProfile) error {
	for env, c := range profile.SuccessCriteria {
		if strings.TrimSpace(env) == "" {
			return errors.New("successCriteria environment key is required")
		}
		if c.NovelFindingsRateMin < 0 || c.NovelFindingsRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].novelFindingsRateMin must be between 0 and 1", env)
		}
		if c.FalsePositiveRateMax < 0 || c.FalsePositiveRateMax > 1 {
			return fmt.Errorf("successCriteria[%s].falsePositiveRateMax must be between 0 and 1", env)
		}
		if c.DuplicateSuppressionRateMin < 0 || c.DuplicateSuppressionRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].duplicateSuppressionRateMin must be between 0 and 1", env)
		}
		if c.FailureRecoveryRateMin < 0 || c.FailureRecoveryRateMin > 1 {
			return fmt.Errorf("successCriteria[%s].failureRecoveryRateMin must be between 0 and 1", env)
		}
		if c.ScanDurationCapMinutes < 0 {
			return fmt.Errorf("successCriteria[%s].scanDurationCapMinutes must be >= 0", env)
		}
	}
	if profile.RiskMatrix.RetryLimit < 0 {
		return errors.New("riskMatrix.retryLimit must be >= 0")
	}
	if profile.FailureHandling.BackoffMillis < 0 ||
		profile.FailureHandling.MaxNoNoveltyRounds < 0 ||
		profile.FailureHandling.MaxConsecutiveFailureRounds < 0 ||
		profile.FailureHandling.PauseForOperatorAfterFailures < 0 {
		return errors.New("failureHandling numeric values must be >= 0")
	}
	if profile.MemoryPolicy.RetentionDays < 0 {
		return errors.New("memoryPolicy.retentionDays must be >= 0")
	}
	if profile.EvaluationGate.MinKPIDeltaScore < 0 {
		return errors.New("evaluationGate.minKpiDeltaScore must be >= 0")
	}
	for stage, pct := range profile.RolloutControl.CanaryPercentByStage {
		if strings.TrimSpace(stage) == "" {
			return errors.New("rolloutControl.canaryPercentByStage stage key is required")
		}
		if pct < 0 || pct > 100 {
			return fmt.Errorf("rolloutControl.canaryPercentByStage[%s] must be between 0 and 100", stage)
		}
	}
	return nil
}

func (s *Server) handleAutomationPolicyPacks(w http.ResponseWriter, r *http.Request) {
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.repo.ListAutomationPolicyPacks(r.Context(), workspaceID, 200)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policy packs"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost, http.MethodPut:
		if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		var req model.AutomationPolicyPack
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		req.WorkspaceID = workspaceID
		req.Name = normalizePolicyPackName(req.Name)
		req.UpdatedBy = requesterFromRequest(r)
		if req.StrategyVersion <= 0 {
			req.StrategyVersion = 1
		}
		if err := validateGovernanceProfile(req.GovernanceProfile); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		before, _ := s.repo.GetAutomationPolicyPack(r.Context(), workspaceID, req.Name)
		req.UpdatedAt = time.Now().UTC()
		if err := s.repo.UpsertAutomationPolicyPack(r.Context(), req); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save policy pack"})
			return
		}
		after, _ := json.Marshal(req)
		beforeJSON := ""
		if before != nil {
			if b, err := json.Marshal(before); err == nil {
				beforeJSON = string(b)
			}
		}
		_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
			ID:              uuid.NewString(),
			WorkspaceID:     workspaceID,
			PolicyPack:      req.Name,
			StrategyVersion: req.StrategyVersion,
			Action:          "upsert",
			ChangedBy:       requesterFromRequest(r),
			ChangedAt:       time.Now().UTC(),
			BeforeJSON:      beforeJSON,
			AfterJSON:       string(after),
		})
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "saved"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAutomationPolicyAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	pack := normalizePolicyPackName(r.URL.Query().Get("policyPack"))
	if strings.TrimSpace(r.URL.Query().Get("policyPack")) == "" {
		pack = ""
	}
	items, err := s.repo.ListAutomationPolicyAudit(r.Context(), workspaceID, pack, 300)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list policy audit"})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleAutomationMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	campaigns, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, false, 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load campaigns"})
		return
	}
	now := time.Now().UTC()
	lagSum := 0.0
	lagCount := 0
	maxLag := 0.0
	retrying := 0
	dlq := 0
	for _, c := range campaigns {
		if c.DeadLetter {
			dlq++
		}
		if c.RetryCount > 0 {
			retrying++
		}
		dueAt := c.NextRunAt
		if c.NextRetryAt != nil && !c.NextRetryAt.IsZero() {
			dueAt = *c.NextRetryAt
		}
		if !dueAt.IsZero() && dueAt.Before(now) {
			lag := now.Sub(dueAt).Seconds()
			lagSum += lag
			lagCount++
			maxLag = maxFloat(maxLag, lag)
		}
	}
	jobs, _ := s.repo.ListCompletedJobs(r.Context(), 1000)
	strategyROI := map[string]float64{}
	strategyCounts := map[string]int{}
	failedRuns := 0
	totalRuns := 0
	for _, job := range jobs {
		if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
			continue
		}
		strategy := normalizePolicyPackName(job.PolicyPack)
		if strategy == "" {
			strategy = "internal"
		}
		if job.Dashboard != nil {
			strategyROI[strategy] += maxFloat(0, job.Dashboard.ExpectedROIUSD)
		}
		strategyCounts[strategy]++
		for _, run := range job.AgentRuns {
			totalRuns++
			if strings.EqualFold(strings.TrimSpace(run.Status), "failed") || run.TimedOut {
				failedRuns++
			}
		}
	}
	for name, total := range strategyCounts {
		if total > 0 {
			strategyROI[name] = roundTo2(strategyROI[name] / float64(total))
		}
	}
	avgLag := 0.0
	if lagCount > 0 {
		avgLag = lagSum / float64(lagCount)
	}
	retryRate := 0.0
	if len(campaigns) > 0 {
		retryRate = float64(retrying) / float64(len(campaigns))
	}
	toolFailureRate := 0.0
	if totalRuns > 0 {
		toolFailureRate = float64(failedRuns) / float64(totalRuns)
	}
	alerts := make([]string, 0)
	if avgLag > float64(maxInt(60, intFromEnv("AUTOMATION_ALERT_QUEUE_LAG_SECONDS", 300))) {
		alerts = append(alerts, "queue lag exceeded threshold")
	}
	if retryRate > floatFromEnv("AUTOMATION_ALERT_RETRY_RATE", 0.35) {
		alerts = append(alerts, "retry rate exceeded threshold")
	}
	if dlq > maxInt(0, intFromEnv("AUTOMATION_ALERT_DLQ_COUNT", 5)) {
		alerts = append(alerts, "dead-letter queue size exceeded threshold")
	}
	if toolFailureRate > floatFromEnv("AUTOMATION_ALERT_TOOL_FAILURE_RATE", 0.25) {
		alerts = append(alerts, "tool failure rate exceeded threshold")
	}
	writeJSON(w, http.StatusOK, model.AutomationMetrics{
		GeneratedAt:       now,
		WorkspaceID:       workspaceID,
		QueueLagSeconds:   roundTo2(avgLag),
		MaxQueueLag:       roundTo2(maxLag),
		RetryRate:         roundTo2(retryRate),
		DLQCount:          dlq,
		ToolFailureRate:   roundTo2(toolFailureRate),
		ROIByStrategy:     strategyROI,
		StrategyRunCounts: strategyCounts,
		Alerts:            alerts,
		Extra: map[string]float64{
			"lagSamples": float64(lagCount),
			"agentRuns":  float64(totalRuns),
		},
	})
}

func (s *Server) handleAutomationRebalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	var req struct {
		PolicyPack     string  `json:"policyPack"`
		CanaryPercent  int     `json:"canaryPercent"`
		Rollback       bool    `json:"rollback"`
		ExpectedMinROI float64 `json:"expectedMinRoiUsd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	packName := normalizePolicyPackName(req.PolicyPack)
	pack, err := s.repo.GetAutomationPolicyPack(r.Context(), workspaceID, packName)
	if err != nil || pack == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy pack not found"})
		return
	}
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	if stage == "" {
		stage = "dev"
	}
	if stage == "prod" &&
		pack.GovernanceProfile.EvaluationGate.PromoteToProdOnlyIfPass &&
		pack.GovernanceProfile.EvaluationGate.RequireReplayBenchmark {
		passed, delta, benchErr := s.runReplayBenchmark(r.Context(), workspaceID, pack.GovernanceProfile.EvaluationGate.MinKPIDeltaScore)
		if benchErr != nil {
			writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": "replay benchmark approval is required for production promotion"})
			return
		}
		if !passed {
			writeJSON(w, http.StatusPreconditionFailed, map[string]string{
				"error": "replay benchmark did not meet minimum KPI delta score",
				"delta": fmt.Sprintf("%.3f", delta),
			})
			return
		}
	}
	beforeRaw, _ := json.Marshal(pack)
	next := *pack
	if req.Rollback {
		next.CanaryPercent = 0
	} else {
		next.StrategyVersion = maxInt(1, next.StrategyVersion+1)
		nextCanary := maxInt(0, minInt(100, req.CanaryPercent))
		if stageCanary, ok := next.GovernanceProfile.RolloutControl.CanaryPercentByStage[stage]; ok {
			nextCanary = minInt(nextCanary, maxInt(0, minInt(100, stageCanary)))
		}
		next.CanaryPercent = nextCanary
		if req.ExpectedMinROI > 0 {
			next.MinExpectedROIUSD = maxFloat(next.MinExpectedROIUSD, req.ExpectedMinROI)
		}
	}
	next.UpdatedBy = requesterFromRequest(r)
	next.UpdatedAt = time.Now().UTC()
	if err := s.repo.UpsertAutomationPolicyPack(r.Context(), next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update policy pack"})
		return
	}
	afterRaw, _ := json.Marshal(next)
	action := "rebalance"
	if req.Rollback {
		action = "rollback"
	}
	_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
		ID:              uuid.NewString(),
		WorkspaceID:     workspaceID,
		PolicyPack:      packName,
		StrategyVersion: next.StrategyVersion,
		Action:          action,
		ChangedBy:       requesterFromRequest(r),
		ChangedAt:       time.Now().UTC(),
		BeforeJSON:      string(beforeRaw),
		AfterJSON:       string(afterRaw),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":          "updated",
		"policyPack":      packName,
		"strategyVersion": next.StrategyVersion,
		"canaryPercent":   next.CanaryPercent,
		"rollback":        req.Rollback,
	})
}

func (s *Server) runReplayBenchmark(ctx context.Context, workspaceID string, minDelta float64) (bool, float64, error) {
	jobs, err := s.repo.ListCompletedJobs(ctx, 500)
	if err != nil {
		return false, 0, err
	}
	total := 0.0
	count := 0
	for _, job := range jobs {
		if firstNonEmpty(job.WorkspaceID, "default") != firstNonEmpty(workspaceID, "default") {
			continue
		}
		runScore := 0.0
		runCount := 0
		for _, run := range job.AgentRuns {
			if run.Metadata == nil {
				continue
			}
			raw := strings.TrimSpace(run.Metadata["decision_quality_score"])
			if raw == "" {
				continue
			}
			parsed, parseErr := strconv.ParseFloat(raw, 64)
			if parseErr != nil {
				continue
			}
			runScore += clampFloat(parsed, 0, 1)
			runCount++
		}
		if runCount == 0 {
			continue
		}
		total += runScore / float64(runCount)
		count++
		if count >= 100 {
			break
		}
	}
	if count == 0 {
		return false, 0, fmt.Errorf("no replay data")
	}
	avg := total / float64(count)
	delta := avg - 0.5
	return delta >= minDelta, delta, nil
}

func (s *Server) evaluatePolicyGate(findings []model.Finding, policyPack string) model.PolicyGateResult {
	highBlock := s.gateHighBlock
	medBlock := s.gateMedBlock
	switch strings.ToLower(strings.TrimSpace(policyPack)) {
	case "regulated":
		highBlock = 0
		medBlock = 1
	case "bugbounty":
		highBlock = maxInt(1, s.gateHighBlock)
		medBlock = maxInt(2, s.gateMedBlock)
	}
	result := model.PolicyGateResult{
		Status:      "pass",
		GeneratedAt: time.Now().UTC(),
	}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityHigh:
			result.HighCount++
			result.BlockedFindings = append(result.BlockedFindings, f.Title)
		case model.SeverityMedium:
			result.MediumCount++
		}
	}
	if result.HighCount >= highBlock || result.MediumCount >= medBlock {
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s high=%d medium=%d exceeded thresholds high>=%d or medium>=%d", strings.TrimSpace(policyPack), result.HighCount, result.MediumCount, highBlock, medBlock)
	} else {
		result.Reason = fmt.Sprintf("policy_pack=%s thresholds satisfied", strings.TrimSpace(policyPack))
	}
	return result
}

func (s *Server) tuneScanOptions(options model.ScanOptions, state *model.PersistentScanState, previous *model.ScanJob) model.ScanOptions {
	if previous != nil && previous.Dashboard != nil && previous.Dashboard.CoverageCompletenessScore < coverageLowThreshold {
		options.CrawlMaxPages = maxInt(options.CrawlMaxPages, coverageLowCrawlBoostPages)
	}
	if previous != nil && previous.Dashboard != nil {
		if previous.Dashboard.MeetsROIGate && previous.Dashboard.ExpectedROIUSD > s.defaultMinROI*highROIMultiplierForDeepScan {
			options.DeepScanOnHighSignal = true
			options.UseNucleiIntegration = true
			options.UseFFUFIntegration = true
		}
		if !previous.Dashboard.MeetsROIGate {
			options.UseSQLMapIntegration = false
			options.CrawlMaxPages = minInt(maxInt(options.CrawlMaxPages, lowROICrawlFloorPages), lowROICrawlCeilingPages)
		}
	}
	if state != nil && state.SessionInstability > 2 {
		options.UseNucleiIntegration = false
		options.UseSQLMapIntegration = false
		options.UseFFUFIntegration = false
	}
	return options
}

func normalizeAutomationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "safe", "aggressive", "autonomous":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "autonomous"
	}
}

func normalizeScheduleType(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "daily", "weekly", "cron":
		return strings.ToLower(strings.TrimSpace(kind))
	default:
		return "interval"
	}
}

func parseScheduleValueAndLocation(raw string) (string, *time.Location, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", time.UTC, nil
	}
	if !strings.Contains(value, "|") {
		return value, time.UTC, nil
	}
	parts := strings.SplitN(value, "|", 2)
	tz := strings.TrimSpace(parts[0])
	inner := strings.TrimSpace(parts[1])
	if tz == "" {
		return inner, time.UTC, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return "", nil, fmt.Errorf("invalid schedule timezone")
	}
	return inner, loc, nil
}

func validateCampaignSchedule(scheduleType, scheduleValue, runWindow string, blackoutWindows []string) error {
	inner, _, err := parseScheduleValueAndLocation(scheduleValue)
	if err != nil {
		return err
	}
	if strings.TrimSpace(runWindow) != "" && !validWindowSpec(runWindow) {
		return fmt.Errorf("runWindow must use HH:MM-HH:MM format")
	}
	for _, win := range blackoutWindows {
		if strings.TrimSpace(win) != "" && !validWindowSpec(win) {
			return fmt.Errorf("blackoutWindows must use HH:MM-HH:MM format")
		}
	}
	switch normalizeScheduleType(scheduleType) {
	case "daily":
		if _, _, ok := parseClock(inner); !ok {
			return fmt.Errorf("daily scheduleValue must use HH:MM (optionally TZ|HH:MM)")
		}
	case "weekly":
		raw := strings.Split(inner, "@")
		if len(raw) != 2 {
			return fmt.Errorf("weekly scheduleValue must use weekday@HH:MM (optionally TZ|weekday@HH:MM)")
		}
		weekday := strings.ToLower(strings.TrimSpace(raw[0]))
		if weekday != "sun" && weekday != "mon" && weekday != "tue" && weekday != "wed" && weekday != "thu" && weekday != "fri" && weekday != "sat" {
			return fmt.Errorf("weekly scheduleValue must use sun|mon|tue|wed|thu|fri|sat")
		}
		if _, _, ok := parseClock(raw[1]); !ok {
			return fmt.Errorf("weekly scheduleValue must use weekday@HH:MM")
		}
	case "cron":
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(strings.TrimSpace(inner)); err != nil {
			return fmt.Errorf("cron scheduleValue must be a 5-field cron expression (optionally TZ|expr)")
		}
	}
	return nil
}

func validWindowSpec(spec string) bool {
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) != 2 {
		return false
	}
	_, _, okS := parseClock(parts[0])
	_, _, okE := parseClock(parts[1])
	return okS && okE
}

func (s *Server) effectiveMinROI(ctx context.Context, job *model.ScanJob) float64 {
	if job == nil {
		return s.defaultMinROI
	}
	options := job.Options
	minROI := s.defaultMinROI
	if options.MinExpectedROIUSD > 0 {
		minROI = options.MinExpectedROIUSD
	}
	if override, err := s.repo.GetProgramROIOverride(ctx, firstNonEmpty(job.WorkspaceID, "default"), strings.TrimSpace(job.ProgramName)); err == nil && override != nil {
		minROI = maxFloat(minROI, override.MinExpectedROIUSD)
	}
	switch normalizeAutomationMode(options.AutomationMode) {
	case "safe":
		minROI = maxFloat(minROI, s.defaultMinROI*1.5)
	case "aggressive":
		minROI = maxFloat(0, minROI*0.6)
	}
	return minROI
}

func (s *Server) applySafetyModePolicy(options model.ScanOptions) model.ScanOptions {
	stage := strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_ENV_STAGE")))
	isProductionLike := stage == "prod" || stage == "production" || stage == "staging"
	switch normalizeAutomationMode(options.AutomationMode) {
	case "safe":
		options.MaxExploitAttempts = 0
		options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
		options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(60, options.MinRescanIntervalMinutes))
		options.AggressiveExploitation = false
	case "aggressive":
		options.MaxExploitAttempts = maxInt(options.MaxExploitAttempts, 5)
		options.MaxPerTargetConcurrency = maxInt(options.MaxPerTargetConcurrency, 3)
		options.MaxAutomationConcurrency = maxInt(options.MaxAutomationConcurrency, 4)
		options.RescanIntervalMinutes = maxInt(15, options.RescanIntervalMinutes)
	default:
		options.MaxExploitAttempts = maxInt(options.MaxExploitAttempts, 1)
		options.MaxPerTargetConcurrency = maxInt(options.MaxPerTargetConcurrency, 2)
		options.MaxAutomationConcurrency = maxInt(options.MaxAutomationConcurrency, 2)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(30, options.MinRescanIntervalMinutes))
		if isProductionLike {
			options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, 1)
			options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
			options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		}
	}
	options.DailyScanLimit = maxInt(options.DailyScanLimit, s.defaultDailyScanLimit)
	options.DailyRuntimeLimitMinutes = maxInt(options.DailyRuntimeLimitMinutes, s.defaultDailyRuntimeMinutes)
	options.DailyProbeLimit = maxInt(options.DailyProbeLimit, s.defaultDailyProbeLimit)
	options.CrawlMaxPages = maxInt(options.CrawlMaxPages, 50)
	return options
}

func (s *Server) shouldDeferForDailyBudget(ctx context.Context, workspaceID string, options model.ScanOptions) (bool, string) {
	usage, err := s.repo.GetWorkspaceDailyUsage(ctx, firstNonEmpty(workspaceID, "default"), time.Now().UTC())
	if err != nil {
		return false, ""
	}
	if options.DailyScanLimit > 0 && usage.ScanCount >= options.DailyScanLimit {
		return true, fmt.Sprintf("daily scan budget exceeded (%d/%d)", usage.ScanCount, options.DailyScanLimit)
	}
	if options.DailyRuntimeLimitMinutes > 0 && usage.RuntimeMinutes >= options.DailyRuntimeLimitMinutes {
		return true, fmt.Sprintf("daily runtime budget exceeded (%d/%d minutes)", usage.RuntimeMinutes, options.DailyRuntimeLimitMinutes)
	}
	if options.DailyProbeLimit > 0 && usage.ProbeVolume >= options.DailyProbeLimit {
		return true, fmt.Sprintf("daily probe budget exceeded (%d/%d)", usage.ProbeVolume, options.DailyProbeLimit)
	}
	return false, ""
}

func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}

func (s *Server) estimateExpectedROI(ctx context.Context, job *model.ScanJob) (float64, string) {
	if job == nil {
		return 0, "no-job"
	}
	feedback, err := s.repo.ListFeedback(ctx, 1000)
	if err != nil {
		feedback = nil
	}
	type feedbackAgg struct {
		total    int
		accepted int
		payout   float64
	}
	byKey := map[string]feedbackAgg{}
	globalAccepted := 0
	globalPayout := 0.0
	for _, item := range feedback {
		key := strings.ToLower(strings.TrimSpace(item.Category)) + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		cur := byKey[key]
		cur.total++
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			cur.accepted++
			cur.payout += maxFloat(0, item.PayoutUSD)
			globalAccepted++
			globalPayout += maxFloat(0, item.PayoutUSD)
		}
		byKey[key] = cur
	}
	globalAvgPayout := 120.0
	if globalAccepted > 0 {
		globalAvgPayout = globalPayout / float64(globalAccepted)
	}
	expected := 0.0
	for _, f := range job.Findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium && f.Severity != model.SeverityLow {
			continue
		}
		severityImpact := 20.0
		switch f.Severity {
		case model.SeverityHigh:
			severityImpact = 550
		case model.SeverityMedium:
			severityImpact = 220
		case model.SeverityLow:
			severityImpact = 60
		}
		conf := f.Confidence
		if conf <= 0 {
			conf = 0.6
		}
		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		agg := byKey[key]
		hitRate := 0.35
		avgPayout := globalAvgPayout
		if agg.total > 0 {
			hitRate = float64(agg.accepted+1) / float64(agg.total+2)
		}
		if agg.accepted > 0 {
			avgPayout = agg.payout / float64(agg.accepted)
		}
		expected += (severityImpact*0.25 + avgPayout*0.75) * conf * hitRate
	}
	return maxFloat(0, roundTo2(expected)), "severity+confidence+historical-payout"
}

func (s *Server) applyAutoSuppressionHeuristics(ctx context.Context, findings []model.Finding) []model.Finding {
	feedback, err := s.repo.ListFeedback(ctx, 1000)
	if err != nil || len(feedback) == 0 || len(findings) == 0 {
		return findings
	}
	type agg struct {
		total    int
		accepted int
		payout   float64
	}
	signals := map[string]agg{}
	for _, item := range feedback {
		key := strings.ToLower(strings.TrimSpace(item.Category)) + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		cur := signals[key]
		cur.total++
		if strings.EqualFold(strings.TrimSpace(item.Outcome), "accepted") {
			cur.accepted++
			cur.payout += maxFloat(0, item.PayoutUSD)
		}
		signals[key] = cur
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == model.SeverityHigh || f.Severity == model.SeverityMedium {
			out = append(out, f)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		agg := signals[key]
		if agg.total < 3 {
			out = append(out, f)
			continue
		}
		acceptRate := float64(agg.accepted) / float64(agg.total)
		avgPayout := 0.0
		if agg.accepted > 0 {
			avgPayout = agg.payout / float64(agg.accepted)
		}
		if acceptRate < 0.15 && avgPayout < 20 && f.Confidence < 0.85 {
			continue
		}
		out = append(out, f)
	}
	return out
}

func (s *Server) runCampaignScheduler() {
	if s.repo == nil || s.campaignPoll <= 0 {
		return
	}
	ticker := time.NewTicker(s.campaignPoll)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().UTC()
		_, _ = s.repo.ReclaimStaleAutomationCampaignLeases(context.Background(), now.Add(-4*s.campaignPoll), 100)
		campaigns, err := s.repo.ListDueAutomationCampaigns(context.Background(), now, 25)
		if err != nil || len(campaigns) == 0 {
			continue
		}
		for _, c := range campaigns {
			if strings.TrimSpace(c.RunWindow) != "" && !inCampaignWindow(now, c) {
				nextRun := computeNextCampaignRun(now.Add(15*time.Minute), model.AutomationCampaignUpsertRequest{
					IntervalMin:     c.IntervalMin,
					ScheduleType:    c.ScheduleType,
					ScheduleValue:   c.ScheduleValue,
					RunWindow:       c.RunWindow,
					BlackoutWindows: c.BlackoutWindows,
				})
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			if inCampaignBlackout(now, c) {
				nextRun := now.Add(30 * time.Minute)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			leaseUntil := now.Add(2 * s.campaignPoll)
			ok, err := s.repo.TryLeaseAutomationCampaign(context.Background(), c.ID, leaseUntil)
			if err != nil || !ok {
				continue
			}
			c.Options.AutomationMode = normalizeAutomationMode(c.Options.AutomationMode)
			c.Options = s.applySafetyModePolicy(c.Options)
			c.PolicyPack = normalizePolicyPackName(c.PolicyPack)
			c.Options, c.PolicyVersion = s.applyAutomationPolicyPack(context.Background(), firstNonEmpty(c.WorkspaceID, "default"), c.PolicyPack, c.Options)
			c.Options.MinExpectedROIUSD = maxFloat(c.Options.MinExpectedROIUSD, s.defaultMinROI)
			if blocked, reason := s.shouldDeferForDailyBudget(context.Background(), firstNonEmpty(c.WorkspaceID, "default"), c.Options); blocked {
				backoff := 30 * time.Minute
				_ = s.repo.MarkAutomationCampaignDispatchFailure(context.Background(), c.ID, reason, now, backoff)
				continue
			}
			runDueAt := c.NextRunAt
			if c.NextRetryAt != nil && !c.NextRetryAt.IsZero() {
				runDueAt = *c.NextRetryAt
			}
			runKey := strings.Join([]string{
				"campaign",
				strings.TrimSpace(c.ID),
				runDueAt.UTC().Format(time.RFC3339Nano),
			}, ":")
			idempotencyTarget := strings.Join([]string{
				firstNonEmpty(c.WorkspaceID, "default"),
				strings.TrimSpace(c.Target),
				strings.TrimSpace(c.ID),
			}, "::")
			if existing, err := s.repo.GetRecentJobByIdempotencyKey(context.Background(), runKey, idempotencyTarget, now.Add(-7*24*time.Hour)); err == nil && existing != nil {
				nextRun := resolveCampaignNextRunAfterDispatch(now, c)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), c.ID, now, nextRun)
				continue
			}
			jobID := uuid.NewString()
			job := &model.ScanJob{
				ID:                 jobID,
				Target:             c.Target,
				WorkspaceID:        firstNonEmpty(c.WorkspaceID, "default"),
				RequestedBy:        c.RequestedBy,
				PolicyPack:         c.PolicyPack,
				Status:             "queued",
				StartedAt:          now,
				AuthProfileSummary: model.SummarizeAuthProfile(c.AuthProfile),
				Options:            c.Options,
				Scope:              c.Scope,
				ProgramName:        strings.TrimSpace(c.ProgramName),
				ProgramPolicyVersion: fmt.Sprintf(
					"%d",
					maxInt(1, c.PolicyVersion),
				),
			}
			if err := s.repo.CreateJob(context.Background(), job); err != nil {
				backoff := campaignRetryBackoff(c.RetryCount)
				_ = s.repo.MarkAutomationCampaignDispatchFailure(context.Background(), c.ID, err.Error(), now, backoff)
				continue
			}
			_ = s.repo.SaveIdempotencyRecord(context.Background(), runKey, idempotencyTarget, jobID, now)
			hbNow := now
			_ = s.repo.UpdateAutomationCampaignQueueState(context.Background(), c.ID, "running", runKey, &hbNow)
			s.appendAuditEvent(jobID, "automation-campaign", fmt.Sprintf("Campaign scheduled run: %s", c.ID))
			go func(campaign model.AutomationCampaign, scanJobID string, idempotencyKey string) {
				stopHB := make(chan struct{})
				go func() {
					beatTicker := time.NewTicker(maxDuration(5*time.Second, s.campaignPoll/2))
					defer beatTicker.Stop()
					for {
						select {
						case <-stopHB:
							return
						case beat := <-beatTicker.C:
							leaseUntil := beat.Add(2 * s.campaignPoll)
							ok, _ := s.repo.HeartbeatAutomationCampaignLease(context.Background(), campaign.ID, beat, leaseUntil)
							if !ok {
								return
							}
						}
					}
				}()
				s.runJob(scanJobID, campaign.Target, campaign.AuthProfile, nil, campaign.Options, campaign.Scope)
				close(stopHB)
				nextRun := resolveCampaignNextRunAfterDispatch(time.Now().UTC(), campaign)
				_ = s.repo.UpdateAutomationCampaignRun(context.Background(), campaign.ID, time.Now().UTC(), nextRun)
				_ = s.repo.UpdateAutomationCampaignQueueState(context.Background(), campaign.ID, "queued", idempotencyKey, nil)
			}(c, jobID, runKey)
		}
	}
}

func (s *Server) syncAutomationTickets(target string, findings []model.Finding) (int, int) {
	now := time.Now().UTC()
	currentFingerprints := make([]string, 0)
	open := 0
	for _, f := range findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium {
			continue
		}
		drift := strings.ToLower(strings.TrimSpace(f.DriftStatus))
		if drift == "resolved" {
			continue
		}
		fp := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		if fp == "" {
			continue
		}
		currentFingerprints = append(currentFingerprints, fp)
		sla := now.Add(72 * time.Hour)
		if f.Severity == model.SeverityHigh {
			sla = now.Add(24 * time.Hour)
		}
		if drift == "new" {
			if f.Severity == model.SeverityHigh {
				sla = now.Add(12 * time.Hour)
			} else {
				sla = now.Add(48 * time.Hour)
			}
		}
		status := "open"
		if drift == "changed" && f.Severity == model.SeverityHigh {
			status = "escalated"
		}
		ticket := model.AutomationTicket{
			ID:          uuid.NewString(),
			Target:      target,
			Fingerprint: fp,
			Title:       f.Title,
			Severity:    f.Severity,
			Status:      status,
			FirstSeenAt: now,
			LastSeenAt:  now,
			SLADueAt:    &sla,
		}
		if err := s.repo.UpsertAutomationTicket(context.Background(), ticket); err == nil {
			open++
		}
	}
	resolved, _ := s.repo.ResolveAutomationTicketsMissingFingerprints(context.Background(), target, currentFingerprints, now)
	return open, int(resolved)
}

func buildDeltaFindings(previousFindings, currentFindings []model.Finding) (int, int, int, []model.Finding) {
	prevByKey := map[string]model.Finding{}
	for _, f := range previousFindings {
		prevByKey[fingerprintFindingBase(f)] = f
	}
	currByKey := map[string]model.Finding{}
	for _, f := range currentFindings {
		currByKey[fingerprintFindingBase(f)] = f
	}

	newItems := make([]string, 0)
	changedItems := make([]string, 0)
	resolvedItems := make([]string, 0)
	for _, current := range currentFindings {
		key := fingerprintFindingBase(current)
		prev, ok := prevByKey[key]
		if !ok {
			newItems = append(newItems, fmt.Sprintf("[%s] %s", current.Severity, current.Title))
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(prev.Evidence), strings.TrimSpace(current.Evidence)) || prev.Severity != current.Severity {
			changedItems = append(changedItems, fmt.Sprintf("[%s] %s", current.Severity, current.Title))
		}
	}
	for _, prev := range previousFindings {
		if _, ok := currByKey[fingerprintFindingBase(prev)]; !ok {
			resolvedItems = append(resolvedItems, fmt.Sprintf("[%s] %s", prev.Severity, prev.Title))
		}
	}

	sort.Strings(newItems)
	sort.Strings(changedItems)
	sort.Strings(resolvedItems)
	delta := make([]model.Finding, 0, 3)
	if len(newItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-new-attack-surface",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("New attack surface detected since last completed scan (%d new findings)", len(newItems)),
			Description:    "This scan surfaced findings not present in the previous completed scan for the same target.",
			Evidence:       strings.Join(limitStrings(newItems, 6), "; "),
			Recommendation: "Prioritize triage of these newly introduced findings and consider enabling scheduled rescans for continuous monitoring.",
			DriftStatus:    "new",
			Confidence:     0.95,
			Sources:        []string{"monitoring"},
		})
	}
	if len(changedItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-changed-findings",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Finding behavior changed since last scan (%d changed)", len(changedItems)),
			Description:    "Previously observed findings changed severity or evidence details.",
			Evidence:       strings.Join(limitStrings(changedItems, 6), "; "),
			Recommendation: "Re-validate exploitability and update remediation priority for changed findings.",
			DriftStatus:    "changed",
			Confidence:     0.9,
			Sources:        []string{"monitoring"},
		})
	}
	if len(resolvedItems) > 0 {
		delta = append(delta, model.Finding{
			ID:             "monitoring-resolved-findings",
			Category:       "monitoring",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("Previously detected findings no longer observed (%d resolved)", len(resolvedItems)),
			Description:    "Findings from the previous completed scan were not reproduced in this run.",
			Evidence:       strings.Join(limitStrings(resolvedItems, 6), "; "),
			Recommendation: "Confirm remediation durability with a follow-up verification run.",
			DriftStatus:    "resolved",
			Confidence:     0.86,
			Sources:        []string{"monitoring"},
		})
	}
	return len(newItems), len(changedItems), len(resolvedItems), delta
}

func fingerprintFinding(f model.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Evidence))
}

func fingerprintFindingBase(f model.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Title))
}

func hasAuthorizationProfile(profile model.ScanAuthProfile) bool {
	return len(profile.Headers) > 0 ||
		len(profile.Cookies) > 0 ||
		strings.TrimSpace(profile.BasicAuthUsername) != "" ||
		strings.TrimSpace(profile.BasicAuthPassword) != "" ||
		(strings.TrimSpace(profile.Username) != "" && strings.TrimSpace(profile.Password) != "")
}

func validateAuthProfile(profile model.ScanAuthProfile) error {
	hasUsername := strings.TrimSpace(profile.Username) != ""
	hasPassword := strings.TrimSpace(profile.Password) != ""
	if hasUsername != hasPassword {
		return errors.New("authProfile username and password must both be provided for standard application authentication")
	}
	if strings.TrimSpace(profile.LoginURL) != "" && !hasUsername {
		return errors.New("authProfile loginUrl requires username and password")
	}
	return nil
}

func applyProgramScope(scanScope model.ScanScope, profile model.ProgramScopeProfile) model.ScanScope {
	if len(profile.IncludeHosts) > 0 {
		scanScope.IncludeHosts = append(scanScope.IncludeHosts, profile.IncludeHosts...)
	}
	if len(profile.ExcludeHosts) > 0 {
		scanScope.ExcludeHosts = append(scanScope.ExcludeHosts, profile.ExcludeHosts...)
	}
	if len(profile.ExcludePaths) > 0 {
		scanScope.ExcludePaths = append(scanScope.ExcludePaths, profile.ExcludePaths...)
	}
	if len(profile.ProgramRules) > 0 {
		scanScope.ProgramRules = append(scanScope.ProgramRules, profile.ProgramRules...)
	}
	return scanScope
}

func enforceDisallowedTests(options model.ScanOptions, disallowed []string, programRules []string) model.ScanOptions {
	set := map[string]struct{}{}
	for _, item := range disallowed {
		key := strings.ToLower(strings.TrimSpace(item))
		if key != "" {
			set[key] = struct{}{}
		}
	}
	for _, rule := range programRules {
		if strings.Contains(strings.ToLower(rule), "no destructive") {
			set["sqlmap"] = struct{}{}
			set["nikto"] = struct{}{}
			set["ffuf"] = struct{}{}
			set["gobuster"] = struct{}{}
		}
	}
	disable := func(tool string) bool {
		_, ok := set[tool]
		return ok
	}
	if disable("nuclei") {
		options.UseNucleiIntegration = false
	}
	if disable("zap") || disable("zap_baseline") {
		options.UseZAPBaselineIntegration = false
	}
	if disable("sqlmap") {
		options.UseSQLMapIntegration = false
	}
	if disable("nikto") {
		options.UseNiktoIntegration = false
	}
	if disable("ffuf") {
		options.UseFFUFIntegration = false
	}
	if disable("gobuster") {
		options.UseGobusterIntegration = false
	}
	if disable("wpscan") {
		options.UseWPScanIntegration = false
	}
	return options
}

func (s *Server) runWithAuthProfiles(ctx context.Context, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope, persistedState *model.PersistentScanState, emit agent.Emitter) ([]agent.AgentOutput, []model.Finding, error) {
	autonomyMemory := model.AutonomyMemory{}
	if persistedState != nil {
		autonomyMemory = persistedState.AutonomyMemory
	}
	input := agent.AgentInput{
		Target:         target,
		AuthProfile:    authProfile,
		Options:        options,
		Scope:          scanScope,
		AutonomyMemory: autonomyMemory,
		Emit:           emit,
	}
	outputs, findings, err := s.runAgents(ctx, input)
	if err != nil {
		return outputs, findings, err
	}
	baselineFindings := append([]model.Finding(nil), findings...)
	roleFindingMap := map[string][]model.Finding{}
	for _, rp := range roleProfiles {
		if strings.TrimSpace(rp.RoleName) == "" || !hasAuthorizationProfile(rp.AuthProfile) {
			continue
		}
		roleInput := input
		roleInput.AuthProfile = rp.AuthProfile
		roleOutputs, roleFindings, roleErr := s.runAgents(ctx, roleInput)
		outputs = append(outputs, roleOutputs...)
		if roleErr != nil {
			continue
		}
		for i := range roleFindings {
			if roleFindings[i].Exploitability == nil {
				roleFindings[i].Exploitability = &model.Exploitability{}
			}
			roleFindings[i].Exploitability.RequiredRole = rp.RoleName
			roleFindings[i].BusinessTags = append(roleFindings[i].BusinessTags, "role:"+rp.RoleName)
		}
		roleFindingMap[strings.TrimSpace(rp.RoleName)] = append([]model.Finding(nil), roleFindings...)
		findings = append(findings, roleFindings...)
	}
	findings = append(findings, buildRoleDiffFindings(baselineFindings, roleFindingMap)...)
	if s.scanService != nil {
		findings = append(findings, s.scanService.RunIDORRoleDiff(ctx, target, scanScope, options, authProfile, roleProfiles, emit)...)
	}
	return outputs, findings, nil
}

// runAgents executes the configured agent pipeline. When autonomous
// orchestration is enabled and an AI provider is reachable, the AI planner
// drives the loop and may dynamically schedule additional agents based on
// the findings observed so far. Otherwise it falls back to the static
// registry order so the historical behavior is preserved exactly.
func (s *Server) runAgents(ctx context.Context, input agent.AgentInput) ([]agent.AgentOutput, []model.Finding, error) {
	if input.Options.AutonomyEmergencyStop {
		return nil, nil, errors.New("autonomy emergency stop is enabled")
	}
	if s.agentFactory == nil {
		return s.agentRegistry.RunAll(ctx, input)
	}
	available := s.agentFactory.Names()
	staticOrder := s.agentRegistry.Order()
	fallback := agent.NewStaticPlanner(staticOrder)
	var planner agent.Planner = fallback
	plannerLock := strings.ToLower(strings.TrimSpace(input.Options.AutonomyPlannerLock))
	useAI := s.autonomous && s.aiClient != nil
	if plannerLock == "static" || plannerLock == "fallback" {
		useAI = false
	}
	if plannerLock == "ai" {
		useAI = s.aiClient != nil
	}
	if useAI {
		aiPlanner := agent.NewAIPlanner(s.aiClient, available, fallback)
		if input.Options.AutonomyExplorationBudgetPercent > 0 {
			aiPlanner.ExplorationBudget = input.Options.AutonomyExplorationBudgetPercent
		}
		planner = aiPlanner
	}
	orchestrator := agent.NewOrchestrator(planner, s.agentFactory, s.maxRounds)
	if input.Options.AutonomyMaxNoNoveltyRounds > 0 {
		orchestrator.MaxNoNoveltyRounds = input.Options.AutonomyMaxNoNoveltyRounds
	}
	if input.Options.AutonomyMaxConsecutiveFailRounds > 0 {
		orchestrator.MaxConsecutiveFailureRounds = input.Options.AutonomyMaxConsecutiveFailRounds
	}
	if input.Options.AutonomyMinMarginalScore > 0 {
		orchestrator.MinMarginalScore = input.Options.AutonomyMinMarginalScore
	}
	outputs, findings, err := orchestrator.Run(ctx, input)
	if err == nil && input.Options.AutonomyFallbackRerun && allAgentRunsFailed(outputs) {
		return s.agentRegistry.RunAll(ctx, input)
	}
	return outputs, findings, err
}

func allAgentRunsFailed(outputs []agent.AgentOutput) bool {
	if len(outputs) == 0 {
		return false
	}
	for _, out := range outputs {
		if strings.EqualFold(strings.TrimSpace(out.Status), "completed") && !out.TimedOut && strings.TrimSpace(out.Error) == "" {
			return false
		}
	}
	return true
}

func buildRoleDiffFindings(baseline []model.Finding, perRole map[string][]model.Finding) []model.Finding {
	if len(perRole) == 0 {
		return nil
	}
	baselineKeys := map[string]struct{}{}
	for _, f := range baseline {
		baselineKeys[fingerprintFindingBase(f)] = struct{}{}
	}
	roleNames := make([]string, 0, len(perRole))
	for role := range perRole {
		role = strings.TrimSpace(role)
		if role != "" {
			roleNames = append(roleNames, role)
		}
	}
	sort.Strings(roleNames)

	findings := make([]model.Finding, 0, len(roleNames)+1)
	summary := make([]string, 0, len(roleNames))
	for _, role := range roleNames {
		roleFindings := perRole[role]
		unique := make([]string, 0)
		for _, f := range roleFindings {
			key := fingerprintFindingBase(f)
			if _, ok := baselineKeys[key]; ok {
				continue
			}
			unique = append(unique, f.Title)
		}
		sort.Strings(unique)
		unique = limitStrings(unique, 6)
		summary = append(summary, fmt.Sprintf("%s:%d", role, len(unique)))
		if len(unique) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             "role-diff-" + strings.ToLower(strings.ReplaceAll(role, " ", "-")),
			Category:       "access-control",
			Severity:       model.SeverityMedium,
			Title:          fmt.Sprintf("Role-specific findings detected for %s", role),
			Description:    "This role produced findings not observed in baseline authenticated coverage, indicating role-dependent behavior that may hide authorization weaknesses.",
			Evidence:       strings.Join(unique, "; "),
			Recommendation: "Run targeted authorization/IDOR checks comparing this role against lower-privilege roles and anonymous access.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Compare role-specific findings against baseline run",
				"role":           role,
			},
			BusinessTags: []string{"auth-required", "role:" + role},
		})
	}
	if len(summary) > 0 {
		findings = append(findings, model.Finding{
			ID:             "role-diff-summary",
			Category:       "coverage",
			Severity:       model.SeverityInfo,
			Title:          "Role-diff coverage summary generated",
			Description:    "Cross-role comparison completed to identify role-dependent attack surface and potential access-control testing priorities.",
			Evidence:       strings.Join(summary, ", "),
			Recommendation: "Prioritize manual verification for roles with non-zero unique findings and validate privilege boundaries.",
			EvidenceFields: map[string]string{
				"validationType": "safe-observation",
				"reproStep":      "Review per-role unique finding counts",
			},
		})
	}
	return findings
}

func (s *Server) acquireTargetSlot(target string, options model.ScanOptions) func() {
	host := strings.ToLower(strings.TrimSpace(hostFromTarget(target)))
	if host == "" {
		return func() {}
	}
	limit := s.maxPerTarget
	if options.MaxPerTargetConcurrency > 0 && options.MaxPerTargetConcurrency <= 20 {
		limit = options.MaxPerTargetConcurrency
	}
	if limit < 1 || limit > 20 {
		limit = 1
	}
	s.semMu.Lock()
	sem, ok := s.targetSem[host]
	if !ok || cap(sem) != limit {
		sem = make(chan struct{}, limit)
		s.targetSem[host] = sem
	}
	s.semMu.Unlock()
	sem <- struct{}{}
	return func() { <-sem }
}

func (s *Server) acquireGlobalSlot(options model.ScanOptions) func() {
	if s.globalSem == nil {
		return func() {}
	}
	select {
	case s.globalSem <- struct{}{}:
	default:
		s.globalSem <- struct{}{}
	}
	return func() { <-s.globalSem }
}

func (s *Server) enforceTargetRateLimit(target string, options model.ScanOptions) {
	limitPerMinute := options.TargetRateLimitPerMinute
	if limitPerMinute <= 0 {
		return
	}
	host := strings.ToLower(strings.TrimSpace(hostFromTarget(target)))
	if host == "" {
		return
	}
	minGap := time.Minute / time.Duration(limitPerMinute)
	if minGap <= 0 {
		return
	}
	s.rateMu.Lock()
	last := s.targetLastRun[host]
	wait := time.Duration(0)
	if !last.IsZero() {
		wait = minGap - time.Since(last)
	}
	if wait > 0 {
		s.rateMu.Unlock()
		time.Sleep(wait)
		s.rateMu.Lock()
	}
	s.targetLastRun[host] = time.Now()
	s.rateMu.Unlock()
}

func redactSensitiveFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		f.Evidence = redactSensitiveText(f.Evidence)
		if f.EvidenceFields != nil {
			for k, v := range f.EvidenceFields {
				f.EvidenceFields[k] = redactSensitiveText(v)
			}
		}
		out = append(out, f)
	}
	return out
}

func redactSensitiveText(value string) string {
	replacer := strings.NewReplacer(
		"authorization:", "authorization:[redacted]",
		"cookie:", "cookie:[redacted]",
		"token=", "token=[redacted]",
		"password=", "password=[redacted]",
	)
	return replacer.Replace(value)
}

func (s *Server) applySuppressions(target string, findings []model.Finding) []model.Finding {
	rules, err := s.repo.ListActiveSuppressionRules(context.Background(), target, time.Now().UTC())
	if err != nil || len(rules) == 0 {
		return findings
	}
	suppressed := 0
	out := make([]model.Finding, 0, len(findings)+1)
	for _, f := range findings {
		if isSuppressed(f, target, rules) {
			suppressed++
			continue
		}
		out = append(out, f)
	}
	if suppressed > 0 {
		out = append(out, model.Finding{
			ID:          "suppression-rules-applied",
			Category:    "monitoring",
			Severity:    model.SeverityInfo,
			Title:       fmt.Sprintf("Suppression rules applied (%d findings hidden)", suppressed),
			Description: "Active suppression/baseline rules were applied to reduce duplicate or accepted-noise findings.",
			Evidence:    fmt.Sprintf("suppressed=%d", suppressed),
			Confidence:  1.0,
		})
	}
	return out
}

func isSuppressed(f model.Finding, target string, rules []model.SuppressionRule) bool {
	for _, r := range rules {
		if r.Target != "" && !strings.EqualFold(strings.TrimSpace(r.Target), strings.TrimSpace(target)) {
			continue
		}
		if r.FindingID != "" && strings.EqualFold(r.FindingID, f.ID) {
			return true
		}
		if r.Category != "" && !strings.EqualFold(r.Category, f.Category) {
			continue
		}
		if r.Title != "" && !strings.EqualFold(r.Title, f.Title) {
			continue
		}
		if r.Category != "" || r.Title != "" {
			return true
		}
	}
	return false
}

type toolHealth struct {
	Name      string `json:"name"`
	Binary    string `json:"binary"`
	Installed bool   `json:"installed"`
	Category  string `json:"category"`
}

func collectToolHealth() []toolHealth {
	tools := []toolHealth{
		{Name: "nuclei", Binary: envOrDefault("NUCLEI_BINARY", "nuclei"), Category: "vuln-scanning"},
		{Name: "zap-baseline", Binary: envOrDefault("ZAP_BASELINE_BINARY", "zap-baseline.py"), Category: "vuln-scanning"},
		{Name: "subfinder", Binary: envOrDefault("SUBFINDER_BINARY", "subfinder"), Category: "recon"},
		{Name: "httpx", Binary: envOrDefault("HTTPX_BINARY", "httpx"), Category: "recon"},
		{Name: "naabu", Binary: envOrDefault("NAABU_BINARY", "naabu"), Category: "recon"},
		{Name: "dnsx", Binary: envOrDefault("DNSX_BINARY", "dnsx"), Category: "recon"},
		{Name: "shuffledns", Binary: envOrDefault("SHUFFLEDNS_BINARY", "shuffledns"), Category: "recon"},
		{Name: "katana", Binary: envOrDefault("KATANA_BINARY", "katana"), Category: "crawler"},
		{Name: "tlsx", Binary: envOrDefault("TLSX_BINARY", "tlsx"), Category: "recon"},
		{Name: "cdncheck", Binary: envOrDefault("CDNCHECK_BINARY", "cdncheck"), Category: "recon"},
		{Name: "asnmap", Binary: envOrDefault("ASNMAP_BINARY", "asnmap"), Category: "recon"},
		{Name: "ffuf", Binary: envOrDefault("FFUF_BINARY", "ffuf"), Category: "content-discovery"},
		{Name: "gobuster", Binary: envOrDefault("GOBUSTER_BINARY", "gobuster"), Category: "content-discovery"},
	}
	for i := range tools {
		_, err := exec.LookPath(tools[i].Binary)
		tools[i].Installed = err == nil
	}
	return tools
}

func buildToolReadinessFindings(options model.ScanOptions) []model.Finding {
	required := map[string]bool{
		"nuclei":       options.UseNucleiIntegration,
		"zap-baseline": options.UseZAPBaselineIntegration,
		"subfinder":    options.UseSubfinderIntegration,
		"httpx":        options.UseHttpxIntegration,
		"naabu":        options.UseNaabuIntegration,
		"dnsx":         options.UseDnsxIntegration,
		"shuffledns":   options.UseShuffleDNSIntegration,
		"katana":       options.UseKatanaIntegration,
		"tlsx":         options.UseTlsxIntegration,
		"cdncheck":     options.UseCdncheckIntegration,
		"asnmap":       options.UseAsnmapIntegration,
		"ffuf":         options.UseFFUFIntegration,
		"gobuster":     options.UseGobusterIntegration,
	}
	health := collectToolHealth()
	missing := make([]string, 0)
	installedByCategory := map[string]int{}
	for _, item := range health {
		if item.Installed {
			installedByCategory[item.Category]++
		}
		if required[item.Name] && !item.Installed {
			missing = append(missing, item.Name)
		}
	}
	findings := make([]model.Finding, 0, 2)
	if len(missing) > 0 {
		sort.Strings(missing)
		findings = append(findings, model.Finding{
			ID:             "tool-readiness-missing-required",
			Category:       "operations",
			Severity:       model.SeverityMedium,
			Title:          "Required bug bounty tools are not installed",
			Description:    "One or more enabled integrations are missing binaries and may reduce scan coverage.",
			Evidence:       strings.Join(missing, ", "),
			Recommendation: "Install missing binaries or disable their integration flags to avoid incomplete runs.",
			Confidence:     0.98,
			Sources:        []string{"tool-health"},
		})
	}
	if installedByCategory["recon"] == 0 || installedByCategory["vuln-scanning"] == 0 || installedByCategory["content-discovery"] == 0 {
		findings = append(findings, model.Finding{
			ID:             "tool-readiness-category-gap",
			Category:       "operations",
			Severity:       model.SeverityInfo,
			Title:          "Toolchain has bug bounty coverage gaps",
			Description:    "Successful bug bounty workflows typically need recon, vulnerability scanning, and content discovery coverage.",
			Evidence:       fmt.Sprintf("recon=%d vuln=%d content=%d", installedByCategory["recon"], installedByCategory["vuln-scanning"], installedByCategory["content-discovery"]),
			Recommendation: "Install at least one tool per category or run equivalent native checks before production engagements.",
			Confidence:     0.9,
			Sources:        []string{"tool-health"},
		})
	}
	return findings
}

func buildIntegrationHealthFinding(outputs []agent.AgentOutput) []model.Finding {
	total := 0
	failures := 0
	timeouts := 0
	flaky := make([]string, 0)
	for _, out := range outputs {
		total++
		status := strings.ToLower(strings.TrimSpace(out.Status))
		if status != "completed" {
			failures++
			flaky = append(flaky, out.AgentName)
		}
		if out.Telemetry.TimedOut {
			timeouts++
			flaky = append(flaky, out.AgentName)
		}
	}
	if total == 0 {
		return nil
	}
	failureRate := float64(failures) / float64(total)
	timeoutRate := float64(timeouts) / float64(total)
	if failureRate == 0 && timeoutRate == 0 {
		return nil
	}
	sort.Strings(flaky)
	return []model.Finding{{
		ID:          "integration-health-telemetry",
		Category:    "integration",
		Severity:    model.SeverityInfo,
		Title:       "Integration health telemetry indicates flaky execution",
		Description: "Some agents or integrations failed or timed out; recommendation confidence should be down-ranked for reliability.",
		Evidence:    fmt.Sprintf("failureRate=%.2f timeoutRate=%.2f", failureRate, timeoutRate),
		EvidenceFields: map[string]string{
			"failureRate": fmt.Sprintf("%.2f", failureRate),
			"timeoutRate": fmt.Sprintf("%.2f", timeoutRate),
			"flakyTools":  strings.Join(limitStrings(flaky, 8), ","),
		},
	}}
}

func applyHealthAwareExecutionGating(options model.ScanOptions) (model.ScanOptions, []string) {
	required := map[string]bool{
		"nuclei":       options.UseNucleiIntegration,
		"zap-baseline": options.UseZAPBaselineIntegration,
		"subfinder":    options.UseSubfinderIntegration,
		"httpx":        options.UseHttpxIntegration,
		"naabu":        options.UseNaabuIntegration,
		"dnsx":         options.UseDnsxIntegration,
		"shuffledns":   options.UseShuffleDNSIntegration,
		"katana":       options.UseKatanaIntegration,
		"tlsx":         options.UseTlsxIntegration,
		"cdncheck":     options.UseCdncheckIntegration,
		"asnmap":       options.UseAsnmapIntegration,
		"ffuf":         options.UseFFUFIntegration,
		"gobuster":     options.UseGobusterIntegration,
	}
	health := collectToolHealth()
	disabled := make([]string, 0)
	for _, item := range health {
		if !required[item.Name] || item.Installed {
			continue
		}
		switch item.Name {
		case "nuclei":
			options.UseNucleiIntegration = false
		case "zap-baseline":
			options.UseZAPBaselineIntegration = false
		case "subfinder":
			options.UseSubfinderIntegration = false
		case "httpx":
			options.UseHttpxIntegration = false
		case "naabu":
			options.UseNaabuIntegration = false
		case "dnsx":
			options.UseDnsxIntegration = false
		case "shuffledns":
			options.UseShuffleDNSIntegration = false
		case "katana":
			options.UseKatanaIntegration = false
		case "tlsx":
			options.UseTlsxIntegration = false
		case "cdncheck":
			options.UseCdncheckIntegration = false
		case "asnmap":
			options.UseAsnmapIntegration = false
		case "ffuf":
			options.UseFFUFIntegration = false
		case "gobuster":
			options.UseGobusterIntegration = false
		}
		disabled = append(disabled, item.Name)
	}
	sort.Strings(disabled)
	return options, disabled
}

func campaignRetryBackoff(retryCount int) time.Duration {
	steps := maxInt(1, retryCount+1)
	backoff := time.Duration(steps*steps) * 5 * time.Minute
	if backoff > 6*time.Hour {
		return 6 * time.Hour
	}
	return backoff
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func automationMisfirePolicy() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AUTOMATION_MISFIRE_POLICY"))) {
	case "catch-up":
		return "catch-up"
	default:
		return "skip"
	}
}

func inCampaignWindow(now time.Time, c model.AutomationCampaign) bool {
	_, loc, err := parseScheduleValueAndLocation(c.ScheduleValue)
	if err != nil {
		loc = time.UTC
	}
	return inWindowAt(now, c.RunWindow, loc)
}

func inCampaignBlackout(now time.Time, c model.AutomationCampaign) bool {
	_, loc, err := parseScheduleValueAndLocation(c.ScheduleValue)
	if err != nil {
		loc = time.UTC
	}
	return inBlackoutAt(now, c.BlackoutWindows, loc)
}

func resolveCampaignNextRunAfterDispatch(now time.Time, c model.AutomationCampaign) time.Time {
	req := model.AutomationCampaignUpsertRequest{
		IntervalMin:     c.IntervalMin,
		ScheduleType:    c.ScheduleType,
		ScheduleValue:   c.ScheduleValue,
		RunWindow:       c.RunWindow,
		BlackoutWindows: c.BlackoutWindows,
	}
	if automationMisfirePolicy() != "catch-up" {
		return computeNextCampaignRun(now, req)
	}
	anchor := now
	if !c.NextRunAt.IsZero() {
		anchor = c.NextRunAt
	}
	next := computeNextCampaignRun(anchor, req)
	cutoff := now.Add(7 * 24 * time.Hour)
	for i := 0; i < 512 && !next.After(now); i++ {
		if next.After(cutoff) {
			return computeNextCampaignRun(now, req)
		}
		anchor = next
		next = computeNextCampaignRun(anchor, req)
	}
	return next
}

func parseClock(value string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, errH := strconv.Atoi(parts[0])
	m, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

func inWindowAt(now time.Time, spec string, loc *time.Location) bool {
	if loc == nil {
		loc = time.UTC
	}
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) != 2 {
		return false
	}
	sh, sm, okS := parseClock(parts[0])
	eh, em, okE := parseClock(parts[1])
	if !okS || !okE {
		return false
	}
	localNow := now.In(loc)
	start := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), sh, sm, 0, 0, loc)
	end := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), eh, em, 0, 0, loc)
	if end.Before(start) {
		return localNow.After(start) || localNow.Before(end)
	}
	return (localNow.Equal(start) || localNow.After(start)) && localNow.Before(end)
}

func inWindowUTC(now time.Time, spec string) bool {
	return inWindowAt(now, spec, time.UTC)
}

func inBlackoutAt(now time.Time, windows []string, loc *time.Location) bool {
	for _, win := range windows {
		if strings.TrimSpace(win) == "" {
			continue
		}
		if inWindowAt(now, win, loc) {
			return true
		}
	}
	return false
}

func inBlackout(now time.Time, windows []string) bool {
	return inBlackoutAt(now, windows, time.UTC)
}

func computeNextCampaignRun(now time.Time, req model.AutomationCampaignUpsertRequest) time.Time {
	base := now.UTC()
	scheduleValue, loc, err := parseScheduleValueAndLocation(req.ScheduleValue)
	if err != nil {
		scheduleValue = strings.TrimSpace(req.ScheduleValue)
		loc = time.UTC
	}
	if loc == nil {
		loc = time.UTC
	}
	switch normalizeScheduleType(req.ScheduleType) {
	case "daily":
		h, m, ok := parseClock(scheduleValue)
		if !ok {
			return base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		}
		localBase := base.In(loc)
		nextLocal := time.Date(localBase.Year(), localBase.Month(), localBase.Day(), h, m, 0, 0, loc)
		if !nextLocal.After(localBase) {
			nextLocal = nextLocal.Add(24 * time.Hour)
		}
		next := nextLocal.In(time.UTC)
		if strings.TrimSpace(req.RunWindow) != "" && !inWindowAt(next, req.RunWindow, loc) {
			next = next.Add(24 * time.Hour)
		}
		for i := 0; i < 1024 && inBlackoutAt(next, req.BlackoutWindows, loc); i++ {
			next = next.Add(30 * time.Minute)
		}
		return next
	case "weekly":
		raw := strings.Split(strings.TrimSpace(scheduleValue), "@")
		if len(raw) != 2 {
			return base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		}
		weekdayMap := map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}
		weekday, okDay := weekdayMap[strings.ToLower(strings.TrimSpace(raw[0]))]
		if !okDay {
			return base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		}
		h, m, ok := parseClock(raw[1])
		if !ok {
			return base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		}
		localBase := base.In(loc)
		nextLocal := time.Date(localBase.Year(), localBase.Month(), localBase.Day(), h, m, 0, 0, loc)
		for nextLocal.Weekday() != weekday || !nextLocal.After(localBase) {
			nextLocal = nextLocal.Add(24 * time.Hour)
		}
		next := nextLocal.In(time.UTC)
		for i := 0; i < 1024 && inBlackoutAt(next, req.BlackoutWindows, loc); i++ {
			next = next.Add(24 * time.Hour)
		}
		return next
	case "cron":
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		parsed, err := parser.Parse(strings.TrimSpace(scheduleValue))
		if err != nil {
			return base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		}
		next := parsed.Next(base.In(loc)).In(time.UTC)
		for i := 0; i < 2048; i++ {
			if strings.TrimSpace(req.RunWindow) != "" && !inWindowAt(next, req.RunWindow, loc) {
				next = parsed.Next(next.In(loc)).In(time.UTC)
				continue
			}
			if inBlackoutAt(next, req.BlackoutWindows, loc) {
				next = parsed.Next(next.In(loc)).In(time.UTC)
				continue
			}
			break
		}
		return next
	default:
		next := base.Add(time.Duration(maxInt(5, req.IntervalMin)) * time.Minute)
		if strings.TrimSpace(req.RunWindow) != "" && !inWindowAt(next, req.RunWindow, loc) {
			next = next.Add(15 * time.Minute)
		}
		for i := 0; i < 1024 && inBlackoutAt(next, req.BlackoutWindows, loc); i++ {
			next = next.Add(30 * time.Minute)
		}
		return next
	}
}

func (s *Server) applyFeedbackConfidencePrioritization(ctx context.Context, findings []model.Finding) []model.Finding {
	feedback, err := s.repo.ListFeedback(ctx, 1000)
	if err != nil || len(feedback) == 0 {
		return findings
	}
	type stats struct {
		total     int
		accepted  int
		rejected  int
		duplicate int
	}
	byKey := map[string]stats{}
	for _, item := range feedback {
		key := strings.ToLower(strings.TrimSpace(item.Category)) + "|" + strings.ToLower(strings.TrimSpace(item.Title))
		cur := byKey[key]
		cur.total++
		switch strings.ToLower(strings.TrimSpace(item.Outcome)) {
		case "accepted":
			cur.accepted++
		case "rejected":
			cur.rejected++
		case "duplicate":
			cur.duplicate++
		}
		byKey[key] = cur
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		conf := f.Confidence
		if conf <= 0 {
			conf = defaultConfidenceForSeverity(f.Severity)
		}
		key := strings.ToLower(strings.TrimSpace(f.Category)) + "|" + strings.ToLower(strings.TrimSpace(f.Title))
		s := byKey[key]
		if s.total >= 3 {
			acceptRate := float64(s.accepted) / float64(s.total)
			noiseRate := float64(s.rejected+s.duplicate) / float64(s.total)
			conf = conf * (0.8 + acceptRate*0.5) * (1 - noiseRate*0.35)
		}
		f.Confidence = maxFloat(0.05, minFloat(0.99, conf))
		out = append(out, f)
	}
	return out
}

func (s *Server) persistScanState(target string, findings []model.Finding, outputs []agent.AgentOutput, options model.ScanOptions) {
	prev, _ := s.repo.GetScanState(context.Background(), target)
	state := model.PersistentScanState{
		Target:        target,
		LastUpdatedAt: time.Now().UTC(),
	}
	if prev != nil {
		state.SessionInstability = prev.SessionInstability
		state.KnownRuntimeEndpoints = append([]string(nil), prev.KnownRuntimeEndpoints...)
		state.AutonomyMemory = prev.AutonomyMemory
	}
	refs := make([]string, 0)
	for _, f := range findings {
		if f.ID == "browser-auth-session-instability" {
			state.SessionInstability++
		}
		if f.ID == "runtime-surface-endpoints" || f.ID == "browser-runtime-references" {
			for _, p := range strings.Split(f.Evidence, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					refs = append(refs, p)
				}
			}
		}
	}
	sort.Strings(refs)
	state.KnownRuntimeEndpoints = limitStrings(mergeActions(state.KnownRuntimeEndpoints, refs), 25)
	feedback, _ := s.repo.ListFeedback(context.Background(), 1000)
	state.AutonomyMemory = mergeAutonomyMemory(state.AutonomyMemory, outputs, options.AutonomyMemoryRetentionDays, feedback)
	_ = s.repo.UpsertScanState(context.Background(), state)
}

func mergeAutonomyMemory(memory model.AutonomyMemory, outputs []agent.AgentOutput, retentionDays int, feedback []model.ReportFeedback) model.AutonomyMemory {
	if retentionDays <= 0 {
		retentionDays = intFromEnv("AUTONOMY_MEMORY_RETENTION_DAYS", 30)
	}
	if retentionDays > 0 && !memory.LastRunAt.IsZero() {
		expiry := memory.LastRunAt.Add(time.Duration(retentionDays) * 24 * time.Hour)
		if time.Now().UTC().After(expiry) {
			memory.PreferredAgents = nil
			memory.SuppressedAgents = nil
			memory.LastAgentSequence = nil
			memory.AgentStats = map[string]model.AutonomyAgentStat{}
		}
	}
	if memory.AgentStats == nil {
		memory.AgentStats = map[string]model.AutonomyAgentStat{}
	}
	if !memory.LastRunAt.IsZero() {
		daysSince := int(time.Since(memory.LastRunAt).Hours() / 24)
		if daysSince > 0 {
			dailyDecay := clampFloat(floatFromEnv("AUTONOMY_MEMORY_DAILY_DECAY", 0.03), 0, 0.25)
			decay := clampFloat(float64(daysSince)*dailyDecay, 0, 0.8)
			for name, stat := range memory.AgentStats {
				stat.Runs = int(float64(stat.Runs) * (1 - decay))
				stat.Errors = int(float64(stat.Errors) * (1 - decay))
				stat.Timeouts = int(float64(stat.Timeouts) * (1 - decay))
				stat.Findings = int(float64(stat.Findings) * (1 - decay))
				stat.HighConfidenceFindings = int(float64(stat.HighConfidenceFindings) * (1 - decay))
				stat.OperatorApprovals = int(float64(stat.OperatorApprovals) * (1 - decay))
				stat.OperatorRejections = int(float64(stat.OperatorRejections) * (1 - decay))
				stat.DecisionQualitySum = stat.DecisionQualitySum * (1 - decay)
				stat.DecisionQualitySamples = int(float64(stat.DecisionQualitySamples) * (1 - decay))
				memory.AgentStats[name] = stat
			}
		}
	}
	sequence := make([]string, 0, len(outputs))
	for _, out := range outputs {
		name := strings.TrimSpace(out.AgentName)
		if name == "" {
			continue
		}
		sequence = append(sequence, name)
		stat := memory.AgentStats[name]
		stat.Runs++
		if out.Status == "error" || strings.TrimSpace(out.Error) != "" {
			stat.Errors++
		}
		if out.TimedOut {
			stat.Timeouts++
		}
		stat.Findings += len(out.Findings)
		for _, f := range out.Findings {
			if f.Confidence >= 0.85 || f.Severity == model.SeverityHigh {
				stat.HighConfidenceFindings++
			}
		}
		if out.DurationMs > 0 {
			minutes := float64(out.DurationMs) / 60000.0
			if minutes > 0 {
				stat.YieldPerMinute = maxFloat(stat.YieldPerMinute, float64(len(out.Findings))/minutes)
			}
		}
		if out.Metadata != nil {
			if raw := strings.TrimSpace(out.Metadata["decision_quality_score"]); raw != "" {
				if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
					stat.DecisionQualitySum += clampFloat(parsed, 0, 1)
					stat.DecisionQualitySamples++
				}
			}
		}
		memory.AgentStats[name] = stat
	}
	for _, item := range feedback {
		if strings.ToLower(strings.TrimSpace(item.Category)) != "autonomy-action" {
			continue
		}
		agentName := parseOperatorFeedbackAgent(item.Notes)
		if agentName == "" {
			continue
		}
		stat := memory.AgentStats[agentName]
		switch strings.ToLower(strings.TrimSpace(item.Outcome)) {
		case "accepted":
			stat.OperatorApprovals++
		case "rejected", "duplicate":
			stat.OperatorRejections++
		}
		memory.AgentStats[agentName] = stat
	}
	memory.LastAgentSequence = limitStrings(sequence, 20)
	memory.LastRunAt = time.Now().UTC()

	preferred := make([]string, 0)
	suppressed := make([]string, 0)
	for name, stat := range memory.AgentStats {
		if stat.Runs == 0 {
			continue
		}
		errorRate := float64(stat.Errors) / float64(stat.Runs)
		normalFindings := maxInt(0, stat.Findings-stat.HighConfidenceFindings)
		noveltyScore := float64(stat.HighConfidenceFindings) + float64(normalFindings)*autonomyNoveltyFindingWeight
		totalOps := maxInt(1, stat.OperatorApprovals+stat.OperatorRejections)
		operatorPenalty := float64(stat.OperatorRejections) / float64(totalOps)
		if stat.DecisionQualitySamples > 0 {
			avgQuality := stat.DecisionQualitySum / float64(maxInt(1, stat.DecisionQualitySamples))
			noveltyScore += avgQuality
		}
		if noveltyScore >= autonomyPreferredMinScore && errorRate < autonomyPreferredMaxErrRate {
			preferred = append(preferred, name)
		}
		if stat.Runs >= autonomySuppressMinRuns && (stat.Findings == 0 || errorRate >= autonomySuppressErrRate || stat.Timeouts >= autonomySuppressTimeouts || operatorPenalty >= 0.5) {
			suppressed = append(suppressed, name)
		}
	}
	sort.Strings(preferred)
	sort.Strings(suppressed)
	memory.PreferredAgents = limitStrings(preferred, 8)
	memory.SuppressedAgents = limitStrings(suppressed, 8)
	memory.RetentionAppliedAt = time.Now().UTC()
	return memory
}

func parseOperatorFeedbackAgent(notes string) string {
	notes = strings.TrimSpace(notes)
	if notes == "" {
		return ""
	}
	var structured map[string]string
	if json.Unmarshal([]byte(notes), &structured) == nil {
		return strings.TrimSpace(structured["agent"])
	}
	parts := strings.Split(notes, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "agent=") {
			continue
		}
		segments := strings.SplitN(part, "=", 2)
		if len(segments) != 2 {
			continue
		}
		name := strings.TrimSpace(segments[1])
		if name != "" {
			return name
		}
	}
	return ""
}

func (s *Server) notifyFindings(job *model.ScanJob) {
	if job == nil {
		return
	}
	if s.webhookURL == "" && s.slackWebhook == "" {
		return
	}
	type noteFinding struct {
		ID         string         `json:"id"`
		Title      string         `json:"title"`
		Severity   model.Severity `json:"severity"`
		Confidence float64        `json:"confidence"`
		Drift      string         `json:"driftStatus,omitempty"`
	}
	selected := make([]noteFinding, 0)
	for _, f := range job.Findings {
		if f.Confidence < s.notifyMinConf {
			continue
		}
		if strings.ToLower(strings.TrimSpace(f.DriftStatus)) != "new" && strings.ToLower(strings.TrimSpace(f.DriftStatus)) != "changed" {
			continue
		}
		selected = append(selected, noteFinding{
			ID:         f.ID,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Drift:      f.DriftStatus,
		})
	}
	if len(selected) == 0 {
		return
	}
	payload := map[string]any{
		"scanId":    job.ID,
		"target":    job.Target,
		"findings":  selected,
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
	sendWebhookJSON(s.webhookURL, payload)
	if s.slackWebhook != "" {
		lines := []string{fmt.Sprintf("*auto-bughunter:* %d high-confidence drift finding(s) on `%s`", len(selected), job.Target)}
		for _, item := range selected {
			lines = append(lines, fmt.Sprintf("• [%s] %s (%.2f)", strings.ToUpper(string(item.Severity)), item.Title, item.Confidence))
		}
		sendWebhookJSON(s.slackWebhook, map[string]string{"text": strings.Join(limitStrings(lines, 12), "\n")})
	}
}

func sendWebhookJSON(target string, payload any) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(redirReq *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if err := safety.ValidateOutboundURL(redirReq.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked by outbound safety policy for %q: %w", redirReq.URL.String(), err)
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func hostFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func diffAssets(previous, current []model.ScanAsset) []string {
	prev := map[string]struct{}{}
	for _, a := range previous {
		prev[a.AssetType+"|"+a.AssetKey] = struct{}{}
	}
	newOnes := make([]string, 0)
	for _, a := range current {
		k := a.AssetType + "|" + a.AssetKey
		if _, ok := prev[k]; ok {
			continue
		}
		newOnes = append(newOnes, k)
	}
	sort.Strings(newOnes)
	return newOnes
}

func shouldTriggerEventDrivenRescan(options model.ScanOptions) bool {
	return options.DeepScanOnHighSignal || options.RescanIntervalMinutes == 0
}

func (s *Server) appendAuditEvent(scanID, stage, message string) {
	if strings.TrimSpace(scanID) == "" {
		return
	}
	_ = s.repo.AppendAuditEvent(context.Background(), scanID, model.ScanAuditEvent{
		Stage:     stage,
		Message:   message,
		Timestamp: time.Now().UTC(),
	})
}

func buildAgentTelemetry(outputs []agent.AgentOutput) []model.AgentRunTelemetry {
	telemetry := make([]model.AgentRunTelemetry, 0, len(outputs))
	for _, out := range outputs {
		t := out.Telemetry
		if t.AgentName == "" {
			t.AgentName = out.AgentName
		}
		if t.Status == "" {
			t.Status = out.Status
		}
		if v, ok := out.Metadata["targets_attempted"]; ok {
			t.TargetsAttempted, _ = strconv.Atoi(v)
		}
		if v, ok := out.Metadata["targets_skipped"]; ok {
			t.TargetsSkipped, _ = strconv.Atoi(v)
		}
		if v, ok := out.Metadata["skipped_reasons"]; ok && strings.TrimSpace(v) != "" {
			t.SkippedReasons = strings.Split(v, ",")
		}
		telemetry = append(telemetry, t)
	}
	return telemetry
}

func enrichFindings(findings []model.Finding) []model.Finding {
	dedup := map[string]model.Finding{}
	for _, f := range findings {
		if len(f.Sources) == 0 {
			f.Sources = []string{defaultSourceForCategory(f.Category)}
		}
		if f.Confidence <= 0 {
			f.Confidence = defaultConfidenceForSeverity(f.Severity)
		}
		if f.DriftStatus == "" {
			f.DriftStatus = "observed"
		}
		if f.EvidenceFields == nil {
			f.EvidenceFields = extractEvidenceFields(f)
		}
		if len(f.BusinessTags) == 0 {
			f.BusinessTags = deriveBusinessTags(f)
		}
		if f.Exploitability == nil {
			f.Exploitability = &model.Exploitability{
				Reachable:       true,
				RequiredRole:    "unknown",
				Prerequisites:   []string{"target_reachable"},
				AttackPathHints: deriveAttackPathHints(f),
			}
		}
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		f.EvidenceFields["validationType"] = "safe-observation"
		f.EvidenceFields["observedAt"] = time.Now().UTC().Format(time.RFC3339)
		f.EvidenceFields["reproStep"] = "Replay request in scoped test window and verify evidence"
		key := fingerprintFindingBase(f)
		existing, ok := dedup[key]
		if !ok {
			dedup[key] = f
			continue
		}
		if f.Confidence > existing.Confidence {
			existing.Confidence = f.Confidence
		}
		if severityRank(f.Severity) > severityRank(existing.Severity) {
			existing.Severity = f.Severity
		}
		existing.Sources = mergeActions(existing.Sources, f.Sources)
		if strings.TrimSpace(existing.Evidence) == "" {
			existing.Evidence = f.Evidence
		}
		dedup[key] = existing
	}
	out := make([]model.Finding, 0, len(dedup))
	for _, f := range dedup {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Title < out[j].Title
	})
	return out
}

func severityRank(sev model.Severity) int {
	switch sev {
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	default:
		return 1
	}
}

func defaultSourceForCategory(category string) string {
	c := strings.ToLower(strings.TrimSpace(category))
	switch c {
	case "integration":
		return "integration"
	case "reconnaissance", "monitoring", "prioritization", "coverage":
		return "agent"
	default:
		return "scanner"
	}
}

func defaultConfidenceForSeverity(sev model.Severity) float64 {
	switch sev {
	case model.SeverityHigh:
		return 0.9
	case model.SeverityMedium:
		return 0.82
	case model.SeverityLow:
		return 0.72
	default:
		return 0.65
	}
}

func extractEvidenceFields(f model.Finding) map[string]string {
	fields := map[string]string{}
	ev := strings.TrimSpace(f.Evidence)
	lower := strings.ToLower(ev)
	if strings.Contains(lower, "status=") {
		fields["status"] = extractFieldValue(lower, "status=")
	}
	if strings.Contains(lower, "warnmarkers=") {
		fields["warnMarkers"] = extractFieldValue(lower, "warnmarkers=")
	}
	if strings.Contains(lower, "matches=") {
		fields["matches"] = extractFieldValue(lower, "matches=")
	}
	if strings.Contains(lower, "openports=") {
		fields["openPorts"] = extractFieldValue(lower, "openports=")
	}
	if strings.Contains(lower, "subdomains=") {
		fields["subdomains"] = extractFieldValue(lower, "subdomains=")
	}
	if strings.Contains(lower, "hosts=") {
		fields["hosts"] = extractFieldValue(lower, "hosts=")
	}
	if strings.Contains(lower, "server:") {
		fields["header"] = "server"
	}
	if strings.Contains(lower, "x-powered-by:") {
		fields["header"] = "x-powered-by"
	}
	if strings.Contains(lower, "/api") {
		fields["urlPath"] = "/api"
	}
	if strings.Contains(lower, "tls") {
		fields["tlsDetail"] = ev
	}
	return fields
}

func extractFieldValue(value, prefix string) string {
	i := strings.Index(value, prefix)
	if i < 0 {
		return ""
	}
	rest := value[i+len(prefix):]
	if j := strings.Index(rest, ";"); j >= 0 {
		return strings.TrimSpace(rest[:j])
	}
	return strings.TrimSpace(rest)
}

func deriveBusinessTags(f model.Finding) []string {
	tags := map[string]struct{}{"internet-facing": {}}
	lower := strings.ToLower(f.Title + " " + f.Description + " " + f.Evidence)
	if strings.Contains(lower, "auth") || strings.Contains(lower, "cookie") || strings.Contains(lower, "session") {
		tags["auth-required"] = struct{}{}
	}
	if strings.Contains(lower, "api") || strings.Contains(lower, "graphql") {
		tags["data-sensitivity:unknown"] = struct{}{}
	}
	out := make([]string, 0, len(tags))
	for k := range tags {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func deriveAttackPathHints(f model.Finding) []string {
	lower := strings.ToLower(f.Category + " " + f.Title + " " + f.Description)
	hints := make([]string, 0, 3)
	if strings.Contains(lower, "header") || strings.Contains(lower, "cookie") {
		hints = append(hints, "hardening-review")
	}
	if strings.Contains(lower, "injection") || strings.Contains(lower, "sql") {
		hints = append(hints, "parameter-fuzzing")
	}
	if strings.Contains(lower, "auth") || strings.Contains(lower, "access") {
		hints = append(hints, "privilege-escalation-checks")
	}
	if len(hints) == 0 {
		hints = append(hints, "manual-validation")
	}
	return hints
}

func buildDecisionDashboard(job *model.ScanJob) *model.DecisionDashboard {
	if job == nil {
		return nil
	}
	totalAgents := len(job.AgentRuns)
	completedAgents := 0
	unauthCount := 0
	untested := map[string]struct{}{}
	for _, run := range job.AgentRuns {
		if strings.EqualFold(run.Status, "completed") {
			completedAgents++
		}
		if v, ok := run.Metadata["auth_mode"]; ok && strings.EqualFold(v, "unauthenticated") {
			unauthCount++
		}
		if run.TargetsSkipped > 0 && len(run.SkippedReasons) > 0 {
			for _, reason := range run.SkippedReasons {
				untested[strings.TrimSpace(reason)] = struct{}{}
			}
		}
	}
	score := 0
	if totalAgents > 0 {
		score = int(math.Round((float64(completedAgents) / float64(totalAgents)) * 100))
	}

	newCount, changedCount, resolvedCount := 0, 0, 0
	actionable := 0
	for _, f := range job.Findings {
		switch strings.ToLower(strings.TrimSpace(f.DriftStatus)) {
		case "new":
			newCount++
		case "changed":
			changedCount++
		case "resolved":
			resolvedCount++
		}
		if (f.Severity == model.SeverityHigh || f.Severity == model.SeverityMedium) && f.Confidence >= 0.75 {
			actionable++
		}
	}

	topAttackPaths := topAttackPaths(job.Findings)
	untestedReasons := make([]string, 0, len(untested))
	for reason := range untested {
		if reason != "" {
			untestedReasons = append(untestedReasons, reason)
		}
	}
	sort.Strings(untestedReasons)
	authRate := 1.0
	if totalAgents > 0 {
		authRate = 1.0 - (float64(unauthCount) / float64(totalAgents))
	}
	return &model.DecisionDashboard{
		CoverageCompletenessScore: score,
		AuthenticatedCoverageRate: authRate,
		NewFindings:               newCount,
		ChangedFindings:           changedCount,
		ResolvedFindings:          resolvedCount,
		TopAttackPaths:            topAttackPaths,
		UntestedReasons:           untestedReasons,
		ActionableFindings:        actionable,
	}
}

func topAttackPaths(findings []model.Finding) []string {
	paths := make([]string, 0, 4)
	for _, f := range findings {
		if f.Exploitability == nil {
			continue
		}
		for _, hint := range f.Exploitability.AttackPathHints {
			if strings.TrimSpace(hint) != "" {
				paths = append(paths, hint+": "+f.Title)
			}
		}
	}
	sort.Strings(paths)
	return limitStrings(paths, 5)
}

func buildNextActions(job *model.ScanJob) []string {
	if job == nil {
		return nil
	}
	actions := []string{
		"Triage high-confidence medium/high findings first.",
		"Review untested or skipped targets and request scope approvals where needed.",
	}
	if job.Dashboard != nil && job.Dashboard.AuthenticatedCoverageRate < 1.0 {
		actions = append(actions, "Fix authentication profile issues and rerun authenticated checks.")
	}
	if job.Dashboard != nil && job.Dashboard.NewFindings > 0 {
		actions = append(actions, "Validate newly introduced findings against recent release changes.")
	}
	actions = append(actions, "Schedule a follow-up scan to verify remediation and monitor drift.")
	return actions
}

func generateAutomatedReport(job *model.ScanJob) string {
	if job == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Automated Penetration Test Report\n\n")
	b.WriteString("## Target\n- " + job.Target + "\n\n")
	b.WriteString("## Findings Summary\n")
	counts := map[model.Severity]int{}
	for _, f := range job.Findings {
		counts[f.Severity]++
	}
	b.WriteString(fmt.Sprintf("- High: %d\n- Medium: %d\n- Low: %d\n- Info: %d\n\n", counts[model.SeverityHigh], counts[model.SeverityMedium], counts[model.SeverityLow], counts[model.SeverityInfo]))

	b.WriteString("## Commands Used\n")
	cmds := collectCommandsUsed(job.Findings)
	if len(cmds) == 0 {
		b.WriteString("- Built-in HTTP/TLS/wordlist checks (native Go modules)\n\n")
	} else {
		for _, cmd := range cmds {
			b.WriteString("- `" + cmd + "`\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("## Detailed Findings\n")
	for i, f := range job.Findings {
		howFound := strings.Join(f.Sources, ", ")
		if strings.TrimSpace(howFound) == "" {
			howFound = "scanner"
		}
		commands := inferCommandsForFinding(f)
		if len(commands) == 0 {
			commands = []string{"native-go-check"}
		}
		b.WriteString(fmt.Sprintf("%d. **[%s] %s**\n", i+1, strings.ToUpper(string(f.Severity)), f.Title))
		b.WriteString(fmt.Sprintf("   - Category: %s\n", f.Category))
		b.WriteString(fmt.Sprintf("   - How found: %s\n", howFound))
		b.WriteString(fmt.Sprintf("   - Commands: %s\n", strings.Join(commands, ", ")))
		b.WriteString(fmt.Sprintf("   - Evidence: %s\n", f.Evidence))
		b.WriteString(fmt.Sprintf("   - Recommendation: %s\n\n", f.Recommendation))
	}
	return b.String()
}

func collectCommandsUsed(findings []model.Finding) []string {
	seen := map[string]struct{}{}
	for _, f := range findings {
		for _, cmd := range inferCommandsForFinding(f) {
			if strings.TrimSpace(cmd) != "" {
				seen[cmd] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for cmd := range seen {
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
}

func inferCommandsForFinding(f model.Finding) []string {
	id := strings.ToLower(f.ID)
	switch {
	case strings.Contains(id, "nuclei"):
		return []string{"nuclei -u <target> -severity medium,high,critical -silent"}
	case strings.Contains(id, "zap"):
		return []string{"zap-baseline.py -t <target> -m 1 -I"}
	case strings.Contains(id, "subfinder"):
		return []string{"subfinder -d <host> -silent"}
	case strings.Contains(id, "httpx"):
		return []string{"httpx -u <target> -silent -status-code -title -tech-detect"}
	case strings.Contains(id, "naabu"):
		return []string{"naabu -host <host> -silent -top-ports 1000"}
	case strings.Contains(id, "dnsx"):
		return []string{"dnsx -d <host> -silent -a -cname -mx -txt"}
	case strings.Contains(id, "shuffledns"):
		return []string{"shuffledns -d <host> -silent"}
	case strings.Contains(id, "katana"):
		return []string{"katana -u <target> -silent -depth <n> -js-crawl"}
	case strings.Contains(id, "tlsx"):
		return []string{"tlsx -u <target> -silent"}
	case strings.Contains(id, "cdncheck"):
		return []string{"cdncheck -host <host>"}
	case strings.Contains(id, "asnmap"):
		return []string{"asnmap -d <host> -silent"}
	case strings.Contains(id, "wpscan"):
		return []string{"native-go-wpscan"}
	case strings.Contains(id, "nikto"):
		return []string{"native-go-nikto"}
	case strings.Contains(id, "sqlmap"):
		return []string{"native-go-sqlmap"}
	default:
		return nil
	}
}

func limitStrings(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func mergeActions(existing, extra []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(existing)+len(extra))
	appendUnique := func(items []string) {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	appendUnique(existing)
	appendUnique(extra)
	return out
}

func (s *Server) scheduleRescan(target, workspaceID, requestedBy string, authProfile model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C
	options = s.applySafetyModePolicy(options)
	if blocked, _ := s.shouldDeferForDailyBudget(context.Background(), firstNonEmpty(workspaceID, "default"), options); blocked {
		return
	}

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
		WorkspaceID:        workspaceID,
		RequestedBy:        requestedBy,
		PolicyPack:         defaultPolicyPack(),
		Status:             "queued",
		StartedAt:          now,
		AuthProfileSummary: model.SummarizeAuthProfile(authProfile),
		Options:            options,
		Scope:              scanScope,
	}
	if err := s.repo.CreateJob(context.Background(), job); err != nil {
		return
	}
	s.appendAuditEvent(jobID, "queued", "Scheduled rescan created from previous completed scan")
	s.runJob(jobID, target, authProfile, nil, options, scanScope)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func floatFromEnv(key string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}

func intFromEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func boolFromEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}
