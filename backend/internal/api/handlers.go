package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"

	"github.com/go-pdf/fpdf"
	"github.com/google/uuid"
)

type AgentConfig struct {
	EnableMLTriageAgent      bool
	EnableAttackPathAgent    bool
	EnableFalsePositiveAgent bool
	EnableRemediationAgent   bool
}

type Server struct {
	scanService    *scanner.Service
	aiClient       *ai.Client
	allowed        map[string]struct{}
	repo           Repository
	agentRegistry  *agent.Registry
	proxyServer    *proxy.Server
	mlService      *ml.Service
	agentLearner   *agentlearner.Client
	agentConfig    AgentConfig
	maxPerTarget   int
	semMu          sync.Mutex
	targetSem      map[string]chan struct{}
	globalSem      chan struct{}
	rateMu         sync.Mutex
	targetLastRun  map[string]time.Time
	webhookURL     string
	slackWebhook   string
	notifyMinConf  float64
	gateHighBlock  int
	gateMedBlock   int
	scanTimeout    time.Duration
	eventBus       *EventBus
	apiToken       string
	rateLimiter    *rateLimiter
	webhookSecret  string
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
}

func NewServer(scanService *scanner.Service, aiClient *ai.Client, mlService *ml.Service, agentLearner *agentlearner.Client, allowedHosts []string, repo Repository, proxyStore proxy.Store, maxPerTarget, globalBudget int, agentCfg AgentConfig, scanTimeout time.Duration) *Server {
	allowed := map[string]struct{}{}
	for _, h := range allowedHosts {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			allowed[h] = struct{}{}
		}
	}

	reg := agent.NewRegistry()
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

	if globalBudget <= 0 {
		globalBudget = 5
	}
	if scanTimeout <= 0 {
		scanTimeout = 10 * time.Minute
	}
	return &Server{
		scanService:   scanService,
		aiClient:      aiClient,
		allowed:       allowed,
		repo:          repo,
		agentRegistry: reg,
		proxyServer:   proxy.NewServer(proxyStore),
		mlService:     mlService,
		agentLearner:  agentLearner,
		agentConfig:   agentCfg,
		maxPerTarget:  maxInt(1, maxPerTarget),
		targetSem:     map[string]chan struct{}{},
		globalSem:     make(chan struct{}, globalBudget),
		targetLastRun: map[string]time.Time{},
		webhookURL:    strings.TrimSpace(os.Getenv("SCAN_WEBHOOK_URL")),
		slackWebhook:  strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL")),
		notifyMinConf: maxFloat(0.0, minFloat(1.0, floatFromEnv("NOTIFY_MIN_CONFIDENCE", 0.9))),
		gateHighBlock: maxInt(0, intFromEnv("POLICY_GATE_HIGH_BLOCK", 1)),
		gateMedBlock:  maxInt(0, intFromEnv("POLICY_GATE_MEDIUM_BLOCK", 3)),
		scanTimeout:   scanTimeout,
		eventBus:      NewEventBus(),
		apiToken:      strings.TrimSpace(os.Getenv("API_TOKEN")),
		rateLimiter:   newRateLimiter(intFromEnv("API_RATE_LIMIT_PER_MINUTE", 0)),
		webhookSecret: strings.TrimSpace(os.Getenv("WEBHOOK_SIGNING_SECRET")),
	}
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
	mux.HandleFunc("/api/automation/event", s.handleAutomationEvent)
	mux.HandleFunc("/api/automation/report", s.handleAutomationReport)
	mux.HandleFunc("/api/automation/tickets", s.handleAutomationTickets)
	mux.HandleFunc("/api/report/", s.handleScanReportPDF)
	mux.HandleFunc("/metrics", s.handleMetrics)
	// Wrap handler chain (innermost first): mux -> auth -> rate limit -> metrics -> CORS.
	// CORS is outermost so OPTIONS preflights are handled before auth.
	handler := authMiddleware(s.apiToken, mux)
	handler = rateLimitMiddleware(s.rateLimiter, handler)
	handler = metricsMiddleware(handler)
	return withCORS(handler)
}

// handleScanOrEvents routes /api/scan/{id}, /api/scan/{id}/events, and
// /api/scan/{id}/sarif.
func (s *Server) handleScanOrEvents(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/events") {
		s.handleScanEvents(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/sarif") {
		s.handleScanSARIF(w, r)
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
		ID          string     `json:"id"`
		Target      string     `json:"target"`
		Status      string     `json:"status"`
		CreatedAt   time.Time  `json:"createdAt"`
		CompletedAt *time.Time `json:"completedAt"`
		FindingCount int       `json:"findingCount"`
		HighCount   int        `json:"highCount"`
	}
	summaries := make([]scanSummary, 0, len(jobs))
	for _, j := range jobs {
		if j == nil {
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

	target, host, err := normalizeAndValidateTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target blocked by outbound safety policy"})
		return
	}

	if len(s.allowed) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "server has no ALLOWED_TARGETS configured"})
		return
	}
	if _, ok := s.allowed[host]; !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target host is not in ALLOWED_TARGETS"})
		return
	}
	req.Scope = applyProgramScope(req.Scope, req.ProgramScopeProfile)
	req.Options = enforceDisallowedTests(req.Options, req.DisallowedTestTypes, req.Scope.ProgramRules)
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
		return
	}
	if !hasAuthorizationProfile(req.AuthProfile) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authProfile is required (headers, cookies, or basic auth)"})
		return
	}
	if req.Options.RescanIntervalMinutes < 0 || req.Options.RescanIntervalMinutes > 10080 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rescanIntervalMinutes must be between 0 and 10080"})
		return
	}
	req.IdempotencyKey = strings.TrimSpace(req.IdempotencyKey)
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	}
	if req.IdempotencyKey != "" {
		if existing, err := s.repo.GetRecentJobByIdempotencyKey(r.Context(), req.IdempotencyKey, target, time.Now().UTC().Add(-24*time.Hour)); err == nil && existing != nil {
			writeJSON(w, http.StatusAccepted, map[string]string{"id": existing.ID, "status": existing.Status, "deduplicated": "true"})
			return
		}
	}

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                   jobID,
		Target:               target,
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
		_ = s.repo.SaveIdempotencyRecord(r.Context(), req.IdempotencyKey, target, jobID, now)
	}
	s.appendAuditEvent(jobID, "queued", "Scan job accepted and queued")

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
	options = s.tuneScanOptions(options, persistedState, previousJob)

	job.Status = "running"
	_ = s.repo.UpdateJob(context.Background(), job)
	s.appendAuditEvent(id, "running", "Scan execution started")
	metrics.recordScanStarted()

	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
	defer cancel()

	outputs, findings, err := s.runWithAuthProfiles(ctx, target, authProfile, roleProfiles, options, scanScope, emit)
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
		metrics.recordScanCompleted(false)
		return
	}

	job.Status = "completed"
	job.Findings = enrichFindings(findings)
	job.Findings = redactSensitiveFindings(job.Findings)
	job.Findings = append(job.Findings, buildToolReadinessFindings(options)...)
	job.Findings = append(job.Findings, buildIntegrationHealthFinding(outputs)...)
	job.Findings = s.applySuppressions(target, job.Findings)
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
					go s.scheduleRescan(target, authProfile, options, scanScope, 5*time.Minute)
				}
			}
		}
	}
	job.AssetLinks = extractAssetLinks(target, job.Assets, job.Findings)
	if len(job.AssetLinks) > 0 {
		s.appendAuditEvent(id, "inventory-graph", fmt.Sprintf("Built %d asset relationship links", len(job.AssetLinks)))
	}
	job.AISummary = s.aiClient.Summarize(context.Background(), target, job.Findings)
	job.Dashboard = buildDecisionDashboard(job)
	job.NextActions = buildNextActions(job)
	if s.mlService != nil {
		job.ModelRecommendations = s.mlService.RecommendFromHistory(context.Background(), s.repo, s.proxyServer.Store(), job)
		if job.ModelRecommendations != nil {
			job.NextActions = mergeActions(job.NextActions, job.ModelRecommendations.Copilot.SuggestedActions)
			s.appendAuditEvent(id, "ml-inference", fmt.Sprintf("ML mode=%s tools=%d prioritized=%d", job.ModelRecommendations.ModelMode, len(job.ModelRecommendations.ToolSelection), len(job.ModelRecommendations.PrioritizedFindings)))
		}
	}
	policyGate := s.evaluatePolicyGate(job.Findings)
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
	openTickets, resolvedTickets := s.syncAutomationTickets(target, job.Findings)
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
	s.persistScanState(target, job.Findings)
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
		s.agentLearner.Learn(context.Background(), job.ID, agentSeq, job.Findings, scanDurationMs)
	}
	s.appendAuditEvent(id, "completed", "Scan execution completed successfully")
	metrics.recordScanCompleted(true)
	sevCounts := map[string]int{}
	for _, f := range job.Findings {
		sevCounts[strings.ToLower(string(f.Severity))]++
	}
	metrics.recordFindings(sevCounts)
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
		s.appendAuditEvent(id, "scheduling", fmt.Sprintf("Scheduled rescan in %d minutes", job.Options.RescanIntervalMinutes))
		go s.scheduleRescan(target, authProfile, options, scanScope, time.Duration(job.Options.RescanIntervalMinutes)*time.Minute)
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
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
	if err := s.repo.SaveFeedback(r.Context(), req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist feedback"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": req.ID, "status": "recorded"})
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
	target, host, err := normalizeAndValidateTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := safety.ValidateOutboundURL(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target blocked by outbound safety policy"})
		return
	}
	if len(s.allowed) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "server has no ALLOWED_TARGETS configured"})
		return
	}
	if _, ok := s.allowed[host]; !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target host is not in ALLOWED_TARGETS"})
		return
	}
	if !hasAuthorizationProfile(req.AuthProfile) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authProfile is required for automation event scans"})
		return
	}
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
		return
	}
	req.Options.DeepScanOnHighSignal = true
	req.Options.RescanIntervalMinutes = 0
	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
		Status:             "queued",
		StartedAt:          now,
		AuthProfileSummary: model.SummarizeAuthProfile(req.AuthProfile),
		Options:            req.Options,
		Scope:              req.Scope,
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
		GeneratedAt:           time.Now().UTC(),
		TotalCompletedScans:   len(jobs),
		OpenAutomationTickets: len(openTickets),
	}
	for _, job := range jobs {
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
	totalReviewed := report.AcceptedFeedback + report.RejectedFeedback + report.DuplicateFeedback
	if totalReviewed > 0 {
		report.FalsePositiveRate = float64(report.RejectedFeedback+report.DuplicateFeedback) / float64(totalReviewed)
	}
	_ = openTickets
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAutomationTickets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	tickets, err := s.repo.ListOpenAutomationTickets(r.Context(), target, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation tickets"})
		return
	}
	writeJSON(w, http.StatusOK, tickets)
}

func (s *Server) evaluatePolicyGate(findings []model.Finding) model.PolicyGateResult {
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
	if result.HighCount >= s.gateHighBlock || result.MediumCount >= s.gateMedBlock {
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("high=%d medium=%d exceeded thresholds high>=%d or medium>=%d", result.HighCount, result.MediumCount, s.gateHighBlock, s.gateMedBlock)
	} else {
		result.Reason = "thresholds satisfied"
	}
	return result
}

func (s *Server) tuneScanOptions(options model.ScanOptions, state *model.PersistentScanState, previous *model.ScanJob) model.ScanOptions {
	if previous != nil && previous.Dashboard != nil && previous.Dashboard.CoverageCompletenessScore < 70 {
		options.CrawlMaxPages = maxInt(options.CrawlMaxPages, 200)
	}
	if state != nil && state.SessionInstability > 2 {
		options.UseNucleiIntegration = false
		options.UseSQLMapIntegration = false
		options.UseFFUFIntegration = false
	}
	return options
}

func (s *Server) syncAutomationTickets(target string, findings []model.Finding) (int, int) {
	now := time.Now().UTC()
	currentFingerprints := make([]string, 0)
	open := 0
	for _, f := range findings {
		if f.Severity != model.SeverityHigh && f.Severity != model.SeverityMedium {
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
		ticket := model.AutomationTicket{
			ID:          uuid.NewString(),
			Target:      target,
			Fingerprint: fp,
			Title:       f.Title,
			Severity:    f.Severity,
			Status:      "open",
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
		strings.TrimSpace(profile.BasicAuthPassword) != ""
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

func (s *Server) runWithAuthProfiles(ctx context.Context, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope, emit agent.Emitter) ([]agent.AgentOutput, []model.Finding, error) {
	input := agent.AgentInput{
		Target:      target,
		AuthProfile: authProfile,
		Options:     options,
		Scope:       scanScope,
		Emit:        emit,
	}
	outputs, findings, err := s.newRegistry(options).RunAll(ctx, input)
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
		roleOutputs, roleFindings, roleErr := s.newRegistry(options).RunAll(ctx, roleInput)
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
	return outputs, findings, nil
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

func (s *Server) persistScanState(target string, findings []model.Finding) {
	state := model.PersistentScanState{
		Target:        target,
		LastUpdatedAt: time.Now().UTC(),
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
	state.KnownRuntimeEndpoints = limitStrings(mergeActions(nil, refs), 25)
	_ = s.repo.UpsertScanState(context.Background(), state)
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
	sendWebhookJSON(s.webhookURL, payload, s.webhookSecret)
	if s.slackWebhook != "" {
		lines := []string{fmt.Sprintf("*auto-bughunter:* %d high-confidence drift finding(s) on `%s`", len(selected), job.Target)}
		for _, item := range selected {
			lines = append(lines, fmt.Sprintf("• [%s] %s (%.2f)", strings.ToUpper(string(item.Severity)), item.Title, item.Confidence))
		}
		// Slack expects an unsigned payload to its incoming webhook URL.
		sendWebhookJSON(s.slackWebhook, map[string]string{"text": strings.Join(limitStrings(lines, 12), "\n")}, "")
	}
}

func sendWebhookJSON(target string, payload any, signingSecret string) {
	target = strings.TrimSpace(target)
	if target == "" {
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
	if signingSecret != "" {
		mac := hmac.New(sha256.New, []byte(signingSecret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		// Use the GitHub-style header (sha256=<hex>) so consumers can verify
		// payloads with widely-available libraries.
		req.Header.Set("X-Auto-Bughunter-Signature", "sha256="+sig)
		req.Header.Set("X-Auto-Bughunter-Timestamp", time.Now().UTC().Format(time.RFC3339))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		metrics.recordWebhook(false)
		return
	}
	_ = resp.Body.Close()
	metrics.recordWebhook(resp.StatusCode >= 200 && resp.StatusCode < 300)
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

func (s *Server) scheduleRescan(target string, authProfile model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
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

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
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

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

// handleScanReportPDF serves a PDF report for a completed scan.
// GET /api/report/{scanId}
func (s *Server) handleScanReportPDF(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/report/")
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

	pdfBytes, err := generateScanReportPDF(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PDF"})
		return
	}

	filename := fmt.Sprintf("scan-report-%s.pdf", id)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pdfBytes)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pdfBytes)
}

// generateScanReportPDF produces a PDF report from a ScanJob.
func generateScanReportPDF(job *model.ScanJob) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	pageW, _ := pdf.GetPageSize()
	contentW := pageW - 30 // left + right margins

	// --- Title ---
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetTextColor(30, 80, 160)
	pdf.CellFormat(contentW, 10, "Auto Bughunter — Scan Report", "", 1, "C", false, 0, "")
	pdf.Ln(4)

	// --- Meta ---
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(contentW, 6, fmt.Sprintf("Target: %s", job.Target), "", 1, "L", false, 0, "")
	pdf.CellFormat(contentW, 6, fmt.Sprintf("Scan ID: %s", job.ID), "", 1, "L", false, 0, "")
	pdf.CellFormat(contentW, 6, fmt.Sprintf("Status: %s", job.Status), "", 1, "L", false, 0, "")
	pdf.CellFormat(contentW, 6, fmt.Sprintf("Started: %s", job.StartedAt.UTC().Format(time.RFC3339)), "", 1, "L", false, 0, "")
	if job.CompletedAt != nil {
		pdf.CellFormat(contentW, 6, fmt.Sprintf("Completed: %s", job.CompletedAt.UTC().Format(time.RFC3339)), "", 1, "L", false, 0, "")
	}
	if job.ProgramName != "" {
		pdf.CellFormat(contentW, 6, fmt.Sprintf("Program: %s", job.ProgramName), "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	// --- Findings Summary ---
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(contentW, 8, "Findings Summary", "", 1, "L", false, 0, "")

	counts := map[model.Severity]int{}
	for _, f := range job.Findings {
		counts[f.Severity]++
	}
	severities := []model.Severity{model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	severityColors := map[model.Severity][3]int{
		model.SeverityHigh:   {200, 50, 50},
		model.SeverityMedium: {220, 130, 30},
		model.SeverityLow:    {50, 130, 200},
		model.SeverityInfo:   {100, 100, 100},
	}
	pdf.SetFont("Helvetica", "", 10)
	for _, sev := range severities {
		c := severityColors[sev]
		pdf.SetTextColor(c[0], c[1], c[2])
		pdf.CellFormat(contentW, 6, fmt.Sprintf("  %-8s %d", strings.ToUpper(string(sev)), counts[sev]), "", 1, "L", false, 0, "")
	}
	pdf.SetTextColor(30, 30, 30)
	pdf.Ln(4)

	// --- AI Summary ---
	if job.AISummary != "" {
		pdf.SetFont("Helvetica", "B", 13)
		pdf.CellFormat(contentW, 8, "AI Summary", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(50, 50, 50)
		pdf.MultiCell(contentW, 5, job.AISummary, "", "L", false)
		pdf.SetTextColor(30, 30, 30)
		pdf.Ln(2)
	}

	// --- Findings Detail ---
	if len(job.Findings) > 0 {
		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(contentW, 8, "Detailed Findings", "", 1, "L", false, 0, "")

		for i, f := range job.Findings {
			// Section header per finding
			c := severityColors[f.Severity]
			pdf.SetFont("Helvetica", "B", 10)
			pdf.SetTextColor(c[0], c[1], c[2])
			header := fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(string(f.Severity)), f.Title)
			pdf.MultiCell(contentW, 6, header, "", "L", false)

			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(50, 50, 50)
			if f.Category != "" {
				pdf.MultiCell(contentW, 5, "Category: "+f.Category, "", "L", false)
			}
			if f.Description != "" {
				pdf.MultiCell(contentW, 5, "Description: "+f.Description, "", "L", false)
			}
			if f.Evidence != "" {
				pdf.MultiCell(contentW, 5, "Evidence: "+f.Evidence, "", "L", false)
			}
			if f.Recommendation != "" {
				pdf.MultiCell(contentW, 5, "Recommendation: "+f.Recommendation, "", "L", false)
			}
			if f.DriftStatus != "" {
				pdf.MultiCell(contentW, 5, "Drift: "+f.DriftStatus, "", "L", false)
			}
			if len(f.Sources) > 0 {
				pdf.MultiCell(contentW, 5, "Sources: "+strings.Join(f.Sources, ", "), "", "L", false)
			}
			if f.Confidence > 0 {
				pdf.MultiCell(contentW, 5, fmt.Sprintf("Confidence: %.2f", f.Confidence), "", "L", false)
			}
			pdf.Ln(3)
		}
	}

	// --- Automated Report ---
	if job.AutomatedReport != "" {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(contentW, 8, "Automated Pen Test Report", "", 1, "L", false, 0, "")
		pdf.SetFont("Courier", "", 8)
		pdf.SetTextColor(40, 40, 40)
		pdf.MultiCell(contentW, 4, job.AutomatedReport, "", "L", false)
	}

	// Footer with page numbers
	reportDate := job.StartedAt.UTC()
	if job.CompletedAt != nil {
		reportDate = job.CompletedAt.UTC()
	}
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(150, 150, 150)
		pdf.CellFormat(0, 5, fmt.Sprintf("Page %d — Auto Bughunter Report — %s", pdf.PageNo(), reportDate.Format("2006-01-02")), "", 0, "C", false, 0, "")
	})

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
