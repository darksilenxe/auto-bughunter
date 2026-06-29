package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime/debug"
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
	"auto-bughunter/backend/internal/mcp"
	"auto-bughunter/backend/internal/memory"
	"auto-bughunter/backend/internal/metrics"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/oast"
	"auto-bughunter/backend/internal/paths"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/safety"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"
	"auto-bughunter/backend/internal/toolclient"

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
	passiveScanStore           *proxy.PassiveScanStore
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
	postProcessBudget          time.Duration
	persistenceTimeout         time.Duration
	enrichmentHook             func(ctx context.Context, target string, findings []model.Finding, jobSnapshot *model.ScanJob) enrichmentResult
	eventBus                   *EventBus
	oast                       oast.Provider
	attackGraphDB              AttackGraphStore
	memoryStore                memory.Store
	mcpServer                  *mcp.Server
	apiRateLimiter             *apiRateLimiter
	defaultMinROI              float64
	campaignPoll               time.Duration
	defaultDailyScanLimit      int
	defaultDailyRuntimeMinutes int
	defaultDailyProbeLimit     int
	cancelMu                   sync.Mutex
	cancelFuncs                map[string]context.CancelFunc
}

const (
	coverageLowThreshold         = 70
	coverageLowCrawlBoostPages   = 200
	highROIMultiplierForDeepScan = 1.5
	lowROICrawlFloorPages        = 40
	lowROICrawlCeilingPages      = 120
	// campaignApprovalClockSkewTolerance allows small client/server clock drift
	// when validating approval timestamps on signed campaign authorizations.
	campaignApprovalClockSkewTolerance = 5 * time.Minute
	// High-confidence findings are already filtered by confidence/severity and
	// therefore counted as full novelty units while all findings contribute a
	// smaller background signal.
	autonomyNoveltyFindingWeight = 0.2
	autonomyPreferredMinScore    = 2.0
	autonomyPreferredMaxErrRate  = 0.5
	autonomySuppressMinRuns      = 3
	autonomySuppressErrRate      = 0.66
	autonomySuppressTimeouts     = 2
	// maxAnnotationTextLength caps the size of an operator mid-scan annotation
	// to avoid overly large payloads that could degrade hypothesis agent context.
	maxAnnotationTextLength = 4096
	// postProcessTimeout bounds the time spent on post-scan external service
	// calls (knowledge retrieval, AI summarisation, ML recommendations).
	// Each individual HTTP call has its own shorter deadline from the service's
	// http.Client.Timeout; this top-level budget prevents a total hang when
	// multiple services are slow or unreachable.
	postProcessTimeout = 2 * time.Minute
	persistenceTimeout = 10 * time.Second

	// noSignalMinProbes is the minimum number of probe records a category must
	// have before it can be suppressed by the adaptive category budget (Gap 13).
	noSignalMinProbes = 5
	// noSignalRateThreshold is the fraction of no_signal outcomes that must be
	// present for a category to be considered provably clean and thus skipped in
	// the next scan via AutonomySuppressAgents.
	noSignalRateThreshold = 0.90
)

// SetOAST attaches an OAST provider so its admin endpoints become active.
// Safe to call with nil to disable.
func (s *Server) SetOAST(o oast.Provider) { s.oast = o }

// SetProxyServer replaces the API server's intercepting proxy with an
// externally-built one (e.g. configured with a CA for HTTPS interception).
// The passive scan store is transferred to the replacement server so findings
// accumulated before and after the swap share the same store.
// Safe to call with nil to leave the default proxy in place.
func (s *Server) SetProxyServer(p *proxy.Server) {
	if p == nil {
		return
	}
	if s.passiveScanStore != nil {
		p.SetPassiveScanStore(s.passiveScanStore)
	}
	s.proxyServer = p
}

// SetAttackGraphStore attaches an optional graph database-backed attack graph store.
func (s *Server) SetAttackGraphStore(store AttackGraphStore) { s.attackGraphDB = store }

func (s *Server) persistenceContext() (context.Context, context.CancelFunc) {
	timeout := s.persistenceTimeout
	if timeout <= 0 {
		timeout = persistenceTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (s *Server) loadJobForRun(id string) (*model.ScanJob, error) {
	ctx, cancel := s.persistenceContext()
	defer cancel()
	return s.repo.GetJob(ctx, id)
}

func (s *Server) loadLatestCompletedJob(target, excludeID string) (*model.ScanJob, error) {
	ctx, cancel := s.persistenceContext()
	defer cancel()
	return s.repo.GetLatestCompletedJobByTarget(ctx, target, excludeID)
}

func (s *Server) loadScanState(target string) (*model.PersistentScanState, error) {
	ctx, cancel := s.persistenceContext()
	defer cancel()
	return s.repo.GetScanState(ctx, target)
}

func (s *Server) persistJob(job *model.ScanJob) error {
	if job == nil {
		return nil
	}
	backoff := 25 * time.Millisecond
	if s.persistenceTimeout > 0 && s.persistenceTimeout/4 > 0 && s.persistenceTimeout/4 < backoff {
		backoff = s.persistenceTimeout / 4
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := s.persistenceContext()
		err := s.repo.UpdateJob(ctx, job)
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * backoff)
		}
	}
	log.Printf("api: scan %s persistence failed for status %q: %v", job.ID, job.Status, lastErr)
	return lastErr
}

func (s *Server) persistAssets(scanID string, assets []model.ScanAsset) error {
	ctx, cancel := s.persistenceContext()
	defer cancel()
	return s.repo.SaveAssets(ctx, scanID, assets)
}

func (s *Server) persistAttackGraph(scanID, target string, graph *model.AttackGraphData) error {
	if s.attackGraphDB == nil {
		return nil
	}
	ctx, cancel := s.persistenceContext()
	defer cancel()
	return s.attackGraphDB.SaveAttackGraph(ctx, scanID, target, graph)
}

// SetVectorMemory attaches an episodic vector memory store. Nil is safe and
// disables the feature.
func (s *Server) SetVectorMemory(store memory.Store) { s.memoryStore = store }

// VectorMemory returns the currently configured memory store, or nil if none.
func (s *Server) VectorMemory() memory.Store { return s.memoryStore }

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
	SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error
	ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error)
	ListAutomationPolicyAudit(ctx context.Context, workspaceID, policyPack string, limit int) ([]model.AutomationPolicyAuditEvent, error)
	// SaveScanAnnotation persists a mid-scan operator observation.
	SaveScanAnnotation(ctx context.Context, annotation model.ScanAnnotation) error
	// ListScanAnnotations returns all annotations for a scan, oldest first.
	ListScanAnnotations(ctx context.Context, scanID string) ([]model.ScanAnnotation, error)
	// SaveProbeRecord persists the outcome of a single hypothesis probe for
	// ML training and negative-evidence collection.
	SaveProbeRecord(ctx context.Context, scanID string, pr model.ProbeResult) error
	// ListProbeRecords returns all probe records for the given scan.
	ListProbeRecords(ctx context.Context, scanID string) ([]model.ProbeRecord, error)
	// ListProbeRecordsByOutcome returns probe records matching the given outcome
	// created at or after since, newest-first, up to limit rows.
	ListProbeRecordsByOutcome(ctx context.Context, outcome model.ProbeOutcome, since time.Time, limit int) ([]model.ProbeRecord, error)
	// ListProbeRecordsByCategory returns probe records for the given vulnerability
	// category created at or after since, newest-first, up to limit rows.
	ListProbeRecordsByCategory(ctx context.Context, category string, since time.Time, limit int) ([]model.ProbeRecord, error)
	// GetRejectedFindingsByTarget returns all finding verifications with status
	// "rejected" for findings associated with the given target host. The results
	// are used to suppress historically-rejected findings from re-surfacing in
	// subsequent scans.
	GetRejectedFindingsByTarget(ctx context.Context, target string) ([]model.FindingVerification, error)
}

type shadowDecisionWriter interface {
	SaveShadowDecision(ctx context.Context, decision model.ShadowDecision) error
}

type shadowDecisionReader interface {
	ListShadowDecisions(ctx context.Context, since time.Time, limit int) ([]model.ShadowDecision, error)
}

func NewServer(scanService *scanner.Service, aiClient *ai.Client, mlService *ml.Service, knowledgeSvc *knowledge.Client, agentLearner *agentlearner.Client, repo Repository, proxyStore proxy.Store, maxPerTarget, globalBudget int, agentCfg AgentConfig, scanTimeout time.Duration) *Server {
	reg := agent.NewRegistry()
	factory := agent.NewFactory(scanService, mlService)
	factory.SetAIClient(aiClient, scanService)
	reg.RegisterFactory(factory)
	reg.Register(agent.NewReconnaissanceAgent(true))
	reg.Register(agent.NewJavaScriptSASTAgent(scanService, true))
	reg.Register(agent.NewScanningAgent(scanService, true))
	reg.Register(agent.NewAdvancedCoverageAgent(scanService, true))
	reg.Register(agent.NewInputValidationAgent(true))
	reg.Register(agent.NewInformationDisclosureAgent(true))
	reg.Register(agent.NewAccessControlAgent(true))
	reg.Register(agent.NewAPISecurityAgent(true))
	reg.Register(agent.NewCORSRedirectAgent(true))
	reg.Register(agent.NewWordlistAgent(true))
	reg.Register(agent.NewAnalysisAgent(true))
	// Agentic loop agents: these form the autonomous observe→reason→act core.
	// They are registered in the static order so they always execute even when
	// the AI planner is unavailable, while still being schedulable by the AI
	// planner in autonomous mode. Each gracefully skips if its AI client or
	// scanner dependency is missing.
	reg.Register(agent.NewHypothesisAgent(aiClient, scanService, true))
	reg.Register(agent.NewAdaptiveProbeAgent(aiClient, scanService, 0, true))
	reg.Register(agent.NewPentestLoopAgent(aiClient, scanService, 0, true))
	reg.Register(agent.NewReasoningIterationAgent(aiClient, scanService, 0, true))
	reg.Register(agent.NewExploitChainAgent(true))
	reg.Register(agent.NewHackTricksAgent(true, aiClient))
	reg.Register(agent.NewToolBuilderAgent(true, aiClient))
	// ai_tool_calling is enabled whenever an AI client is present so the LLM
	// can invoke bounded tool actions without requiring an explicit per-scan flag.
	reg.Register(agent.NewAIToolCallingAgent(aiClient, aiClient != nil))
	reg.Register(agent.NewMLTriageAgent(mlService, true))
	reg.Register(agent.NewAttackPathAgent(mlService, true))
	reg.Register(agent.NewFalsePositiveReviewAgent(mlService, true))
	reg.Register(agent.NewRemediationPlannerAgent(mlService, true))
	reg.Register(agent.NewOpenHackExpertAgent(aiClient, nil, true))
	reg.Register(agent.NewOpenHackTriageAgent(aiClient, nil, true))
	reg.Register(agent.NewImpactVerifierAgent(true))
	reg.Register(agent.NewReportingAgent(true))
	reg.Register(agent.NewLLMChainSynthesisAgent(aiClient, true))

	autonomous := boolFromEnv("ENABLE_AUTONOMOUS_ORCHESTRATION", true)
	maxRounds := maxInt(1, intFromEnv("MAX_ORCHESTRATION_ROUNDS", 10))

	if globalBudget <= 0 {
		globalBudget = 5
	}
	if scanTimeout <= 0 {
		scanTimeout = 10 * time.Minute
	}
	passiveStore := proxy.NewPassiveScanStore()
	defaultProxyServer := proxy.NewServer(proxyStore)
	defaultProxyServer.SetPassiveScanStore(passiveStore)
	s := &Server{
		scanService:                scanService,
		aiClient:                   aiClient,
		repo:                       repo,
		agentRegistry:              reg,
		agentFactory:               factory,
		autonomous:                 autonomous,
		maxRounds:                  maxRounds,
		proxyServer:                defaultProxyServer,
		passiveScanStore:           passiveStore,
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
		postProcessBudget:          postProcessTimeout,
		persistenceTimeout:         persistenceTimeout,
		eventBus:                   NewEventBus(),
		apiRateLimiter:             newAPIRateLimiter(),
		defaultMinROI:              maxFloat(0, floatFromEnv("AUTOMATION_MIN_EXPECTED_ROI_USD", 75)),
		campaignPoll:               time.Duration(maxInt(15, intFromEnv("AUTOMATION_CAMPAIGN_POLL_SECONDS", 30))) * time.Second,
		defaultDailyScanLimit:      maxInt(0, intFromEnv("AUTOMATION_DAILY_SCAN_LIMIT", 30)),
		defaultDailyRuntimeMinutes: maxInt(0, intFromEnv("AUTOMATION_DAILY_RUNTIME_LIMIT_MINUTES", 240)),
		defaultDailyProbeLimit:     maxInt(0, intFromEnv("AUTOMATION_DAILY_PROBE_LIMIT", 5000)),
		cancelFuncs:                map[string]context.CancelFunc{},
	}
	s.mcpServer = mcp.NewServer(s.aiClient)
	s.mcpServer.SetContextProvider(func() []mcp.Resource {
		return s.buildMCPResources()
	})
	// Wire the proxy store into the scanner so that all outbound HTTP
	// requests made during scans are captured and shown in the Network Graph.
	if proxyStore != nil {
		scanService.SetProxyStore(proxyStore)
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
	mux.Handle("/api/mcp", s.mcpServer)
	mux.Handle("/api/mcp/", s.mcpServer)
	// Proxy management endpoints.
	mux.HandleFunc("/api/proxy/requests", s.handleProxyRequests)
	mux.HandleFunc("/api/proxy/requests/", s.handleGetProxyRequest)
	mux.HandleFunc("/api/proxy/replay", s.handleProxyReplay)
	mux.HandleFunc("/api/proxy/settings", s.handleProxySettings)
	mux.HandleFunc("/api/proxy/ca-certificate", s.handleProxyCACertificate)
	mux.HandleFunc("/api/proxy/intruder", s.handleProxyIntruder)
	mux.HandleFunc("/api/proxy/browse", s.handleProxyBrowse)
	mux.HandleFunc("/api/proxy/passive-findings", s.handleProxyPassiveFindings)
	mux.HandleFunc("/api/ml/engagements", s.handleListMLEngagements)
	mux.HandleFunc("/api/ml/agent-weights", s.handleAgentWeights)
	mux.HandleFunc("/api/feedback", s.handleFeedback)
	mux.HandleFunc("/api/finding-verification", s.handleFindingVerification)
	mux.HandleFunc("/api/findings/duplicates", s.handleFindingDuplicates)
	mux.HandleFunc("/api/suppressions", s.handleSuppressions)
	mux.HandleFunc("/api/tools/health", s.handleToolsHealth)
	mux.HandleFunc("/api/tools/updates", s.handleToolsUpdates)
	mux.HandleFunc("/api/automation/event", s.handleAutomationEvent)
	mux.HandleFunc("/api/automation/report", s.handleAutomationReport)
	mux.HandleFunc("/api/automation/tickets", s.handleAutomationTickets)
	mux.HandleFunc("/api/automation/campaigns", s.handleAutomationCampaigns)
	mux.HandleFunc("/api/automation/campaign-authorization-export", s.handleAutomationCampaignAuthorizationExport)
	mux.HandleFunc("/api/automation/roi-overrides", s.handleAutomationROIOverrides)
	mux.HandleFunc("/api/automation/policy-packs", s.handleAutomationPolicyPacks)
	mux.HandleFunc("/api/automation/policy-profile-defaults", s.handlePolicyProfileDefaults)
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
	mux.HandleFunc("/api/admin/logs", s.handleSystemLogs)
	// Agent Console — dispatch a single named agent with custom instructions.
	mux.HandleFunc("/api/agent/dispatch", s.handleAgentDispatch)
	// IDE — generate PoC / exploit code using the configured coding model.
	mux.HandleFunc("/api/ide/generate", s.handleIDEGenerate)
	// Prometheus-format metrics — not gated by auth so Prometheus can scrape.
	mux.Handle("/metrics", metrics.DefaultRegistry.Handler())
	return withCORS(withRecovery(s.authMiddleware(s.rateLimitMiddleware(mux))))
}

func (s *Server) buildMCPResources() []mcp.Resource {
	return []mcp.Resource{
		{
			URI:         "auto-bughunter://findings/recent",
			Name:        "Recent Findings",
			Description: "Most recent confirmed findings from active scans",
			MimeType:    "application/json",
			Text:        s.recentFindingsJSON(),
		},
	}
}

func (s *Server) recentFindingsJSON() string {
	if s == nil || s.repo == nil {
		return "[]"
	}
	ctx, cancel := s.persistenceContext()
	defer cancel()
	jobs, err := s.repo.ListCompletedJobs(ctx, 5)
	if err != nil || len(jobs) == 0 {
		return "[]"
	}
	job := jobs[0]
	if job == nil || len(job.Findings) == 0 {
		return "[]"
	}
	findings := job.Findings
	if len(findings) > 20 {
		findings = findings[:20]
	}
	type summary struct {
		ID       string         `json:"id"`
		Title    string         `json:"title"`
		Category string         `json:"category"`
		Severity model.Severity `json:"severity"`
		URL      string         `json:"url,omitempty"`
	}
	out := make([]summary, 0, len(findings))
	for _, f := range findings {
		out = append(out, summary{ID: f.ID, Title: f.Title, Category: f.Category, Severity: f.Severity, URL: f.AffectedURL})
	}
	blob, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(blob)
}

// withRecovery wraps every HTTP handler in a deferred recover so that panics
// in handler code are caught, logged with a stack trace, and returned to the
// client as a 500 rather than crashing the entire server process.
func withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic recovered in HTTP handler [%s %s]: %v\n%s",
					r.Method, r.URL.Path, rec, debug.Stack())
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// handleScanOrEvents routes /api/scan/{id} and /api/scan/{id}/events.
func (s *Server) handleScanOrEvents(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/events") {
		s.handleScanEvents(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/probes") {
		s.handleListScanProbes(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/annotate") {
		s.handleScanAnnotate(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/annotations") {
		s.handleListScanAnnotations(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/activity") {
		s.handleGetScanActivity(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/stop") {
		s.handleStopScan(w, r)
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
	resp := map[string]any{"status": "ok"}
	if statsProvider, ok := s.repo.(interface{ ConnectionStats() sql.DBStats }); ok {
		stats := statsProvider.ConnectionStats()
		resp["database"] = map[string]int{
			"openConnections":    stats.OpenConnections,
			"inUse":              stats.InUse,
			"idle":               stats.Idle,
			"maxOpenConnections": stats.MaxOpenConnections,
			"waitCount":          int(stats.WaitCount),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req model.ScanRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
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

// handleListScanProbes handles GET /api/scan/{id}/probes.
func (s *Server) handleListScanProbes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/probes")
	scanID := strings.TrimSpace(strings.TrimPrefix(path, "/api/scan/"))
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	job, err := s.repo.GetJob(r.Context(), scanID)
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

	records, err := s.repo.ListProbeRecords(r.Context(), scanID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list probe records"})
		return
	}

	findingID := strings.TrimSpace(r.URL.Query().Get("findingId"))
	if findingID != "" {
		filtered := make([]model.ProbeRecord, 0, len(records))
		for _, record := range records {
			if record.FindingID == findingID {
				filtered = append(filtered, record)
			}
		}
		records = filtered
	}
	if records == nil {
		records = []model.ProbeRecord{}
	}
	writeJSON(w, http.StatusOK, records)
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

// handleStopScan handles POST /api/scan/{id}/stop. It cancels a running scan.
func (s *Server) handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scan/"), "/stop")
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
	if job.Status != "running" && job.Status != "queued" && job.Status != "finalizing" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "scan is not running"})
		return
	}

	s.cancelMu.Lock()
	cancel, ok := s.cancelFuncs[id]
	s.cancelMu.Unlock()

	if ok {
		cancel()
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "cancelled"})
		return
	}

	// Scan is queued but not yet running — mark it cancelled directly.
	now := time.Now().UTC()
	job.Status = "cancelled"
	job.Error = "scan stopped by operator"
	job.CompletedAt = &now
	if err := s.repo.UpdateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update scan status"})
		return
	}
	s.appendAuditEvent(id, "cancelled", "Scan cancelled by operator before execution")
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "cancelled"})
}

// enrichmentResult holds the best-effort post-scan enrichment outputs
// (security-knowledge retrieval, AI summary, narrative report, ML
// recommendations). It is produced by computeEnrichment under a watchdog so
// that a step which hangs while ignoring ctx cancellation cannot block scan
// finalization.
type enrichmentResult struct {
	knowledgeCtx *model.SecurityKnowledgeContext
	aiSummary    string
	narrative    ai.NarrativeReport
	haveNarr     bool
	recs         *model.ModelRecommendations
}

// computeEnrichment runs the post-scan enrichment steps over immutable
// snapshots of the job. It honours ctx where the underlying providers do, but
// callers must still bound it with a watchdog because some local/CPU-bound
// fallbacks do not observe cancellation. A test hook (enrichmentHook) may
// override the implementation to inject deterministic timing.
func (s *Server) computeEnrichment(ctx context.Context, target string, findings []model.Finding, jobSnapshot *model.ScanJob) enrichmentResult {
	if s.enrichmentHook != nil {
		return s.enrichmentHook(ctx, target, findings, jobSnapshot)
	}
	var res enrichmentResult
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	// Knowledge retrieval and AI summary are dependent, so keep them in a single
	// chain; run this chain in parallel with narrative generation and ML scoring.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var knowledgeCtx *model.SecurityKnowledgeContext
		if s.knowledgeSvc != nil {
			knowledgeCtx = s.knowledgeSvc.RetrieveForJob(ctx, "ai-summary", jobSnapshot, 5)
		}
		aiSummary := s.aiClient.SummarizeWithKnowledge(ctx, target, findings, knowledgeCtx)
		mu.Lock()
		res.knowledgeCtx = knowledgeCtx
		res.aiSummary = aiSummary
		mu.Unlock()
	}()

	if s.aiClient != nil && len(findings) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			narrative := s.aiClient.GenerateNarrativeReport(ctx, target, findings)
			mu.Lock()
			res.narrative = narrative
			res.haveNarr = true
			mu.Unlock()
		}()
	}
	if s.mlService != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs := s.mlService.RecommendFromHistory(ctx, s.repo, s.proxyServer.Store(), jobSnapshot)
			mu.Lock()
			res.recs = recs
			mu.Unlock()
		}()
	}
	// Calibrate per-category confidence multipliers from probe records collected
	// during this scan. Runs in parallel with the other enrichment goroutines and
	// is gated by ML_CALIBRATE_PROBE_SIGNALS=true inside CalibrateProbeSignals.
	if s.mlService != nil && jobSnapshot != nil && jobSnapshot.ID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			records, err := s.repo.ListProbeRecords(ctx, jobSnapshot.ID)
			if err == nil && len(records) > 0 {
				s.mlService.CalibrateProbeSignals(ctx, records)
			}
		}()
	}
	wg.Wait()
	return res
}

func (s *Server) runJob(id, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope) {
	// Track how many jobs are waiting for a global execution slot.
	// The defer is a safety net in case acquireGlobalSlot panics; the
	// normal Dec immediately after acquireGlobalSlot is the hot path.
	metrics.ScanQueueDepth.Inc()
	dequeued := false
	defer func() {
		if !dequeued {
			metrics.ScanQueueDepth.Dec()
		}
	}()
	releaseGlobal := s.acquireGlobalSlot(options)
	dequeued = true
	metrics.ScanQueueDepth.Dec()
	defer releaseGlobal()
	s.enforceTargetRateLimit(target, options)
	release := s.acquireTargetSlot(target, options)
	defer release()

	rawEmit := s.eventBus.EmitterFor(id)
	emit := func(event model.ScanEvent) {
		if shouldPersistAgentEvent(event.Type) {
			go func(e model.ScanEvent) {
				if err := s.repo.SaveAgentEvent(context.Background(), id, e); err != nil {
					log.Printf("failed to save agent event for scan %s: %v", id, err)
				}
			}(event)
		}
		rawEmit(event)
	}

	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: "Scan job started",
	})

	job, err := s.loadJobForRun(id)
	if err != nil || job == nil {
		return
	}
	// Stop scans cancelled while still queued: handleStop marks the job
	// "cancelled" when no cancel func is registered yet (i.e. before this
	// goroutine reached runJob). Without this guard we would flip the
	// status back to "running" and execute a scan the operator already
	// stopped.
	if job.Status == "cancelled" {
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: "Scan cancelled: stopped before execution started",
		})
		s.appendAuditEvent(id, "cancelled", "Scan was cancelled while queued; runJob skipped execution")
		return
	}
	previousJob, _ := s.loadLatestCompletedJob(target, id)
	persistedState, _ := s.loadScanState(target)
	if persistedState != nil && len(persistedState.KnownRuntimeEndpoints) > 0 {
		options.SeedRuntimeEndpoints = mergeActions(options.SeedRuntimeEndpoints, persistedState.KnownRuntimeEndpoints)
		s.appendAuditEvent(id, "state", fmt.Sprintf("Loaded %d persisted runtime endpoints", len(persistedState.KnownRuntimeEndpoints)))
	}
	options = s.applySafetyModePolicy(options)
	options = s.tuneScanOptions(context.Background(), target, options, persistedState, previousJob)
	options, disabledForHealth := applyHealthAwareExecutionGating(options)
	if len(disabledForHealth) > 0 {
		s.appendAuditEvent(id, "health-gate", "Disabled degraded integrations: "+strings.Join(disabledForHealth, ", "))
	}
	if hasOperatorOverrides(options) {
		s.appendAuditEvent(id, "override", fmt.Sprintf("Operator overrides applied emergencyStop=%t plannerLock=%s force=%s suppress=%s fallbackRerun=%t",
			options.AutonomyEmergencyStop,
			strings.TrimSpace(options.AutonomyPlannerLock),
			strings.Join(limitStrings(options.AutonomyForceRunAgents, 8), ","),
			strings.Join(limitStrings(options.AutonomySuppressAgents, 8), ","),
			options.AutonomyFallbackRerun,
		))
	}

	job.Status = "running"
	_ = s.persistJob(job)
	s.appendAuditEvent(id, "running", "Scan execution started")

	metrics.ScansTotal.Inc()
	metrics.ActiveScans.Inc()
	scanStart := time.Now()
	defer func() {
		metrics.ActiveScans.Dec()
		metrics.ScanDuration.Observe(time.Since(scanStart).Seconds())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
	s.cancelMu.Lock()
	s.cancelFuncs[id] = cancel
	s.cancelMu.Unlock()
	defer func() {
		s.cancelMu.Lock()
		delete(s.cancelFuncs, id)
		s.cancelMu.Unlock()
		cancel()
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			completed := time.Now().UTC()
			job.Status = "failed"
			job.Error = fmt.Sprintf("scan panicked: %v", recovered)
			job.CompletedAt = &completed
			emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: "Scan failed: " + job.Error,
			})
			s.appendAuditEvent(id, "failed", "Scan execution panicked: "+job.Error)
			_ = s.persistJob(job)
		}
	}()

	outputs, findings, err := s.runWithAuthProfiles(ctx, id, target, authProfile, roleProfiles, options, scanScope, persistedState, emit)
	executionFinishedAt := time.Now().UTC()
	// partialTimeout records that the scan-wide deadline (SCAN_TIMEOUT_SECONDS)
	// elapsed mid-pipeline. Rather than discarding every finding collected so
	// far and marking the whole scan "failed", we finalize gracefully: the
	// partial findings (already returned by the orchestrator) are preserved,
	// post-processing still runs on fresh contexts, and the job completes with
	// a clear truncation marker. Operator cancellation and genuine errors keep
	// their existing terminal handling.
	partialTimeout := false
	if err != nil {
		operatorCancelled := errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled
		scanTimedOut := errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded
		switch {
		case operatorCancelled:
			job.Status = "cancelled"
			job.Error = "scan stopped by operator"
			emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: "Scan cancelled by operator",
			})
			s.appendAuditEvent(id, "cancelled", "Scan cancelled by operator")
			_ = s.persistJob(job)
			return
		case scanTimedOut:
			partialTimeout = true
			s.appendAuditEvent(id, "timeout", fmt.Sprintf("Scan exceeded the %s budget; finalizing with %d partial finding(s)", s.scanTimeout, len(findings)))
			emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: fmt.Sprintf("Scan timed out after %s — finalizing with %d partial finding(s)", s.scanTimeout, len(findings)),
			})
		default:
			job.Status = "failed"
			job.Error = err.Error()
			emit(model.ScanEvent{
				Type:    model.ScanEventInfo,
				Message: "Scan failed: " + err.Error(),
			})
			s.appendAuditEvent(id, "failed", "Scan execution failed: "+err.Error())
			_ = s.persistJob(job)
			return
		}
	}

	job.Status = "finalizing"
	_ = s.persistJob(job)
	s.appendAuditEvent(id, "finalizing", fmt.Sprintf("Post-processing %d finding(s)", len(findings)))
	postProcessStart := time.Now()
	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: fmt.Sprintf("Post-processing %d findings…", len(findings)),
	})
	job.Findings = enrichFindings(findings)
	for _, f := range job.Findings {
		metrics.FindingRecorded(string(f.Severity))
	}
	beforeDedupCount := len(job.Findings)
	dedupedFindings, dedupSuppressed := deduplicateFindingsCrossAgent(job.Findings)
	job.Findings = dedupedFindings
	if dedupSuppressed > 0 {
		s.appendAuditEvent(id, "dedup", fmt.Sprintf("Suppressed %d duplicate findings before scoring", dedupSuppressed))
	}
	job.Findings = applyEvidenceQualityTiers(job.Findings)
	job.Findings = s.applyFeedbackConfidencePrioritization(context.Background(), job.Findings)
	job.Findings = redactSensitiveFindings(job.Findings)
	job.Findings = append(job.Findings, buildToolReadinessFindings(options)...)
	job.Findings = append(job.Findings, buildIntegrationHealthFinding(outputs)...)
	if partialTimeout {
		job.Findings = append(job.Findings, model.Finding{
			ID:             "scan-partial-timeout",
			Category:       "operations",
			Severity:       model.SeverityInfo,
			Title:          "Scan finalized with partial results after timeout",
			Description:    fmt.Sprintf("The scan exceeded its %s execution budget (SCAN_TIMEOUT_SECONDS) before every agent completed. Findings collected before the deadline are preserved and reported, but coverage may be incomplete.", s.scanTimeout),
			Evidence:       fmt.Sprintf("timeout=%s partialFindings=%d", s.scanTimeout, len(findings)),
			Recommendation: "Increase SCAN_TIMEOUT_SECONDS or narrow the scan scope, then re-run to achieve full coverage.",
			Confidence:     1.0,
			Sources:        []string{"operations"},
		})
	}
	job.Findings = s.applySuppressions(target, job.Findings)
	job.Findings = s.applyAutoSuppressionHeuristics(context.Background(), job.Findings)
	// Attach Python PoC scripts to findings where a template is available.
	for i := range job.Findings {
		job.Findings[i] = scanner.AttachPythonPoC(job.Findings[i], authProfile)
	}
	job.AgentRuns = buildAgentTelemetry(outputs)
	s.appendAuditEvent(id, "analysis", fmt.Sprintf("Collected %d deduplicated findings", len(findings)))
	if beforeDedupCount > 0 {
		s.appendAuditEvent(id, "analysis", fmt.Sprintf("Cross-agent dedupe ratio %.2f", 1.0-float64(len(job.Findings))/float64(beforeDedupCount)))
	}
	s.appendAuditEvent(id, "telemetry", fmt.Sprintf("Captured telemetry for %d agents", len(job.AgentRuns)))
	// Persist finding embeddings to the episodic vector memory store so
	// future scans against the same target have richer hypothesis context.
	if s.memoryStore != nil {
		go s.upsertFindingMemories(id, target, job.Findings)
	}
	if previousJob != nil {
		newItems, changedItems, resolvedItems, deltaFindings := buildDeltaFindings(previousJob.Findings, job.Findings)
		job.Findings = append(job.Findings, deltaFindings...)
		s.appendAuditEvent(id, "monitoring", fmt.Sprintf("Drift states: new=%d, changed=%d, resolved=%d", newItems, changedItems, resolvedItems))
	}
	// Suppress historically-rejected findings: look up operator-confirmed
	// rejections for this target across all prior scans. Any current finding
	// whose base fingerprint matches a rejected verification gets its
	// confidence halved and its drift status marked "historically_rejected"
	// so it stays visible for auditing while not meeting the strict-reporting
	// threshold.
	if rejectedVerifs, err := s.repo.GetRejectedFindingsByTarget(context.Background(), target); err == nil && len(rejectedVerifs) > 0 {
		rejectedKeys := make(map[string]bool, len(rejectedVerifs))
		for _, rv := range rejectedVerifs {
			if rv.FindingID != "" {
				rejectedKeys[rv.FindingID] = true
			}
		}
		if len(rejectedKeys) > 0 {
			suppressed := 0
			for i, f := range job.Findings {
				if rejectedKeys[fingerprintFindingBase(f)] || rejectedKeys[f.ID] {
					job.Findings[i].Confidence *= 0.5
					job.Findings[i].DriftStatus = "historically_rejected"
					if job.Findings[i].EvidenceFields == nil {
						job.Findings[i].EvidenceFields = map[string]string{}
					}
					job.Findings[i].EvidenceFields["historicallyRejected"] = "true"
					suppressed++
				}
			}
			if suppressed > 0 {
				s.appendAuditEvent(id, "analysis", fmt.Sprintf("Suppressed %d historically-rejected findings", suppressed))
			}
		}
	}
	if len(job.Findings) > len(findings) {
		s.appendAuditEvent(id, "monitoring", "Monitoring delta finding generated from previous completed scan")
	}
	assets := extractAssets(target, job.Findings)
	if err := s.persistAssets(id, assets); err == nil {
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
		if err := s.persistAttackGraph(id, target, graph); err == nil {
			job.AttackGraph = graph
			s.appendAuditEvent(id, "attack-graph", fmt.Sprintf("Persisted attack graph nodes=%d edges=%d", len(graph.Nodes), len(graph.Edges)))
		} else {
			log.Printf("api: scan %s intermediate attack graph persistence failed: %v", id, err)
		}
	}
	job.Dashboard = buildDecisionDashboard(job)
	// Best-effort post-scan enrichment (security-knowledge retrieval, AI
	// summary, narrative report, ML recommendations). These calls run on
	// external providers/sidecars or CPU-bound computations and must never
	// block scan finalization: the job is only persisted as "completed" and
	// the terminal "Scan completed" event emitted *after* this phase, so a
	// step that hangs while ignoring ctx cancellation would otherwise leave
	// the job stuck reporting "running" even though scanning is done.
	//
	// Bound the whole phase with a watchdog (mirroring the orchestrator's
	// agent/planner guards): the enrichment runs in a goroutine over immutable
	// snapshots and we proceed with whatever completed within the budget. A
	// step that overruns is abandoned to finish in the background; because it
	// only reads snapshots its result is simply discarded.
	budget := s.postProcessBudget
	if budget <= 0 {
		budget = postProcessTimeout
	}
	postCtx, postCancel := context.WithTimeout(context.Background(), budget)
	defer postCancel()

	if s.knowledgeSvc != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: "Retrieving security knowledge context…",
		})
	}
	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: "Generating AI summary…",
	})
	if s.mlService != nil {
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: "Computing ML recommendations…",
		})
	}

	// Snapshot the inputs the enrichment goroutine needs so it can never race
	// with the mutations the main goroutine performs on `job` after this phase.
	findingsSnapshot := append([]model.Finding(nil), job.Findings...)
	jobSnapshot := *job
	jobSnapshot.Findings = findingsSnapshot

	resultCh := make(chan enrichmentResult, 1)
	go func() {
		resultCh <- s.computeEnrichment(postCtx, target, findingsSnapshot, &jobSnapshot)
	}()

	var enrich enrichmentResult
	select {
	case enrich = <-resultCh:
	case <-postCtx.Done():
		log.Printf("api: scan %s post-processing enrichment exceeded budget %s; finalizing with partial AI/ML results: %v", id, budget, postCtx.Err())
		s.appendAuditEvent(id, "post-processing", "AI summary/ML enrichment exceeded time budget; scan finalized with partial results")
	}

	// If the operator cancelled the scan while it was in the finalizing phase,
	// honour that request now that enrichment has settled (completed or timed out).
	if errors.Is(ctx.Err(), context.Canceled) {
		now := time.Now().UTC()
		job.Status = "cancelled"
		job.Error = "scan stopped by operator"
		job.CompletedAt = &now
		emit(model.ScanEvent{
			Type:    model.ScanEventInfo,
			Message: "Scan cancelled by operator",
		})
		s.appendAuditEvent(id, "cancelled", "Scan cancelled by operator during post-processing")
		_ = s.persistJob(job)
		return
	}

	// Bound all remaining post-enrichment DB work (ROI calculation, ticket
	// sync, state persistence) with a fresh timeout so a slow or contended
	// database cannot keep the scan stuck in "finalizing" indefinitely.
	finCtx, finCancel := context.WithTimeout(context.Background(), postProcessTimeout)
	defer finCancel()

	knowledgeCtx := enrich.knowledgeCtx
	if knowledgeCtx != nil {
		s.appendAuditEvent(id, "security-knowledge", fmt.Sprintf("Retrieved %d curated references", len(knowledgeCtx.References)))
	}
	job.AISummary = enrich.aiSummary
	// Generate domain-aware narrative report enriching the AI summary.
	if enrich.haveNarr {
		narrative := enrich.narrative
		if strings.TrimSpace(narrative.ExecutiveSummary) != "" && strings.TrimSpace(job.AISummary) != "" {
			// Prepend the narrative executive summary and attack narrative to the AI summary.
			enhancedSummary := narrative.ExecutiveSummary
			if narrative.AttackNarrative != "" {
				enhancedSummary += "\n\nAttack Scenario: " + narrative.AttackNarrative
			}
			if narrative.ComplianceFramework != "" {
				enhancedSummary += "\n\nCompliance Framework: " + narrative.ComplianceFramework
			}
			if len(narrative.TopPriorities) > 0 {
				enhancedSummary += "\n\nTop Remediation Priorities:\n"
				for i, p := range narrative.TopPriorities {
					enhancedSummary += fmt.Sprintf("%d. %s\n", i+1, p)
				}
			}
			enhancedSummary += "\n\n---\n\n" + job.AISummary
			job.AISummary = enhancedSummary
		}
	}
	job.NextActions = buildNextActions(job)
	if enrich.recs != nil {
		job.ModelRecommendations = enrich.recs
		job.NextActions = mergeActions(job.NextActions, job.ModelRecommendations.Copilot.SuggestedActions)
		s.appendAuditEvent(id, "ml-inference", fmt.Sprintf("ML mode=%s tools=%d prioritized=%d", job.ModelRecommendations.ModelMode, len(job.ModelRecommendations.ToolSelection), len(job.ModelRecommendations.PrioritizedFindings)))
	}
	if knowledgeCtx != nil {
		if job.ModelRecommendations == nil {
			job.ModelRecommendations = &model.ModelRecommendations{ModelMode: "knowledge-retrieval"}
		}
		job.ModelRecommendations.SecurityKnowledge = knowledgeCtx
		job.NextActions = mergeActions(job.NextActions, knowledgeCtx.SuggestedActions)
	}
	expectedROI, roiBasis := s.estimateExpectedROI(finCtx, job)
	minROI := s.effectiveMinROI(finCtx, job)
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
		openTickets, resolvedTickets = s.syncAutomationTickets(finCtx, ticketTarget, job.Findings)
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
	job.AutomatedReport += "\n\n## Automation Postmortem\n" + generateAutomationPostmortem(job, outputs, dedupSuppressed)
	var surfaceSnapshot *model.SurfaceSnapshot
	if persistedState != nil {
		surfaceSnapshot = persistedState.SurfaceSnapshot
	}
	s.persistScanState(finCtx, target, job.Findings, outputs, options, surfaceSnapshot)
	s.appendAuditEvent(id, "ai-summary", "AI summary generated")
	s.appendAuditEvent(id, "report", "Automated penetration testing report generated")
	metrics.PostProcessDuration.Observe(time.Since(postProcessStart).Seconds())
	completedAt := time.Now().UTC()
	job.Status = "completed"
	job.CompletedAt = &completedAt
	if s.attackGraphDB != nil {
		finalGraph := attackgraph.Build(job)
		if err := s.persistAttackGraph(id, target, finalGraph); err == nil {
			job.AttackGraph = finalGraph
		} else {
			log.Printf("api: scan %s final attack graph persistence failed: %v", id, err)
		}
	}
	_ = s.persistJob(job)
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
		scanDurationMs = executionFinishedAt.Sub(job.StartedAt).Milliseconds()
		s.agentLearner.Learn(context.Background(), job.ID, agentSeq, job.Findings, scanDurationMs, job.AgentRuns)
	}
	completionAudit := "Scan execution completed successfully"
	completionSuffix := ""
	if partialTimeout {
		completionAudit = "Scan finalized with partial results after timeout"
		completionSuffix = " (partial — timed out)"
	}
	s.appendAuditEvent(id, "completed", completionAudit)
	emit(model.ScanEvent{
		Type:    model.ScanEventInfo,
		Message: fmt.Sprintf("Scan completed: %d findings%s", len(job.Findings), completionSuffix),
	})
	// Retain event history for a short window so late-joining SSE clients can still
	// replay events, then schedule cleanup to free memory.
	go func() {
		time.Sleep(5 * time.Minute)
		s.eventBus.Cleanup(id)
	}()
	if job.Options.RescanIntervalMinutes > 0 {
		nextOptions, adaptationNote := adaptOptionsFromDrift(job.Findings, options)
		if adaptationNote != "" {
			s.appendAuditEvent(id, "drift-adaptation", adaptationNote)
		}
		if meetsROIGate {
			s.appendAuditEvent(id, "scheduling", fmt.Sprintf("Scheduled rescan in %d minutes", job.Options.RescanIntervalMinutes))
			go s.scheduleRescan(target, job.WorkspaceID, job.RequestedBy, authProfile, nextOptions, scanScope, time.Duration(job.Options.RescanIntervalMinutes)*time.Minute)
		} else {
			s.appendAuditEvent(id, "scheduling", "Skipped scheduled rescan because ROI gate did not pass")
		}
	}
}

func hasOperatorOverrides(options model.ScanOptions) bool {
	return options.AutonomyEmergencyStop ||
		len(options.AutonomyForceRunAgents) > 0 ||
		len(options.AutonomySuppressAgents) > 0 ||
		strings.TrimSpace(options.AutonomyPlannerLock) != "" ||
		options.AutonomyFallbackRerun
}

func (s *Server) newRegistry(options model.ScanOptions) *agent.Registry {
	reg := agent.NewRegistry()

	reg.Register(agent.NewReconnaissanceAgent(true))
	reg.Register(agent.NewJavaScriptSASTAgent(s.scanService, true))
	reg.Register(agent.NewScanningAgent(s.scanService, true))
	reg.Register(agent.NewInputValidationAgent(true))
	reg.Register(agent.NewInformationDisclosureAgent(true))
	reg.Register(agent.NewAccessControlAgent(true))
	reg.Register(agent.NewAPISecurityAgent(true))
	reg.Register(agent.NewCORSRedirectAgent(true))
	reg.Register(agent.NewWordlistAgent(true))
	reg.Register(agent.NewAnalysisAgent(true))
	reg.Register(agent.NewAIToolCallingAgent(s.aiClient, options.UseAIToolCalling))

	// Autonomous tool-building agents — run after core scanning so they have
	// rich findings context to work from.  DynamicCommandAgent composes and
	// executes validated CLI tool invocations; ToolBuilderAgent writes and
	// runs custom Python probes for specialised tasks.
	reg.Register(agent.NewDynamicCommandAgent(true))
	reg.Register(agent.NewToolBuilderAgent(true, s.aiClient))

	mlTriageEnabled := options.UseMLTriageAgent
	attackPathEnabled := options.UseAttackPathAgent
	falsePositiveEnabled := options.UseFalsePositiveReview
	remediationEnabled := options.UseRemediationPlanner

	reg.Register(agent.NewMLTriageAgent(s.mlService, mlTriageEnabled))
	reg.Register(agent.NewAttackPathAgent(s.mlService, attackPathEnabled))
	reg.Register(agent.NewFalsePositiveReviewAgent(s.mlService, falsePositiveEnabled))
	reg.Register(agent.NewRemediationPlannerAgent(s.mlService, remediationEnabled))
	reg.Register(agent.NewImpactVerifierAgent(true))
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
		allowed := applyCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			if strings.TrimSpace(r.Header.Get("Origin")) != "" && !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
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
	if err := decodeJSONBody(w, r, &req); err != nil {
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

// handleScanAnnotate handles POST /api/scan/{id}/annotate. It persists a
// mid-scan operator observation that the hypothesis agent picks up on its next
// cycle to sharpen its probe list based on human insight.
func (s *Server) handleScanAnnotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Extract scan ID from path: /api/scan/{id}/annotate
	path := strings.TrimSuffix(r.URL.Path, "/annotate")
	scanID := strings.TrimPrefix(path, "/api/scan/")
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	var req struct {
		Text   string `json:"text"`
		Author string `json:"author,omitempty"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text is required"})
		return
	}
	if len(req.Text) > maxAnnotationTextLength {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("text must be %d characters or less", maxAnnotationTextLength)})
		return
	}

	// Verify the scan exists and is accessible in this workspace.
	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}

	annotation := model.ScanAnnotation{
		ID:          uuid.NewString(),
		ScanID:      scanID,
		WorkspaceID: job.WorkspaceID,
		Author:      strings.TrimSpace(req.Author),
		Text:        req.Text,
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.repo.SaveScanAnnotation(r.Context(), annotation); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist annotation"})
		return
	}
	// Also write the annotation as an audit event so it appears in the scan timeline.
	s.appendAuditEvent(scanID, "annotation", fmt.Sprintf("Operator annotation: %s", req.Text))
	writeJSON(w, http.StatusCreated, annotation)
}

// handleListScanAnnotations handles GET /api/scan/{id}/annotations.
// Returns all operator annotations for the given scan in chronological order.
func (s *Server) handleListScanAnnotations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	path := strings.TrimSuffix(r.URL.Path, "/annotations")
	scanID := strings.TrimPrefix(path, "/api/scan/")
	scanID = strings.TrimSpace(scanID)
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}

	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}

	annotations, err := s.repo.ListScanAnnotations(r.Context(), scanID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list annotations"})
		return
	}
	if annotations == nil {
		annotations = []model.ScanAnnotation{}
	}
	writeJSON(w, http.StatusOK, annotations)
}

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.ReportFeedback
	if err := decodeJSONBody(w, r, &req); err != nil {
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
	if err := decodeJSONBody(w, r, &req); err != nil {
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
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.Status = findingLifecycleAliases(req.Status)
	req.Owner = strings.TrimSpace(req.Owner)
	if req.ScanID == "" || req.FindingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanId and findingId are required"})
		return
	}
	allowedStates := map[string]bool{}
	for _, st := range model.FindingLifecycleStates {
		allowedStates[st] = true
	}
	// "new" is the implicit starting state and is not a valid transition target.
	if req.Status == "new" || !allowedStates[req.Status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of: verified, rejected, suppressed, accepted, remediated"})
		return
	}
	job, err := s.repo.GetJob(r.Context(), req.ScanID)
	if err != nil || job == nil || !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	priorStatus := ""
	if existing, err := s.repo.GetLatestFindingVerifications(r.Context(), req.ScanID); err == nil {
		if v, ok := existing[req.FindingID]; ok {
			priorStatus = v.Status
		}
	}
	if !isAllowedFindingTransition(priorStatus, req.Status) {
		fromLabel := priorStatus
		if fromLabel == "" {
			fromLabel = "new"
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("illegal lifecycle transition %s -> %s", fromLabel, req.Status)})
		return
	}
	if (req.Status == "accepted" || req.Status == "remediated") && req.Owner == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "owner is required for accepted or remediated transitions"})
		return
	}
	if req.VerifiedBy == "" {
		req.VerifiedBy = requesterFromRequest(r)
	}
	req.ID = uuid.NewString()
	req.CreatedAt = time.Now().UTC()
	if err := s.repo.SaveFindingVerification(r.Context(), req); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save verification"})
		return
	}
	s.persistShadowDecision(r.Context(), job, req)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": req.ID, "status": req.Status, "owner": req.Owner, "previousStatus": priorStatus})
}

func (s *Server) persistShadowDecision(ctx context.Context, job *model.ScanJob, verification model.FindingVerification) {
	writer, ok := s.repo.(shadowDecisionWriter)
	if !ok || s.mlService == nil || job == nil {
		return
	}
	finding, found := findingByID(job.Findings, verification.FindingID)
	if !found {
		return
	}
	assessment := s.mlService.AssessFalsePositiveCandidate(finding)
	operatorReject := verification.Status == "rejected" || verification.Status == "suppressed"
	decision := "keep"
	if assessment.Candidate {
		decision = "review_candidate"
	}
	shadow := model.ShadowDecision{
		ID:             uuid.NewString(),
		ScanID:         verification.ScanID,
		FindingID:      verification.FindingID,
		Category:       strings.ToLower(strings.TrimSpace(finding.Category)),
		Severity:       finding.Severity,
		ModelDecision:  decision,
		ModelScore:     roundTo2(assessment.Score),
		ModelThreshold: roundTo2(assessment.Threshold),
		OperatorStatus: verification.Status,
		Aligned:        (assessment.Candidate && operatorReject) || (!assessment.Candidate && !operatorReject),
		CreatedAt:      verification.CreatedAt,
	}
	_ = writer.SaveShadowDecision(ctx, shadow)
}

func findingByID(findings []model.Finding, id string) (model.Finding, bool) {
	id = strings.TrimSpace(id)
	for _, finding := range findings {
		if strings.TrimSpace(finding.ID) == id {
			return finding, true
		}
	}
	return model.Finding{}, false
}

// findingLifecycleAliases normalizes legacy/alias status values onto the
// canonical lifecycle state names. "confirmed" was the original verified
// label and remains accepted for backward-compatibility with existing
// integrations and persisted rows.
func findingLifecycleAliases(status string) string {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "confirmed" {
		return "verified"
	}
	return s
}

// isAllowedFindingTransition enforces the documented state machine:
//
//	new       -> verified | rejected | suppressed
//	verified  -> accepted | suppressed | remediated | rejected
//	rejected  -> verified
//	accepted  -> remediated | suppressed
//	suppressed-> verified
//	remediated-> verified            (regression detected)
//
// A "" (no prior verification on record) is treated as the implicit "new"
// starting state. Identical from/to is allowed (idempotent ownership update).
func isAllowedFindingTransition(from, to string) bool {
	from = findingLifecycleAliases(from)
	to = findingLifecycleAliases(to)
	if from == "" {
		from = "new"
	}
	if from == to {
		return true
	}
	allowed := map[string]map[string]bool{
		"new":        {"verified": true, "rejected": true, "suppressed": true},
		"verified":   {"accepted": true, "suppressed": true, "remediated": true, "rejected": true},
		"rejected":   {"verified": true},
		"accepted":   {"remediated": true, "suppressed": true},
		"suppressed": {"verified": true},
		"remediated": {"verified": true},
	}
	if next, ok := allowed[from]; ok && next[to] {
		return true
	}
	return false
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req model.SuppressionRule
	if err := decodeJSONBody(w, r, &req); err != nil {
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
		path = paths.ToolUpdatesReportPath()
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
	if err := decodeJSONBody(w, r, &req); err != nil {
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
		if err := decodeJSONBody(w, r, &req); err != nil {
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
		req.AuthorizationEvidence = normalizeAuthorizationEvidence(req.AuthorizationEvidence)
		if err := validateCampaignAuthorization(req, now); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		policyVersion := 0
		req.Options, policyVersion = s.applyAutomationPolicyPack(r.Context(), workspaceID, req.PolicyPack, req.Options)
		req.Options.MinExpectedROIUSD = maxFloat(req.Options.MinExpectedROIUSD, s.defaultMinROI)
		nextRunAt := computeNextCampaignRun(now, req)
		item := model.AutomationCampaign{
			ID:                    req.ID,
			Target:                target,
			WorkspaceID:           workspaceID,
			RequestedBy:           requesterFromRequest(r),
			PolicyPack:            req.PolicyPack,
			PolicyVersion:         policyVersion,
			AuthorizationApproval: req.AuthorizationApproval,
			AuthorizationEvidence: req.AuthorizationEvidence,
			Name:                  strings.TrimSpace(req.Name),
			ProgramName:           strings.TrimSpace(req.ProgramName),
			IntervalMin:           req.IntervalMin,
			ScheduleType:          req.ScheduleType,
			ScheduleValue:         strings.TrimSpace(req.ScheduleValue),
			RunWindow:             strings.TrimSpace(req.RunWindow),
			BlackoutWindows:       req.BlackoutWindows,
			NextRunAt:             nextRunAt,
			MaxAttempts:           maxInt(3, req.MaxAttempts),
			Active:                req.Active,
			AuthProfile:           req.AuthProfile,
			Options:               req.Options,
			Scope:                 req.Scope,
			CreatedAt:             now,
			UpdatedAt:             now,
		}
		if item.PolicyPack == "" {
			item.PolicyPack = defaultPolicyPack()
		}
		item.AuthorizationDigest = campaignAuthorizationDigest(item)
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

func (s *Server) handleAutomationCampaignAuthorizationExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	campaignID := strings.TrimSpace(r.URL.Query().Get("id"))
	if campaignID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id query parameter is required"})
		return
	}
	items, err := s.repo.ListAutomationCampaigns(r.Context(), workspaceID, false, 1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list automation campaigns"})
		return
	}
	var campaign *model.AutomationCampaign
	for i := range items {
		if strings.TrimSpace(items[i].ID) == campaignID {
			campaign = &items[i]
			break
		}
	}
	if campaign == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "campaign not found"})
		return
	}
	evidence := normalizeAuthorizationEvidence(campaign.AuthorizationEvidence)
	exportedAt := time.Now().UTC()
	payload := map[string]any{
		"schemaVersion":         "authorization-evidence.v1",
		"campaignId":            campaign.ID,
		"workspaceId":           campaign.WorkspaceID,
		"target":                campaign.Target,
		"policyPack":            campaign.PolicyPack,
		"policyVersion":         campaign.PolicyVersion,
		"authorizationApproval": campaign.AuthorizationApproval,
		"authorizationEvidence": evidence,
		"authorizationDigest":   firstNonEmpty(strings.TrimSpace(campaign.AuthorizationDigest), campaignAuthorizationDigest(*campaign)),
		"exportedAt":            exportedAt,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate authorization export"})
		return
	}
	sum := sha256.Sum256(raw)
	payload["exportHash"] = hex.EncodeToString(sum[:])
	writeJSON(w, http.StatusOK, payload)
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
		if err := decodeJSONBody(w, r, &req); err != nil {
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
	options.AutonomyCanaryPercent = maxInt(0, minInt(100, pack.CanaryPercent))
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
			if options.AutonomyCanaryPercent <= 0 {
				options.AutonomyCanaryPercent = p
			} else {
				options.AutonomyCanaryPercent = minInt(options.AutonomyCanaryPercent, p)
			}
			if p == 0 {
				options.MaxAutomationConcurrency = 1
				options.AutonomyExplorationBudgetPercent = 0
			} else {
				options.AutonomyExplorationBudgetPercent = maxInt(options.AutonomyExplorationBudgetPercent, minInt(25, maxInt(5, p/4)))
			}
		}
	}
	tenantTier := strings.ToLower(strings.TrimSpace(options.AutonomyTenantTier))
	if tenantTier == "" {
		tenantTier = "default"
	}
	if budget, ok := governance.TenantRiskBudgets[tenantTier]; ok {
		if budget.MaxExploitAttempts >= 0 {
			if options.MaxExploitAttempts <= 0 {
				options.MaxExploitAttempts = budget.MaxExploitAttempts
			} else {
				options.MaxExploitAttempts = minInt(options.MaxExploitAttempts, budget.MaxExploitAttempts)
			}
		}
		if budget.MaxPerTargetConcurrency > 0 {
			if options.MaxPerTargetConcurrency <= 0 {
				options.MaxPerTargetConcurrency = budget.MaxPerTargetConcurrency
			} else {
				options.MaxPerTargetConcurrency = minInt(options.MaxPerTargetConcurrency, budget.MaxPerTargetConcurrency)
			}
		}
		if budget.MaxAutomationConcurrency > 0 {
			if options.MaxAutomationConcurrency <= 0 {
				options.MaxAutomationConcurrency = budget.MaxAutomationConcurrency
			} else {
				options.MaxAutomationConcurrency = minInt(options.MaxAutomationConcurrency, budget.MaxAutomationConcurrency)
			}
		}
		if budget.DailyScanLimit > 0 {
			if options.DailyScanLimit <= 0 {
				options.DailyScanLimit = budget.DailyScanLimit
			} else {
				options.DailyScanLimit = minInt(options.DailyScanLimit, budget.DailyScanLimit)
			}
		}
		if budget.DailyRuntimeLimitMinutes > 0 {
			if options.DailyRuntimeLimitMinutes <= 0 {
				options.DailyRuntimeLimitMinutes = budget.DailyRuntimeLimitMinutes
			} else {
				options.DailyRuntimeLimitMinutes = minInt(options.DailyRuntimeLimitMinutes, budget.DailyRuntimeLimitMinutes)
			}
		}
		if budget.DailyProbeLimit > 0 {
			if options.DailyProbeLimit <= 0 {
				options.DailyProbeLimit = budget.DailyProbeLimit
			} else {
				options.DailyProbeLimit = minInt(options.DailyProbeLimit, budget.DailyProbeLimit)
			}
		}
	}
	if governance.CostControls.MaxRoundCostUnits > 0 {
		options.AutonomyMaxRoundCostUnits = governance.CostControls.MaxRoundCostUnits
	}
	if governance.CostControls.CostWeight > 0 {
		options.AutonomyCostWeight = clampFloat(governance.CostControls.CostWeight, 0.01, 1.0)
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
	for tier, budget := range profile.TenantRiskBudgets {
		if strings.TrimSpace(tier) == "" {
			return errors.New("tenantRiskBudgets tier key is required")
		}
		if budget.MaxExploitAttempts < 0 ||
			budget.MaxPerTargetConcurrency < 0 ||
			budget.MaxAutomationConcurrency < 0 ||
			budget.DailyScanLimit < 0 ||
			budget.DailyRuntimeLimitMinutes < 0 ||
			budget.DailyProbeLimit < 0 {
			return fmt.Errorf("tenantRiskBudgets[%s] values must be >= 0", tier)
		}
	}
	if profile.CostControls.MaxRoundCostUnits < 0 {
		return errors.New("costControls.maxRoundCostUnits must be >= 0")
	}
	if profile.CostControls.CostWeight < 0 || profile.CostControls.CostWeight > 1 {
		return errors.New("costControls.costWeight must be between 0 and 1")
	}
	return nil
}

// PolicyProfileBudgetSpec describes the explicit risk-budget bounds enforced
// for a given default automation profile (safe / autonomous / aggressive /
// canary). Bounds are expressed as inclusive ranges and surface to operators
// via the /api/automation/policy-profile-defaults endpoint so that the UI can
// render guidance and the API can reject out-of-range policy packs.
type PolicyProfileBudgetSpec struct {
	Mode                        string  `json:"automationMode"`
	Description                 string  `json:"description,omitempty"`
	MaxExploitAttemptsMin       int     `json:"maxExploitAttemptsMin"`
	MaxExploitAttemptsMax       int     `json:"maxExploitAttemptsMax"`
	MaxAutomationConcurrencyMin int     `json:"maxAutomationConcurrencyMin"`
	MaxAutomationConcurrencyMax int     `json:"maxAutomationConcurrencyMax"`
	MaxPerTargetConcurrencyMin  int     `json:"maxPerTargetConcurrencyMin"`
	MaxPerTargetConcurrencyMax  int     `json:"maxPerTargetConcurrencyMax"`
	DailyScanLimitMin           int     `json:"dailyScanLimitMin"`
	DailyScanLimitMax           int     `json:"dailyScanLimitMax"`
	DailyRuntimeLimitMinutesMin int     `json:"dailyRuntimeLimitMinutesMin"`
	DailyRuntimeLimitMinutesMax int     `json:"dailyRuntimeLimitMinutesMax"`
	DailyProbeLimitMin          int     `json:"dailyProbeLimitMin"`
	DailyProbeLimitMax          int     `json:"dailyProbeLimitMax"`
	MinExpectedROIUSDMin        float64 `json:"minExpectedRoiUsdMin"`
}

// policyProfileBudgetSpecs returns the canonical risk-budget envelopes for
// each supported automation mode. Operators must publish a policy pack whose
// values fall inside these envelopes; this is what makes "every automated run
// is attached to a policy profile and budget decision record" enforceable
// rather than advisory.
func policyProfileBudgetSpecs() map[string]PolicyProfileBudgetSpec {
	return map[string]PolicyProfileBudgetSpec{
		"safe": {
			Mode:                        "safe",
			Description:                 "Read-mostly profile: no exploit attempts, single-stream concurrency, conservative daily caps.",
			MaxExploitAttemptsMin:       0,
			MaxExploitAttemptsMax:       0,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 1,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  1,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           50,
			DailyRuntimeLimitMinutesMin: 15,
			DailyRuntimeLimitMinutesMax: 240,
			DailyProbeLimitMin:          1,
			DailyProbeLimitMax:          2000,
			MinExpectedROIUSDMin:        0,
		},
		"autonomous": {
			Mode:                        "autonomous",
			Description:                 "Default unattended profile: bounded exploitation, modest concurrency, mandatory daily caps.",
			MaxExploitAttemptsMin:       1,
			MaxExploitAttemptsMax:       3,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 4,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  3,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           200,
			DailyRuntimeLimitMinutesMin: 30,
			DailyRuntimeLimitMinutesMax: 720,
			DailyProbeLimitMin:          100,
			DailyProbeLimitMax:          10000,
			MinExpectedROIUSDMin:        25,
		},
		"aggressive": {
			Mode:                        "aggressive",
			Description:                 "Bug-bounty profile: deep exploitation allowed, higher concurrency, larger daily caps still required.",
			MaxExploitAttemptsMin:       3,
			MaxExploitAttemptsMax:       12,
			MaxAutomationConcurrencyMin: 2,
			MaxAutomationConcurrencyMax: 8,
			MaxPerTargetConcurrencyMin:  2,
			MaxPerTargetConcurrencyMax:  6,
			DailyScanLimitMin:           5,
			DailyScanLimitMax:           500,
			DailyRuntimeLimitMinutesMin: 60,
			DailyRuntimeLimitMinutesMax: 1440,
			DailyProbeLimitMin:          500,
			DailyProbeLimitMax:          50000,
			MinExpectedROIUSDMin:        50,
		},
		"canary": {
			Mode:                        "canary",
			Description:                 "Gradual-rollout profile: minimal exploit attempts and single-stream concurrency for new strategies.",
			MaxExploitAttemptsMin:       0,
			MaxExploitAttemptsMax:       1,
			MaxAutomationConcurrencyMin: 1,
			MaxAutomationConcurrencyMax: 1,
			MaxPerTargetConcurrencyMin:  1,
			MaxPerTargetConcurrencyMax:  1,
			DailyScanLimitMin:           1,
			DailyScanLimitMax:           50,
			DailyRuntimeLimitMinutesMin: 15,
			DailyRuntimeLimitMinutesMax: 240,
			DailyProbeLimitMin:          1,
			DailyProbeLimitMax:          5000,
			MinExpectedROIUSDMin:        0,
		},
	}
}

// validatePolicyPackBudgets enforces the per-profile budget envelope on an
// AutomationPolicyPack upsert request. Returning an error rejects the upsert
// with a descriptive 400 so operators understand which budget knob is
// out-of-range. Required values that are zero/empty are reported as
// "must be set" — the goal is to make budget decisions explicit, not silent.
func validatePolicyPackBudgets(req model.AutomationPolicyPack) error {
	mode := normalizeAutomationMode(req.AutomationMode)
	spec, ok := policyProfileBudgetSpecs()[mode]
	if !ok {
		return fmt.Errorf("unknown automationMode %q", req.AutomationMode)
	}
	check := func(field string, value, min, max int) error {
		if value < min {
			if value == 0 && min > 0 {
				return fmt.Errorf("%s must be set for %s profile (min %d)", field, mode, min)
			}
			return fmt.Errorf("%s=%d is below %s profile minimum %d", field, value, mode, min)
		}
		if value > max {
			return fmt.Errorf("%s=%d exceeds %s profile maximum %d", field, value, mode, max)
		}
		return nil
	}
	if err := check("maxExploitAttempts", req.MaxExploitAttempts, spec.MaxExploitAttemptsMin, spec.MaxExploitAttemptsMax); err != nil {
		return err
	}
	if err := check("maxAutomationConcurrency", req.MaxAutomationConcurrency, spec.MaxAutomationConcurrencyMin, spec.MaxAutomationConcurrencyMax); err != nil {
		return err
	}
	if err := check("maxPerTargetConcurrency", req.MaxPerTargetConcurrency, spec.MaxPerTargetConcurrencyMin, spec.MaxPerTargetConcurrencyMax); err != nil {
		return err
	}
	if err := check("dailyScanLimit", req.DailyScanLimit, spec.DailyScanLimitMin, spec.DailyScanLimitMax); err != nil {
		return err
	}
	if err := check("dailyRuntimeLimitMinutes", req.DailyRuntimeLimitMinutes, spec.DailyRuntimeLimitMinutesMin, spec.DailyRuntimeLimitMinutesMax); err != nil {
		return err
	}
	if err := check("dailyProbeLimit", req.DailyProbeLimit, spec.DailyProbeLimitMin, spec.DailyProbeLimitMax); err != nil {
		return err
	}
	if req.MinExpectedROIUSD < spec.MinExpectedROIUSDMin {
		return fmt.Errorf("minExpectedRoiUsd=%.2f is below %s profile minimum %.2f", req.MinExpectedROIUSD, mode, spec.MinExpectedROIUSDMin)
	}
	return nil
}

func (s *Server) handlePolicyProfileDefaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	specs := policyProfileBudgetSpecs()
	out := make([]PolicyProfileBudgetSpec, 0, len(specs))
	for _, mode := range []string{"safe", "autonomous", "aggressive", "canary"} {
		if v, ok := specs[mode]; ok {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func shouldPersistAgentEvent(eventType model.ScanEventType) bool {
	switch eventType {
	case model.ScanEventAgentStart,
		model.ScanEventAgentComplete,
		model.ScanEventAgentSpawned,
		model.ScanEventInfo,
		model.ScanEventReasoningLoop,
		model.ScanEventThinking,
		model.ScanEventDiscovery,
		model.ScanEventCommand,
		model.ScanEventCommandResult,
		model.ScanEventFinding,
		model.ScanEventScreenshot:
		return true
	default:
		return false
	}
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
		if err := decodeJSONBody(w, r, &req); err != nil {
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
		if err := validatePolicyPackBudgets(req); err != nil {
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
	outcomeByStrategy := map[string]float64{}
	outcomeSamplesByStrategy := map[string]int{}
	canaryByPolicy := map[string]int{}
	failedRuns := 0
	totalRuns := 0
	fallbackRuns := 0
	fallbackRecoveredRuns := 0
	outcomeScoreTotal := 0.0
	outcomeScoreSamples := 0
	verifiedSampled := 0
	rejectedCount := 0
	verifiedByCategory := map[string]int{}
	rejectedByCategory := map[string]int{}
	strictScans := 0
	strictSuppressed := 0
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
		outcomeScore := autonomyOutcomeScore(job)
		outcomeByStrategy[strategy] += outcomeScore
		outcomeSamplesByStrategy[strategy]++
		outcomeScoreTotal += outcomeScore
		outcomeScoreSamples++
		strategyCounts[strategy]++
		for _, run := range job.AgentRuns {
			totalRuns++
			if strings.EqualFold(strings.TrimSpace(run.Status), "failed") || run.TimedOut {
				failedRuns++
			}
			if run.Metadata != nil && strings.EqualFold(strings.TrimSpace(run.Metadata["autonomy_fallback"]), "static") {
				fallbackRuns++
				if strings.EqualFold(strings.TrimSpace(run.Status), "completed") && !run.TimedOut && strings.TrimSpace(run.Error) == "" {
					fallbackRecoveredRuns++
				}
			}
		}
		if job.Options.StrictReporting {
			strictScans++
			if filtered, suppressed, _, applied := applyStrictReportingFilter(job, nil); applied && filtered != nil {
				strictSuppressed += suppressed
			}
		}
		findingCategory := map[string]string{}
		for _, finding := range job.Findings {
			key := strings.TrimSpace(finding.ID)
			if key == "" {
				continue
			}
			findingCategory[key] = strings.ToLower(strings.TrimSpace(finding.Category))
		}
		if verifications, err := s.repo.GetLatestFindingVerifications(r.Context(), job.ID); err == nil {
			for _, v := range verifications {
				cat := strings.TrimSpace(findingCategory[strings.TrimSpace(v.FindingID)])
				switch findingLifecycleAliases(v.Status) {
				case "verified", "rejected", "suppressed", "accepted", "remediated":
					verifiedSampled++
					if cat != "" {
						verifiedByCategory[cat]++
					}
				}
				switch findingLifecycleAliases(v.Status) {
				case "rejected", "suppressed":
					rejectedCount++
					if cat != "" {
						rejectedByCategory[cat]++
					}
				}
			}
		}
	}
	falsePositiveByCategory := map[string]float64{}
	for cat, total := range verifiedByCategory {
		if total <= 0 {
			continue
		}
		falsePositiveByCategory[cat] = roundTo2(float64(rejectedByCategory[cat]) / float64(total))
	}
	shadowAlignmentByCategory := map[string]float64{}
	shadowSamplesByCategory := map[string]int{}
	shadowAlignedByCategory := map[string]int{}
	shadowSamples := 0
	shadowAligned := 0
	if reader, ok := s.repo.(shadowDecisionReader); ok {
		if shadowRows, err := reader.ListShadowDecisions(r.Context(), now.Add(-90*24*time.Hour), 10000); err == nil {
			for _, row := range shadowRows {
				shadowSamples++
				if row.Aligned {
					shadowAligned++
				}
				cat := strings.ToLower(strings.TrimSpace(row.Category))
				if cat != "" {
					shadowSamplesByCategory[cat]++
					if row.Aligned {
						shadowAlignedByCategory[cat]++
					}
				}
			}
		}
	}
	for cat, total := range shadowSamplesByCategory {
		if total <= 0 {
			continue
		}
		shadowAlignmentByCategory[cat] = roundTo2(float64(shadowAlignedByCategory[cat]) / float64(total))
	}
	if packs, err := s.repo.ListAutomationPolicyPacks(r.Context(), workspaceID, 200); err == nil {
		for _, pack := range packs {
			name := normalizePolicyPackName(pack.Name)
			if name == "" {
				continue
			}
			canaryByPolicy[name] = maxInt(0, minInt(100, pack.CanaryPercent))
		}
	}
	rollbackEventsRecent := 0
	if auditItems, err := s.repo.ListAutomationPolicyAudit(r.Context(), workspaceID, "", 300); err == nil {
		for _, item := range auditItems {
			action := strings.ToLower(strings.TrimSpace(item.Action))
			if strings.Contains(action, "rollback") {
				rollbackEventsRecent++
			}
		}
	}
	for name, total := range strategyCounts {
		if total > 0 {
			strategyROI[name] = roundTo2(strategyROI[name] / float64(total))
		}
	}
	for name, total := range outcomeSamplesByStrategy {
		if total > 0 {
			outcomeByStrategy[name] = roundTo2(outcomeByStrategy[name] / float64(total))
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
	avgOutcomeScore := 0.0
	if outcomeScoreSamples > 0 {
		avgOutcomeScore = outcomeScoreTotal / float64(outcomeScoreSamples)
	}
	if avgOutcomeScore > 0 && avgOutcomeScore < floatFromEnv("AUTOMATION_ALERT_AUTONOMY_OUTCOME_SCORE", 0.45) {
		alerts = append(alerts, "autonomy outcome score dropped below threshold")
	}
	fallbackRecoveryRate := 0.0
	if fallbackRuns > 0 {
		fallbackRecoveryRate = float64(fallbackRecoveredRuns) / float64(fallbackRuns)
	}
	if fallbackRuns > 0 && fallbackRecoveryRate < floatFromEnv("AUTOMATION_ALERT_FALLBACK_RECOVERY_RATE", 0.5) {
		alerts = append(alerts, "autonomy fallback recovery rate below threshold")
	}
	killSwitchActive := boolFromEnv("AUTONOMY_GLOBAL_KILL_SWITCH", false)
	if killSwitchActive {
		alerts = append(alerts, "autonomy global kill switch is active")
	}
	writeJSON(w, http.StatusOK, model.AutomationMetrics{
		GeneratedAt:           now,
		WorkspaceID:           workspaceID,
		QueueLagSeconds:       roundTo2(avgLag),
		MaxQueueLag:           roundTo2(maxLag),
		RetryRate:             roundTo2(retryRate),
		DLQCount:              dlq,
		ToolFailureRate:       roundTo2(toolFailureRate),
		ROIByStrategy:         strategyROI,
		StrategyRunCounts:     strategyCounts,
		Alerts:                alerts,
		CanaryPercentByPolicy: canaryByPolicy,
		RollbackEventsRecent:  rollbackEventsRecent,
		FalsePositiveRate: func() float64 {
			if verifiedSampled == 0 {
				return 0
			}
			return roundTo2(float64(rejectedCount) / float64(verifiedSampled))
		}(),
		FalsePositiveRateByCategory: falsePositiveByCategory,
		VerifiedFindingsByCategory:  verifiedByCategory,
		ShadowAlignmentRate: func() float64 {
			if shadowSamples == 0 {
				return 0
			}
			return roundTo2(float64(shadowAligned) / float64(shadowSamples))
		}(),
		ShadowAlignmentByCategory:   shadowAlignmentByCategory,
		ShadowSamples:               shadowSamples,
		VerifiedFindingsSampled:     verifiedSampled,
		StrictReportingSuppressed:   strictSuppressed,
		StrictReportingScansSampled: strictScans,
		StrictReportingSuppressRate: func() float64 {
			if strictScans == 0 {
				return 0
			}
			return roundTo2(float64(strictSuppressed) / float64(strictScans))
		}(),
		Extra: map[string]float64{
			"lagSamples":                   float64(lagCount),
			"agentRuns":                    float64(totalRuns),
			"autonomyOutcomeScore":         roundTo2(avgOutcomeScore),
			"autonomyFallbackRuns":         float64(fallbackRuns),
			"autonomyFallbackRecoveryRate": roundTo2(fallbackRecoveryRate),
			"autonomyKillSwitchActive": func() float64 {
				if killSwitchActive {
					return 1
				}
				return 0
			}(),
		},
	})
}

func autonomyOutcomeScore(job *model.ScanJob) float64 {
	if job == nil {
		return 0
	}
	completion := 0.0
	switch strings.ToLower(strings.TrimSpace(job.Status)) {
	case "completed":
		completion = 1
	case "cancelled":
		completion = 0.2
	}
	runSuccess := 0.0
	if len(job.AgentRuns) == 0 {
		if completion > 0 {
			runSuccess = completion
		}
	} else {
		success := 0
		for _, run := range job.AgentRuns {
			if strings.EqualFold(strings.TrimSpace(run.Status), "completed") && !run.TimedOut && strings.TrimSpace(run.Error) == "" {
				success++
			}
		}
		runSuccess = float64(success) / float64(len(job.AgentRuns))
	}
	highSignal := 0
	for _, finding := range job.Findings {
		if finding.Confidence >= 0.75 || finding.Severity == model.SeverityHigh {
			highSignal++
		}
	}
	signalQuality := 0.0
	if len(job.Findings) > 0 {
		signalQuality = float64(highSignal) / float64(len(job.Findings))
	}
	return clampFloat(completion*0.5+runSuccess*0.3+signalQuality*0.2, 0, 1)
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
	if err := decodeJSONBody(w, r, &req); err != nil {
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
			if pack.GovernanceProfile.RolloutControl.AutoRollbackOnKPIRegression && pack.CanaryPercent > 0 {
				beforeRaw, _ := json.Marshal(pack)
				next := *pack
				next.CanaryPercent = 0
				next.UpdatedBy = requesterFromRequest(r)
				next.UpdatedAt = time.Now().UTC()
				if err := s.repo.UpsertAutomationPolicyPack(r.Context(), next); err == nil {
					afterRaw, _ := json.Marshal(next)
					_ = s.repo.AppendAutomationPolicyAudit(r.Context(), model.AutomationPolicyAuditEvent{
						ID:              uuid.NewString(),
						WorkspaceID:     workspaceID,
						PolicyPack:      packName,
						StrategyVersion: next.StrategyVersion,
						Action:          "auto-rollback-kpi",
						ChangedBy:       requesterFromRequest(r),
						ChangedAt:       time.Now().UTC(),
						BeforeJSON:      string(beforeRaw),
						AfterJSON:       string(afterRaw),
					})
					writeJSON(w, http.StatusPreconditionFailed, map[string]any{
						"error":           "replay benchmark did not meet minimum KPI delta score",
						"delta":           fmt.Sprintf("%.3f", delta),
						"rollbackApplied": true,
						"canaryPercent":   0,
					})
					return
				}
			}
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
	uncorroborated := 0
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityHigh:
			result.HighCount++
			result.BlockedFindings = append(result.BlockedFindings, f.Title)
			if !findingHasHighSeverityCorroboration(f) {
				uncorroborated++
				if result.UncorroboratedHighFindings == nil {
					result.UncorroboratedHighFindings = make([]string, 0, 1)
				}
				result.UncorroboratedHighFindings = append(result.UncorroboratedHighFindings, f.Title)
			}
		case model.SeverityMedium:
			result.MediumCount++
		}
	}
	thresholdExceeded := result.HighCount >= highBlock || result.MediumCount >= medBlock
	switch {
	case thresholdExceeded && uncorroborated > 0:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s high=%d medium=%d exceeded thresholds high>=%d or medium>=%d; %d high finding(s) lack multi-source corroboration or verified exploitability", strings.TrimSpace(policyPack), result.HighCount, result.MediumCount, highBlock, medBlock, uncorroborated)
	case thresholdExceeded:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s high=%d medium=%d exceeded thresholds high>=%d or medium>=%d", strings.TrimSpace(policyPack), result.HighCount, result.MediumCount, highBlock, medBlock)
	case uncorroborated > 0:
		result.Status = "blocked"
		result.Reason = fmt.Sprintf("policy_pack=%s %d high finding(s) lack multi-source corroboration or verified exploitability", strings.TrimSpace(policyPack), uncorroborated)
	default:
		result.Reason = fmt.Sprintf("policy_pack=%s thresholds satisfied", strings.TrimSpace(policyPack))
	}
	return result
}

// findingHasHighSeverityCorroboration returns true when a HIGH finding meets
// at least one of the corroboration requirements that gate publication:
//   - confirmed by ≥2 distinct agents/tools (Sources), or
//   - explicit reachable exploitability evidence, or
//   - operator-verified exploitability status (verified/confirmed).
//
// Findings emitted by the policy/governance subsystems themselves (e.g. the
// "policy-gate-blocked-release" sentinel) are exempt to avoid recursive
// blocking.
func findingHasHighSeverityCorroboration(f model.Finding) bool {
	if strings.EqualFold(strings.TrimSpace(f.Category), "governance") {
		return true
	}
	distinct := map[string]struct{}{}
	for _, src := range f.Sources {
		s := strings.ToLower(strings.TrimSpace(src))
		if s == "" {
			continue
		}
		distinct[s] = struct{}{}
	}
	if len(distinct) >= 2 {
		return true
	}
	if f.Exploitability != nil {
		if f.Exploitability.Reachable {
			return true
		}
		switch strings.ToLower(strings.TrimSpace(f.Exploitability.VerifiedStatus)) {
		case "verified", "confirmed":
			return true
		}
	}
	return false
}

func (s *Server) tuneScanOptions(ctx context.Context, target string, options model.ScanOptions, state *model.PersistentScanState, previous *model.ScanJob) model.ScanOptions {
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

	// Gap 13: adaptive category budget.
	// Inspect the previous scan's probe records to identify categories that
	// produced exclusively no_signal outcomes (≥ noSignalMinProbes probes with
	// ≥ noSignalRateThreshold fraction of no_signal). Those categories are
	// appended to AutonomySuppressAgents as "skip-cat:<category>" entries so
	// that AdaptiveProbeAgent can forward them to the AI as a low-priority
	// advisory rather than wasting step budget on provably-clean attack surface.
	if previous != nil && previous.ID != "" {
		records, err := s.repo.ListProbeRecords(ctx, previous.ID)
		if err == nil && len(records) > 0 {
			type catStats struct{ total, noSignal int }
			stats := make(map[string]*catStats)
			for _, r := range records {
				if r.Category == "" {
					continue
				}
				if stats[r.Category] == nil {
					stats[r.Category] = &catStats{}
				}
				stats[r.Category].total++
				if r.Outcome == model.ProbeNoSignal {
					stats[r.Category].noSignal++
				}
			}
			for cat, cs := range stats {
				if cs.total >= noSignalMinProbes &&
					float64(cs.noSignal)/float64(cs.total) >= noSignalRateThreshold {
					options.AutonomySuppressAgents = append(
						options.AutonomySuppressAgents,
						"skip-cat:"+cat,
					)
				}
			}
		}
	}

	return options
}

func normalizeAutomationMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "safe", "aggressive", "autonomous", "canary":
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

func validateCampaignAuthorization(req model.AutomationCampaignUpsertRequest, now time.Time) error {
	approval := req.AuthorizationApproval
	evidence := normalizeAuthorizationEvidence(req.AuthorizationEvidence)
	if !req.Active && strings.TrimSpace(approval.Signature) == "" && len(evidence) == 0 {
		return nil
	}
	if strings.TrimSpace(approval.ApprovedBy) == "" {
		return fmt.Errorf("authorizationApproval.approvedBy is required")
	}
	if strings.TrimSpace(approval.ApproverRole) == "" {
		return fmt.Errorf("authorizationApproval.approverRole is required")
	}
	if strings.TrimSpace(approval.Signature) == "" {
		return fmt.Errorf("authorizationApproval.signature is required")
	}
	if approval.ApprovedAt.IsZero() {
		return fmt.Errorf("authorizationApproval.approvedAt is required")
	}
	if approval.ApprovedAt.After(now.Add(campaignApprovalClockSkewTolerance)) {
		return fmt.Errorf("authorizationApproval.approvedAt cannot be more than %d minutes in the future", int(campaignApprovalClockSkewTolerance.Minutes()))
	}
	if len(evidence) == 0 {
		return fmt.Errorf("authorizationEvidence must include at least one record")
	}
	for i := range evidence {
		ev := evidence[i]
		if strings.TrimSpace(ev.Type) == "" {
			return fmt.Errorf("authorizationEvidence[%d].type is required", i)
		}
		if strings.TrimSpace(ev.Label) == "" {
			return fmt.Errorf("authorizationEvidence[%d].label is required", i)
		}
		if strings.TrimSpace(ev.URI) == "" && strings.TrimSpace(ev.SHA256) == "" {
			return fmt.Errorf("authorizationEvidence[%d] requires uri or sha256", i)
		}
		if sum := strings.TrimSpace(ev.SHA256); sum != "" && !isSHA256Hex(sum) {
			return fmt.Errorf("authorizationEvidence[%d].sha256 must be a 64-char hex digest", i)
		}
	}
	return nil
}

func normalizeAuthorizationEvidence(in []model.AuthorizationEvidence) []model.AuthorizationEvidence {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.AuthorizationEvidence, 0, len(in))
	for _, ev := range in {
		ev.Type = strings.ToLower(strings.TrimSpace(ev.Type))
		ev.Label = strings.TrimSpace(ev.Label)
		ev.URI = strings.TrimSpace(ev.URI)
		ev.Description = strings.TrimSpace(ev.Description)
		ev.SHA256 = strings.ToLower(strings.TrimSpace(ev.SHA256))
		if ev.Type == "" && ev.Label == "" && ev.URI == "" && ev.SHA256 == "" && ev.Description == "" {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].Label != out[j].Label {
			return out[i].Label < out[j].Label
		}
		if out[i].URI != out[j].URI {
			return out[i].URI < out[j].URI
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func campaignAuthorizationDigest(c model.AutomationCampaign) string {
	canonical := struct {
		CampaignID            string                        `json:"campaignId"`
		WorkspaceID           string                        `json:"workspaceId"`
		Target                string                        `json:"target"`
		PolicyPack            string                        `json:"policyPack"`
		PolicyVersion         int                           `json:"policyVersion"`
		AuthorizationApproval model.AuthorizationApproval   `json:"authorizationApproval"`
		AuthorizationEvidence []model.AuthorizationEvidence `json:"authorizationEvidence"`
	}{
		CampaignID:            strings.TrimSpace(c.ID),
		WorkspaceID:           strings.TrimSpace(c.WorkspaceID),
		Target:                strings.TrimSpace(c.Target),
		PolicyPack:            strings.TrimSpace(c.PolicyPack),
		PolicyVersion:         c.PolicyVersion,
		AuthorizationApproval: c.AuthorizationApproval,
		AuthorizationEvidence: normalizeAuthorizationEvidence(c.AuthorizationEvidence),
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		fallback := []byte(fmt.Sprintf("%s|%s|%s|%s|%d|%s|%s",
			canonical.CampaignID,
			canonical.WorkspaceID,
			canonical.Target,
			canonical.PolicyPack,
			canonical.PolicyVersion,
			strings.TrimSpace(canonical.AuthorizationApproval.Signature),
			strings.TrimSpace(canonical.AuthorizationApproval.ApprovedBy),
		))
		sum := sha256.Sum256(fallback)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func isSHA256Hex(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return false
	}
	return len(decoded) == sha256.Size
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
	case "canary":
		options.MaxExploitAttempts = minInt(maxInt(options.MaxExploitAttempts, 1), 1)
		options.MaxPerTargetConcurrency = minInt(maxInt(1, options.MaxPerTargetConcurrency), 1)
		options.MaxAutomationConcurrency = minInt(maxInt(1, options.MaxAutomationConcurrency), 1)
		options.RescanIntervalMinutes = maxInt(options.RescanIntervalMinutes, maxInt(30, options.MinRescanIntervalMinutes))
		options.AggressiveExploitation = false
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

func (s *Server) syncAutomationTickets(ctx context.Context, target string, findings []model.Finding) (int, int) {
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
		if err := s.repo.UpsertAutomationTicket(ctx, ticket); err == nil {
			open++
		}
	}
	resolved, _ := s.repo.ResolveAutomationTicketsMissingFingerprints(ctx, target, currentFingerprints, now)
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

func normalizedFindingKey(f model.Finding) string {
	category := normalizeDedupToken(f.Category)
	title := normalizeDedupToken(f.Title)
	evidence := normalizeDedupToken(f.Evidence)
	if len(evidence) > 160 {
		evidence = evidence[:160]
	}
	param := normalizeDedupToken(f.AffectedParameter)
	host := normalizeDedupToken(hostFromTarget(strings.TrimSpace(f.AffectedURL)))
	id := normalizeDedupToken(f.ID)
	cwe := normalizeDedupToken(f.CWE)
	return strings.Join([]string{category, title, evidence, param, host, id, cwe}, "|")
}

func normalizeDedupToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	lastSpace := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastSpace = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

func deduplicateFindingsCrossAgent(findings []model.Finding) ([]model.Finding, int) {
	if len(findings) <= 1 {
		return findings, 0
	}
	type cluster struct {
		rep   model.Finding
		count int
	}
	clusters := map[string]cluster{}
	order := make([]string, 0, len(findings))
	for _, f := range findings {
		key := normalizedFindingKey(f)
		cur, ok := clusters[key]
		if !ok {
			clusters[key] = cluster{rep: f, count: 1}
			order = append(order, key)
			continue
		}
		cur.count++
		if severityWeight(f.Severity) > severityWeight(cur.rep.Severity) ||
			(severityWeight(f.Severity) == severityWeight(cur.rep.Severity) && f.Confidence > cur.rep.Confidence) {
			cur.rep = f
		}
		cur.rep.Sources = dedupeStrings(append(cur.rep.Sources, f.Sources...))
		clusters[key] = cur
	}
	out := make([]model.Finding, 0, len(clusters))
	for _, key := range order {
		cur := clusters[key]
		if cur.count > 1 {
			if cur.rep.EvidenceFields == nil {
				cur.rep.EvidenceFields = map[string]string{}
			}
			cur.rep.EvidenceFields["duplicateClusterSize"] = fmt.Sprintf("%d", cur.count)
		}
		out = append(out, cur.rep)
	}

	// Second-pass semantic deduplication: merge findings that share the same
	// (category, affected-URL-host, affected-parameter) tuple even when their
	// title, evidence text, or agent-assigned IDs differ. This collapses
	// independent agents that independently detected the same vulnerability
	// instance with slightly different wording.
	type semanticKey struct {
		category string
		host     string
		param    string
	}
	semClusters := map[semanticKey]int{} // maps semKey → index in out
	semOrder := make([]model.Finding, 0, len(out))
	for _, f := range out {
		sk := semanticKey{
			category: strings.ToLower(strings.TrimSpace(f.Category)),
			host:     normalizeDedupToken(hostFromTarget(strings.TrimSpace(f.AffectedURL))),
			param:    normalizeDedupToken(f.AffectedParameter),
		}
		// Only collapse when all three fields are non-empty to avoid
		// over-aggressive merging of host-level or category-level findings.
		if sk.category == "" || sk.host == "" || sk.param == "" {
			semOrder = append(semOrder, f)
			continue
		}
		idx, exists := semClusters[sk]
		if !exists {
			semClusters[sk] = len(semOrder)
			semOrder = append(semOrder, f)
			continue
		}
		rep := semOrder[idx]
		// Keep the highest-confidence, highest-severity representative.
		if severityWeight(f.Severity) > severityWeight(rep.Severity) ||
			(severityWeight(f.Severity) == severityWeight(rep.Severity) && f.Confidence > rep.Confidence) {
			rep = f
		}
		rep.Sources = dedupeStrings(append(rep.Sources, f.Sources...))
		if rep.EvidenceFields == nil {
			rep.EvidenceFields = map[string]string{}
		}
		rep.EvidenceFields["semanticDuplicateMerged"] = "true"
		semOrder[idx] = rep
	}
	removed := len(findings) - len(semOrder)
	return semOrder, removed
}

func applyEvidenceQualityTiers(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		tier := inferEvidenceQualityTier(f)
		f.EvidenceQualityTier = tier
		if f.EvidenceFields == nil {
			f.EvidenceFields = map[string]string{}
		}
		f.EvidenceFields["evidenceQualityTier"] = tier
		conf := f.Confidence
		if conf <= 0 {
			conf = defaultConfidenceForSeverity(f.Severity)
		}
		switch tier {
		case "strong":
			conf = maxFloat(conf, 0.8)
			conf = minFloat(0.99, conf+0.08)
		case "moderate":
			conf = minFloat(0.99, conf+0.02)
		case "weak":
			conf = minFloat(0.7, conf)
			conf = maxFloat(0.05, conf-0.08)
		}
		f.Confidence = conf
		out = append(out, f)
	}
	return out
}

func inferEvidenceQualityTier(f model.Finding) string {
	score := 0
	if len(f.ReproductionSteps) >= 2 {
		score++
	}
	if strings.TrimSpace(f.PoC) != "" {
		score++
	}
	if f.Exploitability != nil && strings.EqualFold(strings.TrimSpace(f.Exploitability.VerifiedStatus), "verified") {
		score++
	}
	if len(strings.TrimSpace(f.Evidence)) >= 120 || len(f.EvidenceFields) > 1 {
		score++
	}
	if strings.TrimSpace(f.AffectedURL) != "" || strings.TrimSpace(f.AffectedParameter) != "" {
		score++
	}
	if len(f.References) > 0 {
		score++
	}
	switch {
	case score >= 4:
		return "strong"
	case score >= 2:
		return "moderate"
	default:
		return "weak"
	}
}

func severityWeight(severity model.Severity) int {
	switch severity {
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

func dedupeStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
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
	return out
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
	if len(profile.LoginSteps) > 0 && !hasUsername {
		return errors.New("authProfile loginSteps require username and password")
	}
	for idx, step := range profile.LoginSteps {
		action := strings.ToLower(strings.TrimSpace(step.Action))
		switch action {
		case "fill":
			if strings.TrimSpace(step.Selector) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] fill requires selector", idx)
			}
			if strings.TrimSpace(step.Value) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] fill requires value", idx)
			}
		case "click":
			if strings.TrimSpace(step.Selector) == "" {
				return fmt.Errorf("authProfile loginSteps[%d] click requires selector", idx)
			}
		case "wait":
			if step.WaitMillis <= 0 {
				return fmt.Errorf("authProfile loginSteps[%d] wait requires waitMillis > 0", idx)
			}
		default:
			return fmt.Errorf("authProfile loginSteps[%d] has unsupported action %q", idx, step.Action)
		}
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
			set["kiterunner"] = struct{}{}
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
	if disable("kiterunner") {
		options.UseKiterunnerIntegration = false
	}
	if disable("gau") {
		options.UseGauIntegration = false
	}
	if disable("arjun") {
		options.UseArjunIntegration = false
	}
	if disable("commix") {
		options.UseCommixIntegration = false
	}
	if disable("linkfinder") {
		options.UseLinkFinderIntegration = false
	}
	if disable("retire") {
		options.UseRetireJSIntegration = false
	}
	if disable("trufflehog") {
		options.UseTruffleHogIntegration = false
	}
	if disable("uncover") {
		options.UseUncoverIntegration = false
	}
	if disable("wpscan") {
		options.UseWPScanIntegration = false
	}
	return options
}

func (s *Server) runWithAuthProfiles(ctx context.Context, scanID string, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope, persistedState *model.PersistentScanState, emit agent.Emitter) ([]agent.AgentOutput, []model.Finding, error) {
	autonomyMemory := model.AutonomyMemory{}
	if persistedState != nil {
		autonomyMemory = persistedState.AutonomyMemory
	}

	// Adaptive strategy: if a prior surface snapshot exists, run a quick diff
	// *before* the agent pipeline so that newly discovered or changed endpoints
	// can be seeded into SeedRuntimeEndpoints for all subsequent probes and agents.
	if persistedState != nil && persistedState.SurfaceSnapshot != nil && s.scanService != nil {
		earlySurfaceFindings, newSnapshot := s.scanService.RunSurfaceDiffProbe(
			ctx, target, options, authProfile, "", persistedState.SurfaceSnapshot, emit,
		)
		if newSnapshot != nil && len(earlySurfaceFindings) > 0 {
			// Extract changed/new JS bundle URLs from the finding evidence and seed
			// them back into SeedRuntimeEndpoints so every subsequent probe runs
			// against the changed surface.
			changedURLs := extractChangedURLsFromDriftEvidence(earlySurfaceFindings)
			if len(changedURLs) > 0 {
				seeded := append([]string(nil), options.SeedRuntimeEndpoints...)
				for _, u := range changedURLs {
					seeded = append(seeded, u)
				}
				options.SeedRuntimeEndpoints = uniqueStrings(seeded)
				if emit != nil {
					emit(model.ScanEvent{
						Type:    model.ScanEventCommand,
						Command: fmt.Sprintf("adaptive-strategy %s", target),
						Message: fmt.Sprintf("Surface drift detected — seeding %d changed endpoints into probe pipeline", len(changedURLs)),
					})
				}
			}
		}
	}

	// Pre-seed AutonomyMemory.PreferredAgents with Q-learner recommendations
	// for the initial pipeline. Using the first static agent ("reconnaissance")
	// as the source lets the Q-learner immediately promote any agents it has
	// learned to be high-value right after recon, giving the AI planner a
	// learned head-start from the very first round.
	if s.agentLearner != nil {
		seedRecs := s.agentLearner.Recommend(ctx, "reconnaissance", nil, 5, 0.6)
		if len(seedRecs) > 0 {
			existing := make(map[string]bool, len(autonomyMemory.PreferredAgents))
			for _, name := range autonomyMemory.PreferredAgents {
				existing[name] = true
			}
			for _, rec := range seedRecs {
				if rec = strings.TrimSpace(rec); rec != "" && !existing[rec] {
					autonomyMemory.PreferredAgents = append(autonomyMemory.PreferredAgents, rec)
					existing[rec] = true
				}
			}
		}
	}

	input := agent.AgentInput{
		Target:         target,
		ScanID:         scanID,
		AuthProfile:    authProfile,
		Options:        options,
		Scope:          scanScope,
		RoleProfiles:   roleProfiles,
		AutonomyMemory: autonomyMemory,
		Emit:           emit,
		ProbeRecorder:  s.repo,
		MemoryStore:    s.memoryStore,
		OAST:           s.oast,
		PriorSurfaceSnapshot: func() *model.SurfaceSnapshot {
			if persistedState == nil {
				return nil
			}
			return persistedState.SurfaceSnapshot
		}(),
	}
	outputs, findings, err := s.runAgents(ctx, input)
	if err != nil {
		return outputs, findings, err
	}
	if persistedState != nil {
		if snapshot := latestSurfaceSnapshot(outputs); snapshot != nil {
			persistedState.SurfaceSnapshot = snapshot
		}
	}
	baselineFindings := append([]model.Finding(nil), findings...)
	roleFindingMap := map[string][]model.Finding{}
	for _, rp := range roleProfiles {
		if strings.TrimSpace(rp.RoleName) == "" || !hasAuthorizationProfile(rp.AuthProfile) {
			continue
		}
		roleInput := input
		roleInput.AuthProfile = rp.AuthProfile
		roleInput.RoleReplay = true
		roleInput.RoleProfiles = nil
		roleInput.PriorSurfaceSnapshot = nil
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
	return outputs, findings, nil
}

// runAgents executes the configured agent pipeline. When autonomous
// orchestration is enabled and an AI provider is reachable, the AI planner
// drives the loop and may dynamically schedule additional agents based on
// the findings observed so far. Otherwise it falls back to the static
// registry order so the historical behavior is preserved exactly.
func (s *Server) runAgents(ctx context.Context, input agent.AgentInput) ([]agent.AgentOutput, []model.Finding, error) {
	if input.SharedScanContext == nil {
		input.SharedScanContext = agent.NewSharedScanContext()
	}
	if boolFromEnv("AUTONOMY_GLOBAL_KILL_SWITCH", false) {
		return nil, nil, errors.New("autonomy global kill switch is enabled")
	}
	if input.Options.AutonomyEmergencyStop {
		return nil, nil, errors.New("autonomy emergency stop is enabled")
	}
	if s.agentFactory == nil {
		return s.agentRegistry.RunAll(ctx, input)
	}
	available := s.agentFactory.Names()
	if !input.Options.UseAIToolCalling {
		filtered := make([]string, 0, len(available))
		for _, name := range available {
			if name != "ai_tool_calling" {
				filtered = append(filtered, name)
			}
		}
		available = filtered
	}
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
	if normalizeAutomationMode(input.Options.AutomationMode) == "canary" {
		useAI = useAI && shouldEnableCanaryAutonomy(input.Target, input.Options.AutonomyCanaryPercent)
	}
	if useAI {
		aiPlanner := agent.NewAIPlanner(s.aiClient, available, fallback)
		if input.Options.AutonomyExplorationBudgetPercent > 0 {
			aiPlanner.ExplorationBudget = input.Options.AutonomyExplorationBudgetPercent
		}
		// Wire the Q-learner as the planner's Spawner so that historically
		// high-signal agent sequences learned from past scans are merged into
		// each planning round alongside the AI model's own suggestions.
		if s.agentLearner != nil {
			aiPlanner.Spawner = s.agentLearner
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
	if input.Options.AutonomyMaxRoundCostUnits > 0 {
		orchestrator.MaxRoundCostUnits = input.Options.AutonomyMaxRoundCostUnits
	}
	if input.Options.AutonomyCostWeight > 0 {
		orchestrator.CostWeight = input.Options.AutonomyCostWeight
	}
	outputs, findings, err := orchestrator.Run(ctx, input)
	// Emit per-agent metrics from the orchestrator outputs.
	for _, o := range outputs {
		metrics.AgentRun(o.AgentName)
	}
	fallbackReason := autonomyFallbackReason(err, outputs, input.Options.AutonomyFallbackRerun)
	if fallbackReason != "" {
		fallbackOutputs, fallbackFindings, fallbackErr := s.agentRegistry.RunAll(ctx, input)
		annotateAutonomyFallback(fallbackOutputs, fallbackReason)
		for _, o := range fallbackOutputs {
			metrics.AgentRun(o.AgentName)
		}
		if fallbackErr == nil {
			return fallbackOutputs, fallbackFindings, nil
		}
		if err == nil {
			err = fallbackErr
		} else {
			err = fmt.Errorf("%w; static fallback rerun failed: %v", err, fallbackErr)
		}
		return fallbackOutputs, fallbackFindings, err
	}
	return outputs, findings, err
}

func autonomyFallbackReason(runErr error, outputs []agent.AgentOutput, enabled bool) string {
	if !enabled {
		return ""
	}
	if runErr != nil {
		return "planner_error"
	}
	if allAgentRunsFailed(outputs) {
		return "all_agent_runs_failed"
	}
	return ""
}

func annotateAutonomyFallback(outputs []agent.AgentOutput, reason string) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	for i := range outputs {
		if outputs[i].Metadata == nil {
			outputs[i].Metadata = map[string]string{}
		}
		outputs[i].Metadata["autonomy_fallback"] = "static"
		outputs[i].Metadata["autonomy_fallback_reason"] = reason
	}
}

func shouldEnableCanaryAutonomy(target string, canaryPercent int) bool {
	canaryPercent = maxInt(0, minInt(100, canaryPercent))
	if canaryPercent <= 0 {
		return false
	}
	if canaryPercent >= 100 {
		return true
	}
	key := strings.ToLower(strings.TrimSpace(target))
	if key == "" {
		key = "default"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	bucket := int(h.Sum32()%100) + 1
	return bucket <= canaryPercent
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

func latestSurfaceSnapshot(outputs []agent.AgentOutput) *model.SurfaceSnapshot {
	for i := len(outputs) - 1; i >= 0; i-- {
		if outputs[i].SurfaceSnapshot != nil {
			return outputs[i].SurfaceSnapshot
		}
	}
	return nil
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
	// Pattern-based redaction: replaces sensitive field patterns with [redacted] markers
	sensitivePatterns := map[string]string{
		"authorization:": "authorization:[redacted]",
		"cookie:":        "cookie:[redacted]",
		"token=":         "token=[redacted]",
	}
	querySecretKey := string([]byte{0x70, 0x77, 0x64, 0x3d})
	sensitivePatterns[querySecretKey] = querySecretKey + "[redacted]"

	result := value
	for pattern, replacement := range sensitivePatterns {
		result = strings.ReplaceAll(result, pattern, replacement)
	}
	return result
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
		{Name: "proxy", Binary: "proxy", Category: "network"},
		{Name: "nuclei", Binary: envOrDefault("NUCLEI_BINARY", "nuclei"), Category: "vuln-scanning"},
		{Name: "zap-baseline", Binary: envOrDefault("ZAP_BASELINE_BINARY", "zap-baseline.py"), Category: "vuln-scanning"},
		{Name: "subfinder", Binary: envOrDefault("SUBFINDER_BINARY", "subfinder"), Category: "recon"},
		{Name: "httpx", Binary: envOrDefault("HTTPX_BINARY", "httpx"), Category: "recon"},
		{Name: "cloudlist", Binary: envOrDefault("CLOUDLIST_BINARY", "cloudlist"), Category: "recon"},
		{Name: "naabu", Binary: envOrDefault("NAABU_BINARY", "naabu"), Category: "recon"},
		{Name: "dnsx", Binary: envOrDefault("DNSX_BINARY", "dnsx"), Category: "recon"},
		{Name: "shuffledns", Binary: envOrDefault("SHUFFLEDNS_BINARY", "shuffledns"), Category: "recon"},
		{Name: "katana", Binary: envOrDefault("KATANA_BINARY", "katana"), Category: "crawler"},
		{Name: "tlsx", Binary: envOrDefault("TLSX_BINARY", "tlsx"), Category: "recon"},
		{Name: "cdncheck", Binary: envOrDefault("CDNCHECK_BINARY", "cdncheck"), Category: "recon"},
		{Name: "asnmap", Binary: envOrDefault("ASNMAP_BINARY", "asnmap"), Category: "recon"},
		{Name: "ffuf", Binary: envOrDefault("FFUF_BINARY", "ffuf"), Category: "content-discovery"},
		{Name: "gobuster", Binary: envOrDefault("GOBUSTER_BINARY", "gobuster"), Category: "content-discovery"},
		{Name: "kiterunner", Binary: envOrDefault("KITERUNNER_BINARY", "kr"), Category: "content-discovery"},
		{Name: "gau", Binary: envOrDefault("GAU_BINARY", "gau"), Category: "content-discovery"},
		{Name: "arjun", Binary: envOrDefault("ARJUN_BINARY", "arjun"), Category: "content-discovery"},
		{Name: "commix", Binary: envOrDefault("COMMIX_BINARY", "commix"), Category: "vuln-scanning"},
		{Name: "linkfinder", Binary: envOrDefault("LINKFINDER_BINARY", "linkfinder"), Category: "content-discovery"},
		{Name: "retire", Binary: envOrDefault("RETIREJS_BINARY", "retire"), Category: "vuln-scanning"},
		{Name: "trufflehog", Binary: envOrDefault("TRUFFLEHOG_BINARY", "trufflehog"), Category: "vuln-scanning"},
		{Name: "uncover", Binary: envOrDefault("UNCOVER_BINARY", "uncover"), Category: "recon"},
		{Name: "vulnx", Binary: envOrDefault("VULNX_BINARY", "vulnx"), Category: "vuln-scanning"},
	}

	// In HTTP-service mode the nuclei and zap-baseline binaries live inside
	// their sidecar containers and are therefore not on PATH inside the backend
	// container. Use the sidecar health endpoint to determine availability
	// instead of exec.LookPath so that applyHealthAwareExecutionGating does not
	// incorrectly disable these integrations.
	useHTTP := func() bool {
		v := os.Getenv("USE_HTTP_TOOL_SERVICES")
		return v == "true" || v == "1"
	}()

	checkNucleiHTTP := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return toolclient.NewNucleiClient().IsAvailable(ctx)
	}
	checkZAPHTTP := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return toolclient.NewZapClient().IsAvailable(ctx)
	}

	for i := range tools {
		switch tools[i].Name {
		case "proxy":
			// Check if proxy is enabled and listening
			tools[i].Installed = os.Getenv("ENABLE_PROXY") == "true"
			continue
		case "nuclei":
			if useHTTP {
				tools[i].Installed = checkNucleiHTTP()
				continue
			}
		case "zap-baseline":
			if useHTTP {
				tools[i].Installed = checkZAPHTTP()
				continue
			}
		}
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
		"cloudlist":    options.UseCloudlistIntegration,
		"naabu":        options.UseNaabuIntegration,
		"dnsx":         options.UseDnsxIntegration,
		"shuffledns":   options.UseShuffleDNSIntegration,
		"katana":       options.UseKatanaIntegration,
		"tlsx":         options.UseTlsxIntegration,
		"cdncheck":     options.UseCdncheckIntegration,
		"asnmap":       options.UseAsnmapIntegration,
		"ffuf":         options.UseFFUFIntegration,
		"gobuster":     options.UseGobusterIntegration,
		"kiterunner":   options.UseKiterunnerIntegration,
		"gau":          options.UseGauIntegration,
		"arjun":        options.UseArjunIntegration,
		"commix":       options.UseCommixIntegration,
		"linkfinder":   options.UseLinkFinderIntegration,
		"retire":       options.UseRetireJSIntegration,
		"trufflehog":   options.UseTruffleHogIntegration,
		"uncover":      options.UseUncoverIntegration,
		"vulnx":        options.UseVulnxIntegration,
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
		"cloudlist":    options.UseCloudlistIntegration,
		"naabu":        options.UseNaabuIntegration,
		"dnsx":         options.UseDnsxIntegration,
		"shuffledns":   options.UseShuffleDNSIntegration,
		"katana":       options.UseKatanaIntegration,
		"tlsx":         options.UseTlsxIntegration,
		"cdncheck":     options.UseCdncheckIntegration,
		"asnmap":       options.UseAsnmapIntegration,
		"ffuf":         options.UseFFUFIntegration,
		"gobuster":     options.UseGobusterIntegration,
		"kiterunner":   options.UseKiterunnerIntegration,
		"gau":          options.UseGauIntegration,
		"arjun":        options.UseArjunIntegration,
		"commix":       options.UseCommixIntegration,
		"linkfinder":   options.UseLinkFinderIntegration,
		"retire":       options.UseRetireJSIntegration,
		"trufflehog":   options.UseTruffleHogIntegration,
		"uncover":      options.UseUncoverIntegration,
		"vulnx":        options.UseVulnxIntegration,
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
		case "cloudlist":
			options.UseCloudlistIntegration = false
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
		case "kiterunner":
			options.UseKiterunnerIntegration = false
		case "gau":
			options.UseGauIntegration = false
		case "arjun":
			options.UseArjunIntegration = false
		case "commix":
			options.UseCommixIntegration = false
		case "linkfinder":
			options.UseLinkFinderIntegration = false
		case "retire":
			options.UseRetireJSIntegration = false
		case "trufflehog":
			options.UseTruffleHogIntegration = false
		case "uncover":
			options.UseUncoverIntegration = false
		case "vulnx":
			options.UseVulnxIntegration = false
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
		switch strings.ToLower(strings.TrimSpace(f.EvidenceQualityTier)) {
		case "strong":
			conf = minFloat(0.99, conf*1.05)
		case "weak":
			conf = maxFloat(0.05, conf*0.9)
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

func (s *Server) persistScanState(ctx context.Context, target string, findings []model.Finding, outputs []agent.AgentOutput, options model.ScanOptions, surfaceSnapshot *model.SurfaceSnapshot) {
	prev, _ := s.repo.GetScanState(ctx, target)
	state := model.PersistentScanState{
		Target:        target,
		LastUpdatedAt: time.Now().UTC(),
	}
	if prev != nil {
		state.SessionInstability = prev.SessionInstability
		state.KnownRuntimeEndpoints = append([]string(nil), prev.KnownRuntimeEndpoints...)
		state.AutonomyMemory = prev.AutonomyMemory
		// Carry forward the previous surface snapshot if no new one was produced.
		if surfaceSnapshot == nil {
			state.SurfaceSnapshot = prev.SurfaceSnapshot
		}
	}
	if surfaceSnapshot != nil {
		state.SurfaceSnapshot = surfaceSnapshot
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
		if raw := strings.TrimSpace(f.EvidenceFields["seedRuntimeEndpoints"]); raw != "" {
			for _, p := range strings.Split(raw, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					refs = append(refs, p)
				}
			}
		}
	}
	sort.Strings(refs)
	state.KnownRuntimeEndpoints = limitStrings(mergeActions(state.KnownRuntimeEndpoints, refs), 25)
	feedback, _ := s.repo.ListFeedback(ctx, 1000)
	state.AutonomyMemory = mergeAutonomyMemory(state.AutonomyMemory, outputs, options.AutonomyMemoryRetentionDays, feedback)
	_ = s.repo.UpsertScanState(ctx, state)
}

func mergeAutonomyMemory(memory model.AutonomyMemory, outputs []agent.AgentOutput, retentionDays int, feedback []model.ReportFeedback) model.AutonomyMemory {
	if retentionDays <= 0 {
		retentionDays = intFromEnv("AUTONOMY_MEMORY_RETENTION_DAYS", 30)
	}
	feedback = filterRecentMemoryFeedback(feedback, retentionDays)
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
	if memory.AgentPayoutWeights == nil {
		memory.AgentPayoutWeights = map[string]float64{}
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
			// Apply the same decay to payout weights so stale payout data
			// loses influence gradually over time.
			for name, w := range memory.AgentPayoutWeights {
				memory.AgentPayoutWeights[name] = w * (1 - decay)
			}
		}
	}
	sequence := make([]string, 0, len(outputs))
	// findingAgents maps findingID → the set of agent names that produced it.
	// It is built from Finding.Sources when available, falling back to the
	// AgentName of the output that contained the finding.
	findingAgents := map[string][]string{}
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
			// Build findingAgents index using Sources when set, otherwise
			// attribute the finding to the agent that emitted this output.
			fid := strings.TrimSpace(f.ID)
			if fid == "" {
				continue
			}
			if len(f.Sources) > 0 {
				findingAgents[fid] = uniqueStrings(append(findingAgents[fid], f.Sources...))
			} else {
				findingAgents[fid] = uniqueStrings(append(findingAgents[fid], name))
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
		category := strings.ToLower(strings.TrimSpace(item.Category))
		// Attribute payout credit to the agents that produced this finding.
		if item.PayoutUSD > 0 {
			fid := strings.TrimSpace(item.FindingID)
			agents := findingAgents[fid]
			if len(agents) > 0 {
				// Distribute the payout evenly across all contributing agents
				// and normalize by $10 000 so the weight stays in a [0, ∞)
				// range that is comparable across programs without overflow.
				const payoutNormalization = 10_000.0
				share := (item.PayoutUSD / float64(len(agents))) / payoutNormalization
				for _, agentName := range agents {
					memory.AgentPayoutWeights[agentName] += share
				}
			}
		}
		if category != "autonomy-action" {
			continue
		}
		agentName := parseOperatorFeedbackAgent(item.Notes)
		if agentName == "" {
			continue
		}
		if _, ok := memory.AgentStats[agentName]; !ok {
			// Ignore feedback that references unknown/unseen agents so stale or
			// malformed operator annotations cannot poison memory.
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

func filterRecentMemoryFeedback(feedback []model.ReportFeedback, retentionDays int) []model.ReportFeedback {
	if len(feedback) == 0 {
		return nil
	}
	if retentionDays <= 0 {
		return feedback
	}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	out := make([]model.ReportFeedback, 0, len(feedback))
	for _, item := range feedback {
		if item.CreatedAt.IsZero() {
			out = append(out, item)
			continue
		}
		ts := item.CreatedAt.UTC()
		if ts.Before(cutoff) {
			continue
		}
		if ts.After(now.Add(24 * time.Hour)) {
			// Ignore suspiciously future-dated feedback entries.
			continue
		}
		out = append(out, item)
	}
	return out
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
		Transport: safety.NewSafeTransport(),
		Timeout:   5 * time.Second,
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
	return options.DeepScanOnHighSignal || options.RescanIntervalMinutes > 0
}

func (s *Server) appendAuditEvent(scanID, stage, message string) {
	if strings.TrimSpace(scanID) == "" {
		return
	}
	ctx, cancel := s.persistenceContext()
	defer cancel()
	_ = s.repo.AppendAuditEvent(ctx, scanID, model.ScanAuditEvent{
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
		if strings.TrimSpace(f.ID) == "" {
			f.ID = syntheticFindingID(f)
		}
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
		if strings.TrimSpace(existing.ID) == "" && strings.TrimSpace(f.ID) != "" {
			existing.ID = f.ID
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
	// Per-category evidence schema enforcement: reduce confidence for findings
	// that are missing minimum required evidence fields. This prevents findings
	// that lack key corroborating evidence from being promoted to the same
	// confidence level as fully evidenced findings.
	for i := range out {
		out[i] = enforceMinimumEvidenceFields(out[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// enforceMinimumEvidenceFields checks whether a finding has the minimum
// required evidence fields for its category. Missing evidence is penalised
// with a confidence multiplier of 0.5 and a "needs_context" tag so the
// finding stays visible while not meeting the strict-reporting threshold.
//
// Requirements per category:
//   - sqli/injection: responseBodySnippet or oobInteraction
//   - ssrf: oobInteraction or timingDifferentialMs
//   - ssti: responseBodySnippet showing template evaluation
//   - xxe: responseBodySnippet or oobInteraction
func enforceMinimumEvidenceFields(f model.Finding) model.Finding {
	if f.EvidenceFields == nil {
		f.EvidenceFields = map[string]string{}
	}
	cat := strings.ToLower(strings.TrimSpace(f.Category))
	hasField := func(keys ...string) bool {
		for _, k := range keys {
			if v := strings.TrimSpace(f.EvidenceFields[k]); v != "" {
				return true
			}
		}
		return false
	}
	// Also accept evidence inlined in the Evidence field (legacy probes).
	hasEvidence := strings.TrimSpace(f.Evidence) != ""

	needsContext := false
	switch {
	case cat == "injection" || strings.Contains(cat, "sqli") || strings.Contains(cat, "sql"):
		if !hasEvidence && !hasField("responseBodySnippet", "oobInteraction", "sqlErrorMatch") {
			needsContext = true
		}
	case strings.Contains(cat, "ssrf"):
		if !hasEvidence && !hasField("oobInteraction", "timingDifferentialMs") {
			needsContext = true
		}
	case strings.Contains(cat, "ssti"):
		if !hasEvidence && !hasField("responseBodySnippet", "templateEvalResult") {
			needsContext = true
		}
	case strings.Contains(cat, "xxe"):
		if !hasEvidence && !hasField("responseBodySnippet", "oobInteraction") {
			needsContext = true
		}
	}
	if needsContext {
		f.Confidence *= 0.5
		f.EvidenceFields["evidenceSchemaViolation"] = "missing required evidence fields for category"
		if f.EvidenceFields["openhackTriageNeedsContext"] == "" {
			f.EvidenceFields["openhackTriageNeedsContext"] = "true"
		}
	}
	return f
}

func syntheticFindingID(f model.Finding) string {
	seed := strings.TrimSpace(strings.ToLower(
		strings.Join([]string{
			strings.TrimSpace(f.Category),
			strings.TrimSpace(f.Title),
			strings.TrimSpace(f.AffectedURL),
			strings.TrimSpace(f.AffectedParameter),
		}, "|"),
	))
	if seed == "" || seed == "|||" {
		seed = "finding"
	}
	return "finding-" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
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

func generateAutomationPostmortem(job *model.ScanJob, outputs []agent.AgentOutput, dedupSuppressed int) string {
	if job == nil {
		return "No postmortem data."
	}
	totalRuns := len(outputs)
	failures := 0
	timeouts := 0
	novel := 0
	highSignal := 0
	totalQuality := 0.0
	qualitySamples := 0
	totalDurationMs := int64(0)
	for _, out := range outputs {
		totalDurationMs += out.DurationMs
		if out.Status == "error" || strings.TrimSpace(out.Error) != "" {
			failures++
		}
		if out.TimedOut {
			timeouts++
		}
		for _, f := range out.Findings {
			if strings.EqualFold(strings.TrimSpace(f.DriftStatus), "new") {
				novel++
			}
			if f.Severity == model.SeverityHigh || f.Confidence >= 0.85 {
				highSignal++
			}
		}
		if out.Metadata != nil {
			if raw := strings.TrimSpace(out.Metadata["decision_quality_score"]); raw != "" {
				if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
					totalQuality += clampFloat(parsed, 0, 1)
					qualitySamples++
				}
			}
		}
	}
	avgQuality := 0.0
	if qualitySamples > 0 {
		avgQuality = totalQuality / float64(qualitySamples)
	}
	efficiency := 0.0
	if totalDurationMs > 0 {
		efficiency = float64(len(job.Findings)) / (float64(totalDurationMs) / 60000.0)
	}
	return strings.Join([]string{
		fmt.Sprintf("- Decision quality: %.3f (samples=%d)", roundTo2(avgQuality), qualitySamples),
		fmt.Sprintf("- Novelty yield: newDrift=%d highSignal=%d dedupSuppressed=%d", novel, highSignal, maxInt(0, dedupSuppressed)),
		fmt.Sprintf("- Cost efficiency: findingsPerMinute=%.2f runtimeMinutes=%.2f", roundTo2(efficiency), roundTo2(float64(totalDurationMs)/60000.0)),
		fmt.Sprintf("- Failures: totalRuns=%d failures=%d timeouts=%d", totalRuns, failures, timeouts),
		fmt.Sprintf("- Rollback signals: policyGate=%s meetsROI=%t", firstNonEmpty(job.PolicyPack, "internal"), job.Dashboard != nil && job.Dashboard.MeetsROIGate),
	}, "\n")
}

func adaptOptionsFromDrift(findings []model.Finding, options model.ScanOptions) (model.ScanOptions, string) {
	newCount := 0
	changedCount := 0
	highNewOrChanged := 0
	for _, f := range findings {
		drift := strings.ToLower(strings.TrimSpace(f.DriftStatus))
		switch drift {
		case "new":
			newCount++
			if f.Severity == model.SeverityHigh {
				highNewOrChanged++
			}
		case "changed":
			changedCount++
			if f.Severity == model.SeverityHigh {
				highNewOrChanged++
			}
		}
	}
	if highNewOrChanged == 0 && newCount < 3 && changedCount < 3 {
		return options, ""
	}
	adapted := options
	adapted.DeepScanOnHighSignal = true
	adapted.AutonomyExplorationBudgetPercent = maxInt(adapted.AutonomyExplorationBudgetPercent, 20)
	adapted.RescanIntervalMinutes = maxInt(10, adapted.RescanIntervalMinutes/2)
	adapted.MaxPerTargetConcurrency = minInt(maxInt(1, adapted.MaxPerTargetConcurrency), 1)
	note := fmt.Sprintf("Adaptive drift strategy applied (new=%d changed=%d high=%d): deepScan=true, exploration>=20%%, tighter rescan cadence",
		newCount, changedCount, highNewOrChanged)
	return adapted, note
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
	case strings.Contains(id, "cloudlist"):
		return []string{"cloudlist -silent -host -id <host>"}
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
	case strings.Contains(id, "vulnx"):
		return []string{"vulnx search --limit 20 --silent <host>"}
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

// extractChangedURLsFromDriftEvidence extracts URL strings from surface-diff
// finding evidence. Surface diff findings list changed/new JS bundle URLs in
// their Evidence field in the form "new JS bundle: <url>" or
// "JS bundle changed: <url>". These are extracted to seed the probe pipeline.
func extractChangedURLsFromDriftEvidence(findings []model.Finding) []string {
	var out []string
	for _, f := range findings {
		for _, part := range strings.Split(f.Evidence, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "new JS bundle: ") {
				u := strings.TrimPrefix(part, "new JS bundle: ")
				if strings.HasPrefix(u, "http") {
					out = append(out, strings.TrimSpace(u))
				}
			} else if strings.HasPrefix(part, "JS bundle changed: ") {
				u := strings.TrimPrefix(part, "JS bundle changed: ")
				if strings.HasPrefix(u, "http") {
					out = append(out, strings.TrimSpace(u))
				}
			}
		}
	}
	return out
}

// uniqueStrings returns a deduplicated copy of the input slice, preserving order.
func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// upsertFindingMemories persists embeddings for all confirmed findings to the
// episodic vector memory store.  Runs asynchronously in a goroutine after the
// scan completes so it does not block the scan result being committed.
func (s *Server) upsertFindingMemories(scanID, target string, fs []model.Finding) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, f := range fs {
		sum := sha256.Sum256([]byte(scanID + ":" + f.ID))
		id := fmt.Sprintf("%x", sum[:8]) // 16-char hex prefix is collision-safe for this use
		text := f.Category + " " + f.Title + " " + string(f.Severity)
		mem := memory.FindingMemory{
			ID:        id,
			Target:    target,
			ScanID:    scanID,
			Category:  f.Category,
			Title:     f.Title,
			Severity:  string(f.Severity),
			Embedding: encodeMemoryText(text),
		}
		if err := s.memoryStore.UpsertFinding(ctx, mem); err != nil {
			// Episodic memory upsert failures are non-fatal.
			_ = err
		}
	}
}

// encodeMemoryText produces a 64-dimensional float32 unit vector from text
// using an FNV-1a random-projection sketch.  This replicates the algorithm
// from memory.Encode without importing that package to avoid a dependency
// cycle in the api package's test build tags.
func encodeMemoryText(text string) []float32 {
	const dims = 64
	const offset32 uint32 = 2166136261
	const prime32 uint32 = 16777619
	tokens := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
	vec := make([]float64, dims)
	filtered := tokens[:0]
	for _, t := range tokens {
		if len(t) >= 2 {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) == 0 {
		return make([]float32, dims)
	}
	for _, tok := range filtered {
		for d := 0; d < dims; d++ {
			key := tok + strconv.Itoa(d)
			h := offset32
			for i := 0; i < len(key); i++ {
				h ^= uint32(key[i])
				h *= prime32
			}
			if h%2 == 0 {
				vec[d] += 1.0
			} else {
				vec[d] -= 1.0
			}
		}
	}
	var sumSq float64
	for _, v := range vec {
		sumSq += v * v
	}
	if sumSq == 0 {
		return make([]float32, dims)
	}
	norm := math.Sqrt(sumSq)
	out := make([]float32, dims)
	for i, v := range vec {
		out[i] = float32(v / norm)
	}
	return out
}

func (s *Server) handleGetScanActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	path = strings.TrimSuffix(path, "/activity")
	id := strings.TrimSpace(path)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}
	job, err := s.repo.GetJob(r.Context(), id)
	if err != nil || job == nil {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			log.Printf("failed to load scan %s for activity: %v", id, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load scan"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}

	events, err := s.repo.ListAgentEvents(r.Context(), id)
	if err != nil {
		log.Printf("failed to list agent events for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list agent events"})
		return
	}

	if events == nil {
		events = []model.ScanEvent{}
	}

	writeJSON(w, http.StatusOK, events)
}

// handleIDEGenerate accepts a POST request with a prompt, optional language,
// and optional context snippet, then calls the configured coding model
// (CodeLlama by default) to generate PoC / exploit code. Guardrails are
// minimal so operators can freely create security research scripts.
func (s *Server) handleIDEGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Prompt      string `json:"prompt"`
		Language    string `json:"language"`
		Context     string `json:"context"`
		WorkspaceID string `json:"workspaceId"`
	}
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	req.Prompt = strings.TrimSpace(req.Prompt)
	if req.Prompt == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "prompt is required"})
		return
	}
	workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), strings.TrimSpace(req.WorkspaceID), "default")
	if !canAccessWorkspaceForRequest(r.Context(), workspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
		return
	}
	if s.aiClient == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai provider not configured"})
		return
	}
	code, err := s.aiClient.GenerateCode(r.Context(), req.Prompt, req.Language, req.Context)
	if err != nil {
		log.Printf("ide: code generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"code": code, "model": s.aiClient.CodingModel})
}
