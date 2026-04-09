package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"
	"auto-bughunter/backend/internal/scope"

	"github.com/google/uuid"
)

type Server struct {
	scanService   *scanner.Service
	aiClient      *ai.Client
	allowed       map[string]struct{}
	repo          Repository
	agentRegistry *agent.Registry
	proxyServer   *proxy.Server
	mlService     *ml.Service
	maxPerTarget  int
	semMu         sync.Mutex
	targetSem     map[string]chan struct{}
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
}

func NewServer(scanService *scanner.Service, aiClient *ai.Client, mlService *ml.Service, allowedHosts []string, repo Repository, proxyStore proxy.Store, maxPerTarget int) *Server {
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

	return &Server{
		scanService:   scanService,
		aiClient:      aiClient,
		allowed:       allowed,
		repo:          repo,
		agentRegistry: reg,
		proxyServer:   proxy.NewServer(proxyStore),
		mlService:     mlService,
		maxPerTarget:  maxInt(1, maxPerTarget),
		targetSem:     map[string]chan struct{}{},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scan", s.handleCreateScan)
	mux.HandleFunc("/api/scan/", s.handleGetScan)
	// Proxy management endpoints.
	mux.HandleFunc("/api/proxy/requests", s.handleProxyRequests)
	mux.HandleFunc("/api/proxy/requests/", s.handleGetProxyRequest)
	mux.HandleFunc("/api/proxy/replay", s.handleProxyReplay)
	mux.HandleFunc("/api/ml/engagements", s.handleListMLEngagements)
	mux.HandleFunc("/api/feedback", s.handleFeedback)
	return withCORS(mux)
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
		ProgramName:        strings.TrimSpace(req.ProgramName),
		ProgramPolicyVersion: strings.TrimSpace(req.ProgramPolicyVersion),
		DisallowedTestTypes:  append([]string(nil), req.DisallowedTestTypes...),
	}

	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist scan job"})
		return
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

	writeJSON(w, http.StatusOK, job)
}

func (s *Server) runJob(id, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope) {
	release := s.acquireTargetSlot(target, options)
	defer release()

	job, err := s.repo.GetJob(context.Background(), id)
	if err != nil || job == nil {
		return
	}
	previousJob, _ := s.repo.GetLatestCompletedJobByTarget(context.Background(), target, id)

	job.Status = "running"
	_ = s.repo.UpdateJob(context.Background(), job)
	s.appendAuditEvent(id, "running", "Scan execution started")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	outputs, findings, err := s.runWithAuthProfiles(ctx, target, authProfile, roleProfiles, options, scanScope)
	completed := time.Now().UTC()

	job.CompletedAt = &completed
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		s.appendAuditEvent(id, "failed", "Scan execution failed: "+err.Error())
		_ = s.repo.UpdateJob(context.Background(), job)
		return
	}

	job.Status = "completed"
	job.Findings = enrichFindings(findings)
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
	job.AutomatedReport = generateAutomatedReport(job)
	s.appendAuditEvent(id, "ai-summary", "AI summary generated")
	s.appendAuditEvent(id, "report", "Automated penetration testing report generated")
	_ = s.repo.UpdateJob(context.Background(), job)
	s.appendAuditEvent(id, "completed", "Scan execution completed successfully")
	if job.Options.RescanIntervalMinutes > 0 {
		s.appendAuditEvent(id, "scheduling", fmt.Sprintf("Scheduled rescan in %d minutes", job.Options.RescanIntervalMinutes))
		go s.scheduleRescan(target, authProfile, options, scanScope, time.Duration(job.Options.RescanIntervalMinutes)*time.Minute)
	}
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

func (s *Server) runWithAuthProfiles(ctx context.Context, target string, authProfile model.ScanAuthProfile, roleProfiles []model.RoleAuthProfile, options model.ScanOptions, scanScope model.ScanScope) ([]agent.AgentOutput, []model.Finding, error) {
	input := agent.AgentInput{
		Target:      target,
		AuthProfile: authProfile,
		Options:     options,
		Scope:       scanScope,
	}
	outputs, findings, err := s.agentRegistry.RunAll(ctx, input)
	if err != nil {
		return outputs, findings, err
	}
	for _, rp := range roleProfiles {
		if strings.TrimSpace(rp.RoleName) == "" || !hasAuthorizationProfile(rp.AuthProfile) {
			continue
		}
		roleInput := input
		roleInput.AuthProfile = rp.AuthProfile
		roleOutputs, roleFindings, roleErr := s.agentRegistry.RunAll(ctx, roleInput)
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
		findings = append(findings, roleFindings...)
	}
	return outputs, findings, nil
}

func (s *Server) acquireTargetSlot(target string, options model.ScanOptions) func() {
	host := strings.ToLower(strings.TrimSpace(hostFromTarget(target)))
	if host == "" {
		return func() {}
	}
	limit := s.maxPerTarget
	if options.MaxPerTargetConcurrency > 0 {
		limit = options.MaxPerTargetConcurrency
	}
	if limit <= 0 {
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
