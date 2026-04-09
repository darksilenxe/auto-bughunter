package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/ai"
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
}

type Repository interface {
	CreateJob(ctx context.Context, job *model.ScanJob) error
	UpdateJob(ctx context.Context, job *model.ScanJob) error
	GetJob(ctx context.Context, id string) (*model.ScanJob, error)
	GetLatestCompletedJobByTarget(ctx context.Context, target, excludeID string) (*model.ScanJob, error)
}

func NewServer(scanService *scanner.Service, aiClient *ai.Client, allowedHosts []string, repo Repository, proxyStore proxy.Store) *Server {
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
	req.Scope = scope.Normalize(target, req.Scope)
	if !scope.IsURLInScope(target, req.Scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target is out of configured scope profile"})
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
	}

	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist scan job"})
		return
	}

	go s.runJob(jobID, target, req.AuthProfile, req.Options, req.Scope)
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

func (s *Server) runJob(id, target string, authProfile model.ScanAuthProfile, options model.ScanOptions, scanScope model.ScanScope) {
	job, err := s.repo.GetJob(context.Background(), id)
	if err != nil || job == nil {
		return
	}
	previousJob, _ := s.repo.GetLatestCompletedJobByTarget(context.Background(), target, id)

	job.Status = "running"
	_ = s.repo.UpdateJob(context.Background(), job)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	input := agent.AgentInput{
		Target:      target,
		AuthProfile: authProfile,
		Options:     options,
		Scope:       scanScope,
	}

	_, findings, err := s.agentRegistry.RunAll(ctx, input)
	completed := time.Now().UTC()

	job.CompletedAt = &completed
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		_ = s.repo.UpdateJob(context.Background(), job)
		return
	}

	job.Status = "completed"
	job.Findings = findings
	if previousJob != nil {
		job.Findings = append(job.Findings, buildDeltaFinding(previousJob.Findings, findings)...)
	}
	job.AISummary = s.aiClient.Summarize(context.Background(), target, job.Findings)
	_ = s.repo.UpdateJob(context.Background(), job)
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

func buildDeltaFinding(previousFindings, currentFindings []model.Finding) []model.Finding {
	prev := map[string]struct{}{}
	for _, f := range previousFindings {
		prev[fingerprintFinding(f)] = struct{}{}
	}

	newItems := make([]string, 0)
	for _, f := range currentFindings {
		fp := fingerprintFinding(f)
		if _, ok := prev[fp]; ok {
			continue
		}
		newItems = append(newItems, fmt.Sprintf("[%s] %s", f.Severity, f.Title))
	}
	if len(newItems) == 0 {
		return nil
	}
	sort.Strings(newItems)
	if len(newItems) > 5 {
		newItems = newItems[:5]
	}

	return []model.Finding{{
		ID:             "monitoring-new-attack-surface",
		Category:       "monitoring",
		Severity:       model.SeverityInfo,
		Title:          fmt.Sprintf("New attack surface detected since last completed scan (%d new findings)", len(newItems)),
		Description:    "This scan surfaced findings not present in the previous completed scan for the same target.",
		Evidence:       strings.Join(newItems, "; "),
		Recommendation: "Prioritize triage of these newly introduced findings and consider enabling scheduled rescans for continuous monitoring.",
	}}
}

func fingerprintFinding(f model.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Category)) + "|" +
		strings.ToLower(strings.TrimSpace(f.Title)) + "|" +
		strings.TrimSpace(f.Evidence)
}
