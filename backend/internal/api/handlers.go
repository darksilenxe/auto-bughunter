package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/ai"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/proxy"
	"auto-bughunter/backend/internal/scanner"

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

	jobID := uuid.NewString()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:                 jobID,
		Target:             target,
		Status:             "queued",
		StartedAt:          now,
		AuthProfileSummary: model.SummarizeAuthProfile(req.AuthProfile),
		Options:            req.Options,
	}

	if err := s.repo.CreateJob(r.Context(), job); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist scan job"})
		return
	}

	go s.runJob(jobID, target, req.AuthProfile, req.Options)
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

func (s *Server) runJob(id, target string, authProfile model.ScanAuthProfile, options model.ScanOptions) {
	job, err := s.repo.GetJob(context.Background(), id)
	if err != nil || job == nil {
		return
	}

	job.Status = "running"
	_ = s.repo.UpdateJob(context.Background(), job)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	input := agent.AgentInput{
		Target:      target,
		AuthProfile: authProfile,
		Options:     options,
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
	job.AISummary = s.aiClient.Summarize(context.Background(), target, findings)
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

	replayed, err := s.proxyServer.Replay(r.Context(), req.RequestID, req.OverrideHeaders, req.OverrideBody)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, replayed)
}
