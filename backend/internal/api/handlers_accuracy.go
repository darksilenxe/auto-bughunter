package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"auto-bughunter/backend/internal/accuracybench"
	"auto-bughunter/backend/internal/model"
)

// accuracyCorpusDir returns the directory the benchmark manifests live in.
// It honours the ACCURACY_CORPUS_DIR env var (populated in the Docker image
// via backend/Dockerfile) and falls back to the in-repo testdata copy so the
// endpoint keeps working in local dev without extra configuration.
func accuracyCorpusDir() string {
	if v := strings.TrimSpace(os.Getenv("ACCURACY_CORPUS_DIR")); v != "" {
		return v
	}
	if _, err := os.Stat("/app/accuracy-corpus"); err == nil {
		return "/app/accuracy-corpus"
	}
	// Local dev fallback: repo-relative path (works when the server binary
	// is launched from the repo root, which is the convention documented in
	// the README).
	return filepath.Join("backend", "cmd", "accuracy-bench", "testdata", "corpus")
}

// accuracyManifestSummary is the compact list-view of a bundled manifest.
type accuracyManifestSummary struct {
	Target                 string   `json:"target"`
	Description            string   `json:"description,omitempty"`
	BaseURL                string   `json:"baseUrl,omitempty"`
	ExpectedFindingsCount  int      `json:"expectedFindingsCount"`
	SafeEndpointsCount     int      `json:"safeEndpointsCount"`
	AllowedExtraCategories []string `json:"allowedExtraCategories,omitempty"`
	Categories             []string `json:"categories,omitempty"`
}

// handleAccuracyCorpus lists the benchmark manifests bundled with the
// backend so the UI can render "which targets can I grade against?".
func (s *Server) handleAccuracyCorpus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	dir := accuracyCorpusDir()
	corpus, err := accuracybench.LoadCorpus(dir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to load accuracy corpus: " + err.Error(),
			"dir":   dir,
		})
		return
	}
	out := make([]accuracyManifestSummary, 0, len(corpus))
	for _, m := range corpus {
		cats := make(map[string]struct{})
		for _, exp := range m.ExpectedFindings {
			if c := strings.TrimSpace(exp.Category); c != "" {
				cats[c] = struct{}{}
			}
		}
		catList := make([]string, 0, len(cats))
		for c := range cats {
			catList = append(catList, c)
		}
		sort.Strings(catList)
		out = append(out, accuracyManifestSummary{
			Target:                 m.Target,
			Description:            m.Description,
			BaseURL:                m.BaseURL,
			ExpectedFindingsCount:  len(m.ExpectedFindings),
			SafeEndpointsCount:     len(m.SafeEndpoints),
			AllowedExtraCategories: m.AllowedExtraCategories,
			Categories:             catList,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"corpusDir": dir,
		"manifests": out,
	})
}

// accuracyRunRequest maps corpus target names to completed scan job IDs that
// should be graded as their "actual" scan. When PreReportVerificationPassRate
// is omitted for a target, it defaults to -1 ("not measured") so it doesn't
// silently drag the aggregate pass-rate down.
type accuracyRunRequest struct {
	Actuals []accuracyRunActualEntry `json:"actuals"`
}

type accuracyRunActualEntry struct {
	Target                        string   `json:"target"`
	ScanID                        string   `json:"scanId"`
	PreReportVerificationPassRate *float64 `json:"preReportVerificationPassRate,omitempty"`
}

// handleAccuracyRun grades a user-selected mapping of {corpus target →
// completed scan job} against the bundled manifests and returns the resulting
// accuracybench.Report plus a rendered Markdown summary.
//
// The endpoint intentionally does not persist runs — each call is a
// snapshot. The nightly CI workflow (qa-accuracy.yml) remains the source of
// truth for regression gating; this endpoint just gives operators a way to
// grade an ad-hoc scan from the UI.
func (s *Server) handleAccuracyRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.repo == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scan repository unavailable"})
		return
	}
	var req accuracyRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return
	}
	if len(req.Actuals) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one target→scan mapping is required"})
		return
	}

	dir := accuracyCorpusDir()
	corpus, err := accuracybench.LoadCorpus(dir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to load accuracy corpus: " + err.Error(),
			"dir":   dir,
		})
		return
	}

	actuals := make(map[string]accuracybench.ActualScan, len(req.Actuals))
	usedScans := make(map[string]string, len(req.Actuals))
	for _, entry := range req.Actuals {
		target := strings.TrimSpace(entry.Target)
		scanID := strings.TrimSpace(entry.ScanID)
		if target == "" || scanID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "each actuals entry needs a non-empty target and scanId",
			})
			return
		}
		job, err := s.repo.GetJob(r.Context(), scanID)
		if err != nil || job == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error":  "scan job not found: " + scanID,
				"target": target,
			})
			return
		}
		if !canAccessWorkspaceForRequest(r.Context(), job.WorkspaceID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied for scan " + scanID})
			return
		}
		findings := append([]model.Finding(nil), job.Findings...)
		passRate := -1.0
		if entry.PreReportVerificationPassRate != nil {
			passRate = *entry.PreReportVerificationPassRate
		}
		actuals[target] = accuracybench.ActualScan{
			Target:                        target,
			Findings:                      findings,
			PreReportVerificationPassRate: passRate,
		}
		usedScans[target] = scanID
	}

	report := accuracybench.Grade(corpus, actuals)
	writeJSON(w, http.StatusOK, map[string]any{
		"report":    report,
		"markdown":  accuracybench.RenderMarkdown(report),
		"usedScans": usedScans,
		"corpusDir": dir,
	})
}
