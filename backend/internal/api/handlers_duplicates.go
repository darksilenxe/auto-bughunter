package api

import (
	"net/http"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/report"
)

// handleFindingDuplicates exposes the deterministic duplicate detector via
// the HTTP API. Operators call this before submitting a finding to a bug
// bounty program to check whether the same vulnerability was already
// reported in a prior scan against the same (or another) target.
//
//	GET /api/findings/duplicates?scanId=<id>&threshold=0.6&priorLimit=50
//
// `threshold` defaults to report.DefaultDuplicateThreshold and is clamped to
// [0, 1]. `priorLimit` defaults to 50 and caps how many recently completed
// scans are scanned for prior findings (capped at 200).
func (s *Server) handleFindingDuplicates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	scanID := strings.TrimSpace(r.URL.Query().Get("scanId"))
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required query parameter scanId"})
		return
	}
	threshold := report.DefaultDuplicateThreshold
	if raw := strings.TrimSpace(r.URL.Query().Get("threshold")); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "threshold must be a number in [0,1]"})
			return
		}
		threshold = v
	}
	priorLimit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("priorLimit")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "priorLimit must be a positive integer"})
			return
		}
		if v > 200 {
			v = 200
		}
		priorLimit = v
	}

	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil || job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}

	jobs, err := s.repo.ListCompletedJobs(r.Context(), priorLimit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load prior scans"})
		return
	}
	prior := make([]report.PriorFinding, 0)
	for _, j := range jobs {
		if j == nil || j.ID == scanID {
			continue
		}
		for _, f := range j.Findings {
			prior = append(prior, report.PriorFinding{
				ScanID:      j.ID,
				Target:      j.Target,
				ProgramName: j.ProgramName,
				Finding:     f,
			})
		}
	}

	matches := report.FindDuplicates(job.Findings, prior, threshold)
	writeJSON(w, http.StatusOK, map[string]any{
		"scanId":            scanID,
		"threshold":         threshold,
		"priorScansSampled": len(jobs),
		"duplicateGroups":   matches,
	})
}