package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"auto-bughunter/backend/internal/report"
)

// serveSubmitFinding sends a single finding to a supported bug-bounty platform
// using the configured per-program API key. The action is blocked when the
// submission-readiness score is below 90.
func (s *Server) serveSubmitFinding(w http.ResponseWriter, r *http.Request, scanID, findingID string) {
	job, ok := s.loadJobOrRespond(w, r, scanID)
	if !ok {
		return
	}
	finding, found := report.FindingByID(job.Findings, findingID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
		return
	}
	readiness := report.SubmissionReadinessScore(finding)
	if !readiness.ReadyToSubmit {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":         "submission blocked: readiness score below 90",
			"score":         readiness.Score,
			"missingFields": readiness.MissingFields,
		})
		return
	}
	duplicates, err := s.findDuplicateCandidatesForSubmission(r, scanID, findingID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to run duplicate pre-check"})
		return
	}
	if len(duplicates) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":               "submission blocked: duplicate pre-check found similar historical submissions",
			"duplicateCandidates": duplicates,
			"score":               readiness.Score,
			"missingFields":       readiness.MissingFields,
		})
		return
	}
	platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
	if platform == "" {
		platform = "hackerone"
	}
	apiKey := resolveSubmissionAPIKey(platform, job.ProgramName)
	if apiKey == "" {
		writeJSON(w, http.StatusPreconditionFailed, map[string]string{
			"error": "missing API key for submission platform/program configuration",
		})
		return
	}
	sub := report.FindingToBugBountySubmission(finding, job.Target)
	res, err := report.SubmitBugBountyFinding(r.Context(), platform, apiKey, sub)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "submitted",
		"platform":    platform,
		"reference":   res.Reference,
		"response":    res.RawResponse,
		"programName": job.ProgramName,
		"readiness":   readiness,
		"duplicates":  []report.DuplicateCandidate{},
	})
}

func (s *Server) findDuplicateCandidatesForSubmission(r *http.Request, scanID, findingID string) ([]report.DuplicateCandidate, error) {
	threshold := report.DefaultDuplicateThreshold
	if raw := strings.TrimSpace(r.URL.Query().Get("threshold")); raw != "" {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, err
		}
		threshold = v
	}
	priorLimit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("priorLimit")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return nil, err
		}
		if v > 0 {
			priorLimit = v
		}
	}
	if priorLimit > 200 {
		priorLimit = 200
	}
	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil || job == nil {
		return nil, err
	}
	jobs, err := s.repo.ListCompletedJobs(r.Context(), priorLimit)
	if err != nil {
		return nil, err
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
	for _, match := range report.FindDuplicates(job.Findings, prior, threshold) {
		if match.FindingID == findingID {
			return match.Candidates, nil
		}
	}
	return nil, nil
}

func resolveSubmissionAPIKey(platform, programName string) string {
	p := strings.ToUpper(strings.TrimSpace(platform))
	if p == "" {
		return ""
	}
	program := sanitizeEnvToken(programName)
	if program != "" {
		if v := strings.TrimSpace(os.Getenv("ABH_SUBMIT_" + p + "_API_KEY_" + program)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(os.Getenv("ABH_SUBMIT_" + p + "_API_KEY"))
}

func sanitizeEnvToken(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
