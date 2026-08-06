package api

import (
	"net/http"
	"os"
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
	})
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
