package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"

	"github.com/google/uuid"
)

var negativeFeedbackOutcomes = map[string]struct{}{
	"rejected":    {},
	"duplicate":   {},
	"informative": {},
	"na":          {},
}

func normalizeFeedbackOutcome(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "accepted":
		return "accepted", true
	case "rejected":
		return "rejected", true
	case "duplicate":
		return "duplicate", true
	case "informative":
		return "informative", true
	case "n/a", "na", "not_applicable", "not-applicable", "not applicable":
		return "na", true
	default:
		return "", false
	}
}

func normalizeFeedbackRequest(req *model.ReportFeedback) bool {
	if req == nil {
		return false
	}
	req.ScanID = strings.TrimSpace(req.ScanID)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.Category = strings.TrimSpace(req.Category)
	req.Title = strings.TrimSpace(req.Title)
	req.ProgramName = strings.TrimSpace(req.ProgramName)
	req.Reason = strings.TrimSpace(req.Reason)
	req.Notes = strings.TrimSpace(req.Notes)
	outcome, ok := normalizeFeedbackOutcome(req.Outcome)
	if !ok {
		return false
	}
	req.Outcome = outcome
	return req.ScanID != "" && req.FindingID != ""
}

func feedbackOutcomeError() map[string]string {
	return map[string]string{"error": "outcome must be one of accepted, rejected, duplicate, informative, n/a"}
}

func (s *Server) handleBountyOutcomeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	secret := strings.TrimSpace(os.Getenv("ABH_BOUNTY_OUTCOME_WEBHOOK_SECRET"))
	if secret != "" {
		got := strings.TrimSpace(r.Header.Get("X-Bounty-Webhook-Secret"))
		if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid webhook secret"})
			return
		}
	}
	var req model.ReportFeedback
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if !normalizeFeedbackRequest(&req) {
		if strings.TrimSpace(req.ScanID) == "" || strings.TrimSpace(req.FindingID) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scanId and findingId are required"})
			return
		}
		writeJSON(w, http.StatusBadRequest, feedbackOutcomeError())
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
