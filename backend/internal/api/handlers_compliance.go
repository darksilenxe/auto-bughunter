package api

import (
	"net/http"
	"strings"
	"time"

	"auto-bughunter/backend/internal/model"
)

func (s *Server) handleComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	scanID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/compliance/evidence/"))
	if scanID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing scan id"})
		return
	}
	job, err := s.repo.GetJob(r.Context(), scanID)
	if err != nil || job == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	if !canAccessWorkspace(r.Context(), job.WorkspaceID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scan not accessible in this workspace"})
		return
	}
	policyGate := s.evaluatePolicyGate(job.Findings, job.PolicyPack)
	writeJSON(w, http.StatusOK, map[string]any{
		"scanId":      job.ID,
		"workspaceId": job.WorkspaceID,
		"policyPack":  job.PolicyPack,
		"generatedAt": time.Now().UTC(),
		"policyGate":  policyGate,
		"auditTrail":  job.AuditTrail,
		"findingStats": map[string]int{
			"total":  len(job.Findings),
			"high":   countSeverity(job.Findings, "high"),
			"medium": countSeverity(job.Findings, "medium"),
			"low":    countSeverity(job.Findings, "low"),
			"info":   countSeverity(job.Findings, "info"),
		},
	})
}

func countSeverity(findings []model.Finding, severity string) int {
	c := 0
	for _, finding := range findings {
		if strings.EqualFold(string(finding.Severity), severity) {
			c++
		}
	}
	return c
}
