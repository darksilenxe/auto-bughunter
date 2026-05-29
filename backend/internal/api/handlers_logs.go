package api

import (
	"net/http"
	"time"

	"auto-bughunter/backend/internal/logbuffer"
	"auto-bughunter/backend/internal/model"
)

// handleSystemLogs streams the most recent captured system logs as a plain-text
// attachment. It is gated to admin principals because logs can contain
// operationally sensitive details.
func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	logs := logbuffer.Default.Snapshot()
	filename := "auto-bughunter-" + time.Now().UTC().Format("20060102T150405Z") + ".log"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(logs)
}
