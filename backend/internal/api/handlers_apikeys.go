package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"auto-bughunter/backend/internal/model"
)

type apiKeyCreateRequest struct {
	WorkspaceID string `json:"workspaceId"`
	Name        string `json:"name"`
	Role        string `json:"role"`
}

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	store, ok := s.repo.(APIKeyStore)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "api key store is unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		workspaceID := firstNonEmpty(workspaceFromRequest(r), workspaceFromHeader(r), "default")
		if !canAccessWorkspace(r.Context(), workspaceID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
			return
		}
		keys, err := store.ListAPIKeys(r.Context(), workspaceID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list api keys"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"apiKeys": keys})
	case http.MethodPost:
		var req apiKeyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		req.WorkspaceID = firstNonEmpty(req.WorkspaceID, workspaceFromRequest(r), "default")
		if !canAccessWorkspace(r.Context(), req.WorkspaceID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
			return
		}
		record, raw, err := store.CreateAPIKey(r.Context(), req.WorkspaceID, strings.TrimSpace(req.Name), normalizeAPIKeyRole(req.Role))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create api key"})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"apiKey": record,
			"token":  raw,
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	if !hasRole(r.Context(), model.APIKeyRoleAdmin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
		return
	}
	store, ok := s.repo.(APIKeyStore)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "api key store is unavailable"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/admin/apikeys/")
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown api key route"})
		return
	}
	id := strings.TrimSpace(parts[0])
	action := strings.TrimSpace(parts[1])
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "api key id is required"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	switch action {
	case "rotate":
		record, raw, err := store.RotateAPIKey(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to rotate api key"})
			return
		}
		if !canAccessWorkspace(r.Context(), record.WorkspaceID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "workspace access denied"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"apiKey": record, "token": raw})
	case "revoke":
		if err := store.RevokeAPIKey(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to revoke api key"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "revoked"})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown api key action"})
	}
}
