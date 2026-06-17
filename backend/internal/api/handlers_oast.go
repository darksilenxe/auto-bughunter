package api

import (
	"net/http"
	"strings"
)

// handleOASTTokens supports:
//
//	GET  /api/oast/tokens            - list active tokens (optional ?scanId= filter)
//	POST /api/oast/tokens            - issue a new token (body: {"scanId":"...","label":"..."})
func (s *Server) handleOASTTokens(w http.ResponseWriter, r *http.Request) {
	if s.oast == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oast service not enabled"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"publicBaseUrl": s.oast.PublicBaseURL(),
			"tokens":        s.oast.Tokens(strings.TrimSpace(r.URL.Query().Get("scanId"))),
		})
	case http.MethodPost:
		var body struct {
			ScanID string `json:"scanId"`
			Label  string `json:"label"`
		}
		if r.Body != nil {
			defer r.Body.Close()
			// Empty body is fine; both fields are optional.
			_ = decodeJSONBody(w, r, &body)
		}
		tok := s.oast.Issue(strings.TrimSpace(body.ScanID), strings.TrimSpace(body.Label))
		if tok.CallbackURL == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"token":   tok,
				"warning": "OAST_PUBLIC_BASE_URL is not configured; the issued token has no usable callback URL.",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": tok})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleOASTHits returns recorded callback interactions for a token.
//
//	GET /api/oast/hits/{token}
func (s *Server) handleOASTHits(w http.ResponseWriter, r *http.Request) {
	if s.oast == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oast service not enabled"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	tok := strings.TrimPrefix(r.URL.Path, "/api/oast/hits/")
	tok = strings.TrimSuffix(tok, "/")
	if tok == "" || strings.Contains(tok, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid token"})
		return
	}
	hits, ok := s.oast.Hits(tok)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown or expired token"})
		return
	}
	if hits == nil {
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "hits": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "hits": hits})
}
