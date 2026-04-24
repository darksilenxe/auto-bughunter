package api

import (
	"net/http"
	"os"
	"strings"
)

const defaultCORSAllowedOrigins = "http://localhost:3000,http://127.0.0.1:3000"

func applyCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-API-Key,X-Workspace-ID,Idempotency-Key")

	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	if !isAllowedCORSOrigin(origin) {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	addVaryHeader(w, "Origin")
	return true
}

func isAllowedCORSOrigin(origin string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return false
	}

	allowedRaw := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if allowedRaw == "" {
		allowedRaw = defaultCORSAllowedOrigins
	}
	for _, item := range strings.Split(allowedRaw, ",") {
		if strings.TrimSpace(item) == origin {
			return true
		}
	}
	return false
}

func addVaryHeader(w http.ResponseWriter, value string) {
	current := strings.TrimSpace(w.Header().Get("Vary"))
	if current == "" {
		w.Header().Set("Vary", value)
		return
	}
	for _, part := range strings.Split(current, ",") {
		if strings.EqualFold(strings.TrimSpace(part), value) {
			return
		}
	}
	w.Header().Set("Vary", current+", "+value)
}
