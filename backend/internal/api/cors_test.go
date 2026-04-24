package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORS_AllowsConfiguredOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")

	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Origin", "https://console.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.com" {
		t.Fatalf("expected allowed origin in response, got %q", got)
	}
}

func TestWithCORS_BlocksDisallowedPreflightOrigin(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://console.example.com")

	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/api/scan", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden preflight for disallowed origin, got %d", rec.Code)
	}
}

func TestWithCORS_DefaultAllowsLocalFrontend(t *testing.T) {
	t.Setenv("CORS_ALLOWED_ORIGINS", "")

	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("expected localhost to be allowed by default, got %q", got)
	}
}
