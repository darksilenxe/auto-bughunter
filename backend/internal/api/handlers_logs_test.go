package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/logbuffer"
	"auto-bughunter/backend/internal/model"
)

func TestHandleSystemLogsReturnsCapturedLogsForAdmin(t *testing.T) {
	if _, err := logbuffer.Default.Write([]byte("unit-test-log-line\n")); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	s := &Server{}
	req := authRequest("GET", "/api/admin/logs", nil)
	rec := httptest.NewRecorder()
	s.handleSystemLogs(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".log") {
		t.Fatalf("content-disposition = %q, want attachment .log", cd)
	}
	if !strings.Contains(rec.Body.String(), "unit-test-log-line") {
		t.Fatalf("body did not contain seeded log line: %q", rec.Body.String())
	}
}

func TestHandleSystemLogsRejectsNonAdmin(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/api/admin/logs", nil)
	ctx := context.WithValue(req.Context(), principalContextKey, principal{
		KeyID:       "viewer-key",
		WorkspaceID: "default",
		Role:        model.APIKeyRoleViewer,
		Name:        "viewer",
	})
	rec := httptest.NewRecorder()
	s.handleSystemLogs(rec, req.WithContext(ctx))

	if rec.Code != 403 {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleSystemLogsRejectsNonGet(t *testing.T) {
	s := &Server{}
	req := authRequest("POST", "/api/admin/logs", nil)
	rec := httptest.NewRecorder()
	s.handleSystemLogs(rec, req)

	if rec.Code != 405 {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
