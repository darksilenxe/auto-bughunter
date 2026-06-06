package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunFileUploadProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runFileUploadProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestRunFileUploadProbe_NoUploadEndpoints_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	// No upload-like paths in body, no seeded endpoints — should produce no findings.
	got := svc.runFileUploadProbe(context.Background(), RunInput{
		Target: srv.URL,
	}, "")
	if len(got) != 0 {
		t.Fatalf("expected 0 findings when no upload endpoints discovered, got %d", len(got))
	}
}

func TestRunFileUploadProbe_AcceptedUploadDetected(t *testing.T) {
	// Test the detection logic directly without going through the HTTP client.
	result := detectUploadExecution(`{"status":"uploaded","url":"/uploads/test.php.jpg"}`)
	if result == "" {
		t.Fatal("expected acceptance detection for upload-success JSON response")
	}
}

func TestRunFileUploadProbe_ExecutionConfirmedCritical(t *testing.T) {
	result := detectUploadExecution(`abh_upload_rce_test`)
	if result != "rce" {
		t.Fatalf("expected rce detection, got %q", result)
	}
}

func TestRunFileUploadProbe_CleanResponse(t *testing.T) {
	result := detectUploadExecution(`{"error":"file type not allowed"}`)
	if result != "" {
		t.Fatalf("expected no detection for rejected upload, got %q", result)
	}
}

func TestBuildMultipartUpload(t *testing.T) {
	buf, ct, err := buildMultipartUpload("test.php", "image/jpeg", "content")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf == nil || buf.Len() == 0 {
		t.Fatal("expected non-empty multipart body")
	}
	if !strings.HasPrefix(ct, "multipart/form-data;") {
		t.Errorf("unexpected Content-Type: %s", ct)
	}
}

func TestDiscoverUploadEndpoints_MatchesKnownPaths(t *testing.T) {
	target := "http://example.com"
	seeded := []string{"http://example.com/api/upload", "http://example.com/home"}
	scope := model.ScanScope{IncludeHosts: []string{"example.com"}}
	found := discoverUploadEndpoints(target, "", scope, seeded)
	hasUpload := false
	for _, ep := range found {
		if strings.Contains(ep, "upload") {
			hasUpload = true
		}
	}
	if !hasUpload {
		t.Error("expected at least one upload endpoint to be discovered")
	}
}
