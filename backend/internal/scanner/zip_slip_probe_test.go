package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunZipSlipProbe_PassiveOnlyDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	got := svc.runZipSlipProbe(context.Background(), RunInput{
		Target:  srv.URL,
		Options: model.ScanOptions{PassiveOnly: true},
	}, "")
	if len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestRunZipSlipProbe_NoUploadEndpoints_NoFindings(t *testing.T) {
	svc := NewService(Config{})
	got := svc.runZipSlipProbe(context.Background(), RunInput{Target: "https://example.com/home"}, "")
	if len(got) != 0 {
		t.Fatalf("expected 0 findings when no upload endpoints discovered, got %d", len(got))
	}
}

func TestBuildZipUpload_ContainsTraversalEntry(t *testing.T) {
	body, contentType, err := buildZipUpload("../../../../tmp/abh_zipslip_c4e91.txt", zipSlipMarker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(contentType, "multipart/form-data") {
		t.Fatalf("expected multipart content type, got %q", contentType)
	}
	if body.Len() == 0 {
		t.Fatal("expected non-empty multipart body")
	}
}

func TestZipSlipSanitizeName(t *testing.T) {
	got := zipSlipSanitizeName("../../../../../../tmp/abh_zipslip_c4e91.txt")
	if strings.Contains(got, "..") || strings.Contains(got, "/") {
		t.Fatalf("expected sanitized name without traversal sequences, got %q", got)
	}
}
