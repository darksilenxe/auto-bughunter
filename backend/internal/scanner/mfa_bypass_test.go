package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunMFABypassProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" {
			_, _ = w.Write([]byte("dashboard"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer target.Close()

	findings := NewService(Config{}).runMFABypassProbe(context.Background(), RunInput{Target: target.URL, AuthProfile: model.ScanAuthProfile{Username: "user", Password: "pass"}, Session: NewScanSession()})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "mfa-bypass-step-skip" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-308" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunMFABypassProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dashboard" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("mfa required"))
			return
		}
		if r.URL.Path == "/otp" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer target.Close()

	findings := NewService(Config{}).runMFABypassProbe(context.Background(), RunInput{Target: target.URL, AuthProfile: model.ScanAuthProfile{Username: "user", Password: "pass"}, Session: NewScanSession()})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
