package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunCacheDeceptionProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile.css" {
			if r.Header.Get("Cookie") == "session=1" {
				w.Header().Set("Cache-Control", "public, max-age=60")
				w.Header().Set("X-Cache", "HIT")
				_, _ = w.Write([]byte("private profile"))
				return
			}
			w.Header().Set("Cache-Control", "public, max-age=60")
			w.Header().Set("X-Cache", "HIT")
			_, _ = w.Write([]byte("private profile"))
			return
		}
		_, _ = w.Write([]byte("root"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runCacheDeceptionProbe(context.Background(), RunInput{Target: target.URL, AuthProfile: model.ScanAuthProfile{Cookies: map[string]string{"session": "1"}}, Session: NewScanSession()})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "web-cache-deception" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-525" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunCacheDeceptionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile.css" && r.Header.Get("Cookie") != "session=1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		_, _ = w.Write([]byte("private profile"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runCacheDeceptionProbe(context.Background(), RunInput{Target: target.URL, AuthProfile: model.ScanAuthProfile{Cookies: map[string]string{"session": "1"}}, Session: NewScanSession()})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
