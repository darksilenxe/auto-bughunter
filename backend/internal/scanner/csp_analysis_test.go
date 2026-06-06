package scanner

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunCSPAnalysisProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline' * cdn.jsdelivr.net")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	resp, err := http.Get(target.URL)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runCSPAnalysisProbe(RunInput{Target: target.URL}, resp.Header, string(body))
	if len(findings) == 0 {
		t.Fatal("expected CSP finding")
	}
	found := false
	for _, f := range findings {
		if f.ID == "csp-bypass-unsafe-inline" && f.Severity == model.SeverityHigh && f.CWE == "CWE-693" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unsafe-inline finding, got %+v", findings)
	}
}

func TestRunCSPAnalysisProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	resp, err := http.Get(target.URL)
	if err != nil {
		t.Fatalf("baseline request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	svc := NewService(Config{})
	findings := svc.runCSPAnalysisProbe(RunInput{Target: target.URL}, resp.Header, string(body))
	if len(findings) != 0 {
		t.Fatalf("expected no finding, got %+v", findings)
	}
}
