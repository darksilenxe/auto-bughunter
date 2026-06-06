package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunFormulaInjectionProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Query().Get("name")))
	}))
	defer target.Close()

	findings := NewService(Config{}).runFormulaInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "formula-injection" || findings[0].Severity != model.SeverityMedium || findings[0].CWE != "CWE-1236" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunFormulaInjectionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("safe"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runFormulaInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
