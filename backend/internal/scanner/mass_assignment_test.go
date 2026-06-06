package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunMassAssignmentProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"role":"admin"`) {
				_, _ = w.Write([]byte(`{"role":"admin","isAdmin":true}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	findings := NewService(Config{}).runMassAssignmentProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "mass-assignment" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-915" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunMassAssignmentProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	findings := NewService(Config{}).runMassAssignmentProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
