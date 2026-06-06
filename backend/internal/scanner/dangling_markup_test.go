package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunDanglingMarkupProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>" + r.URL.Query().Get("q") + "</div>"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runDanglingMarkupProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "dangling-markup-injection" || findings[0].Severity != model.SeverityMedium || findings[0].CWE != "CWE-79" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunDanglingMarkupProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		payload := strings.ReplaceAll(r.URL.Query().Get("q"), "<", "&lt;")
		_, _ = w.Write([]byte("<div>" + payload + "</div>"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runDanglingMarkupProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
