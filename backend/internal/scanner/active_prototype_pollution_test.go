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

func TestRunActivePrototypePollutionProbe_FindsVulnerability(t *testing.T) {
	var polluted string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("__proto__[polluted]"); v != "" {
			polluted = v
		}
		if v := r.URL.Query().Get("constructor[prototype][polluted]"); v != "" {
			polluted = v
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), prototypePollutionMarker) {
				polluted = prototypePollutionMarker
			}
		}
		_, _ = w.Write([]byte("polluted=" + polluted))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActivePrototypePollutionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "active-prototype-pollution" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-1321" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunActivePrototypePollutionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActivePrototypePollutionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
