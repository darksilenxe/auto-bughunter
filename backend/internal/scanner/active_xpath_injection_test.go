package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunActiveXPathInjectionProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, value := range r.URL.Query() {
			if strings.Contains(value[0], "' or '1'='1") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("XPathException: invalid XPath syntax"))
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveXPathInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "active-xpath-injection" || findings[0].Severity != model.SeverityHigh || findings[0].CWE != "CWE-643" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunActiveXPathInjectionProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runActiveXPathInjectionProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
