package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunAccountEnumerationProbe_FindsVulnerability(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user := r.Form.Get("username")
		if strings.Contains(user, "admin") {
			_, _ = w.Write([]byte(strings.Repeat("A", 120)))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runAccountEnumerationProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "account-enumeration" || findings[0].Severity != model.SeverityMedium || findings[0].CWE != "CWE-200" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestRunAccountEnumerationProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid credentials"))
	}))
	defer target.Close()

	findings := NewService(Config{}).runAccountEnumerationProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %+v", findings)
	}
}
