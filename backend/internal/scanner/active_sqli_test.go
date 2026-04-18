package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunActiveSQLiProbe_FindsErrorSignature simulates a vulnerable
// endpoint that leaks a MySQL parser error when the id parameter contains
// an unbalanced quote.
func TestRunActiveSQLiProbe_FindsErrorSignature(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		if strings.Contains(v, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 1 {
		t.Fatalf("expected 1 SQLi finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "active-sqli-error-based" || f.Severity != model.SeverityHigh {
		t.Fatalf("unexpected finding shape: %+v", f)
	}
	if f.CWE != "CWE-89" {
		t.Fatalf("expected CWE-89, got %q", f.CWE)
	}
	if f.EvidenceFields["errorSignature"] == "" {
		t.Fatalf("expected errorSignature evidence field to be populated, got %+v", f.EvidenceFields)
	}
}

// TestRunActiveSQLiProbe_NoFindingWhenSafe ensures the probe stays quiet
// when the target does not leak a database error signature.
func TestRunActiveSQLiProbe_NoFindingWhenSafe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not found"))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runActiveSQLiProbe(context.Background(), RunInput{Target: target.URL}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no SQLi findings, got %d: %+v", len(findings), findings)
	}
}

// TestMatchSQLErrorSignature verifies the signature matcher.
func TestMatchSQLErrorSignature(t *testing.T) {
	cases := map[string]string{
		"You have an error in your SQL syntax; check ...": "you have an error in your sql syntax",
		"PG_QUERY(): blah":            "pg_query():",
		"<html>nothing to see</html>": "",
		"":                            "",
	}
	for body, want := range cases {
		got := matchSQLErrorSignature(body)
		if got != want {
			t.Fatalf("matchSQLErrorSignature(%q) = %q, want %q", body, got, want)
		}
	}
}
