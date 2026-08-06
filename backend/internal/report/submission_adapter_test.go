package report

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestSubmitBugBountyFinding_HackerOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer ") {
			t.Fatalf("unexpected auth header: %s", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"h1-123","ok":true}`))
	}))
	defer srv.Close()

	t.Setenv("ABH_SUBMIT_HACKERONE_URL", srv.URL)
	res, err := SubmitBugBountyFinding(context.Background(), "hackerone", "token-1", model.BugBountySubmission{
		Title: "SQLi",
		Steps: []string{"step 1"},
	})
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if res.Reference != "h1-123" {
		t.Fatalf("expected reference h1-123, got %q", res.Reference)
	}
}

func TestSubmitBugBountyFinding_BugcrowdError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	}))
	defer srv.Close()

	t.Setenv("ABH_SUBMIT_BUGCROWD_URL", srv.URL)
	_, err := SubmitBugBountyFinding(context.Background(), "bugcrowd", "token-2", model.BugBountySubmission{Title: "XSS"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected HTTP 400 error, got %v", err)
	}
}

func TestPlatformBaseURLRequiresConfig(t *testing.T) {
	_ = os.Unsetenv("ABH_SUBMIT_HACKERONE_URL")
	_, err := SubmitBugBountyFinding(context.Background(), "hackerone", "token", model.BugBountySubmission{Title: "XSS"})
	if err == nil || !strings.Contains(err.Error(), "missing platform base URL") {
		t.Fatalf("expected missing URL error, got %v", err)
	}
}
