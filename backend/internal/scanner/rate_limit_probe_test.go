package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRunRateLimitProbe_MissingRateLimitDetected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runRateLimitProbe(context.Background(), RunInput{
		Target:  target.URL + "/register",
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/register"}},
	}, "")
	if len(findings) == 0 {
		t.Fatalf("expected at least 1 missing-rate-limit finding, got 0")
	}
	f := findings[0]
	if f.CWE != "CWE-307" {
		t.Fatalf("expected CWE-307, got %q", f.CWE)
	}
	if f.EvidenceFields["rateLimitDetected"] != "false" {
		t.Fatalf("expected rateLimitDetected=false, got %q", f.EvidenceFields["rateLimitDetected"])
	}
}

func TestRunRateLimitProbe_ThrottledNoFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"too many requests"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	findings := svc.runRateLimitProbe(context.Background(), RunInput{
		Target:  target.URL + "/register",
		Options: model.ScanOptions{SeedRuntimeEndpoints: []string{target.URL + "/register"}},
	}, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings when endpoint throttles requests, got %d: %+v", len(findings), findings)
	}
}

func TestRunRateLimitProbe_PassiveOnlyDisables(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	in := RunInput{Target: target.URL + "/register"}
	in.Options.PassiveOnly = true
	if got := svc.runRateLimitProbe(context.Background(), in, ""); len(got) != 0 {
		t.Fatalf("PassiveOnly must disable the probe, got %d findings", len(got))
	}
}

func TestRunRateLimitProbe_NoCandidates_NoFindings(t *testing.T) {
	svc := NewService(Config{})
	got := svc.runRateLimitProbe(context.Background(), RunInput{Target: "not-a-valid-url"}, "")
	if len(got) != 0 {
		t.Fatalf("expected no findings for invalid target, got %d", len(got))
	}
}

func TestRateLimitBurst_RetryAfterHeader(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusLocked)
	}))
	defer target.Close()

	svc := NewService(Config{})
	throttled, _, _, sent := svc.rateLimitBurst(context.Background(), RunInput{}, target.URL, 5)
	if !throttled {
		t.Fatal("expected throttled=true when Retry-After header is present")
	}
	if sent == 0 {
		t.Fatal("expected at least one request to be sent")
	}
}

func TestRateLimitBurst_429ConvertedErrorDetected(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer target.Close()

	svc := NewService(Config{})
	throttled, _, _, _ := svc.rateLimitBurst(context.Background(), RunInput{}, target.URL, 5)
	if !throttled {
		t.Fatal("expected throttled=true when server returns HTTP 429")
	}
}
