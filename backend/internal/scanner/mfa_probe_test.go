package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newMFAScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// TestMFAProbe_PassiveOnly ensures the probe is a no-op in passive mode.
func TestMFAProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestMFAProbe_SurfaceDiscovered verifies an Info finding when an MFA endpoint
// responds with HTTP 200.
func TestMFAProbe_SurfaceDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "mfa") || strings.Contains(r.URL.Path, "otp") ||
			strings.Contains(r.URL.Path, "2fa") {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "mfa-surface-discovered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected mfa-surface-discovered finding; got: %+v", findings)
	}
}

// TestMFAProbe_OTPBruteForce_NoRateLimit verifies a High finding when 10
// sequential OTP attempts all succeed without a 429.
func TestMFAProbe_OTPBruteForce_NoRateLimit(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "mfa") || strings.Contains(r.URL.Path, "otp") ||
			strings.Contains(r.URL.Path, "2fa") || strings.Contains(r.URL.Path, "verify") {
			callCount++
			// Always 200 — no rate limiting enforced.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"invalid_otp"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "mfa-otp-no-ratelimit" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-307" {
				t.Fatalf("expected CWE-307, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected OTP brute-force finding; got: %+v", findings)
	}
}

// TestMFAProbe_OTPBruteForce_RateLimited verifies no mfa-otp-no-ratelimit finding when
// the server returns 429 on the second attempt.
func TestMFAProbe_OTPBruteForce_RateLimited(t *testing.T) {
	var otpCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		isMFAPath := strings.Contains(path, "mfa") || strings.Contains(path, "otp") ||
			strings.Contains(path, "verify") || strings.Contains(path, "2fa") ||
			strings.Contains(path, "backup") || strings.Contains(path, "recovery")
		if isMFAPath {
			otpCount++
			// Rate-limit immediately after the first request for all MFA paths.
			if otpCount > 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	for _, f := range findings {
		if f.ID == "mfa-otp-no-ratelimit" {
			t.Fatalf("unexpected mfa-otp-no-ratelimit finding when server rate-limits: %+v", f)
		}
	}
}

// TestMFAProbe_OTPReuse_Accepted verifies a Medium finding when the server
// accepts the same OTP code twice.
func TestMFAProbe_OTPReuse_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "mfa") || strings.Contains(r.URL.Path, "otp") ||
			strings.Contains(r.URL.Path, "verify") {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "123456") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"verified":true}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid otp"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "mfa-otp-reuse" {
			found = true
			if f.Severity != model.SeverityMedium {
				t.Fatalf("expected Medium severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-294" {
				t.Fatalf("expected CWE-294, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected mfa-otp-reuse finding; got: %+v", findings)
	}
}

// TestMFAProbe_StepUpSkip_Accessible verifies a High finding when step-up
// protected endpoints are accessible with a base-level token.
func TestMFAProbe_StepUpSkip_Accessible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "mfa") || strings.Contains(r.URL.Path, "otp") || strings.Contains(r.URL.Path, "verify")) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid otp"}`))
			return
		}
		// Sensitive resources still return 200 — step-up not enforced.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"path":"%s"}`, r.URL.Path)))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMFAProbe(
		context.Background(), srv.URL,
		newMFAScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "******"},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "mfa-skip-direct-access" || f.ID == "mfa-stepup-not-enforced" {
			found = true
			if f.CWE != "CWE-306" {
				t.Fatalf("expected CWE-306, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected step-up finding; got: %+v", findings)
	}
}
