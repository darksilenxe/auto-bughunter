package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newLoginScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// TestLoginProbe_PassiveOnly ensures the probe is a no-op in passive mode.
func TestLoginProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestLoginProbe_UsernameEnumeration_DifferentResponse verifies a finding when the
// server returns different responses for valid vs. invalid usernames.
func TestLoginProbe_UsernameEnumeration_DifferentResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "login") ||
			strings.Contains(r.URL.Path, "signin") || strings.Contains(r.URL.Path, "auth")) {
			body := make([]byte, 1024)
			n, _ := r.Body.Read(body)
			bodyStr := string(body[:n])
			// Differentiate: known-valid user vs. unknown user.
			if strings.Contains(bodyStr, "admin") {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"wrong password"}`))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"user not found"}`))
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "login-username-enumeration" {
			found = true
			if f.Severity != model.SeverityMedium {
				t.Fatalf("expected Medium severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-204" {
				t.Fatalf("expected CWE-204, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected login-username-enumeration finding; got: %+v", findings)
	}
}

// TestLoginProbe_UsernameEnumeration_SameResponse verifies no finding when the
// server returns identical responses regardless of username.
func TestLoginProbe_UsernameEnumeration_SameResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "login") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	for _, f := range findings {
		if f.ID == "login-username-enumeration" {
			t.Fatalf("unexpected enumeration finding when responses are identical: %+v", f)
		}
	}
}

// TestLoginProbe_BruteForce_NoLockout verifies a High finding when 15 login
// attempts never receive a 429 or lockout response.
func TestLoginProbe_BruteForce_NoLockout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "login") {
			// Always 401 — no lockout, no rate limit.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"wrong password"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "brute") || strings.Contains(f.ID, "lockout") || strings.Contains(f.ID, "rate") {
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
		t.Fatalf("expected brute-force/no-lockout finding; got: %+v", findings)
	}
}

// TestLoginProbe_DefaultCredentials_Accepted verifies a Critical finding when
// the server accepts a known default credential pair.
func TestLoginProbe_DefaultCredentials_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "login") {
			body := make([]byte, 2048)
			n, _ := r.Body.Read(body)
			bodyStr := string(body[:n])
			// Accept admin/admin — classic default.
			if strings.Contains(bodyStr, "admin") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token":"admin_session_token"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "default-credential") || strings.Contains(f.ID, "default-cred") {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Fatalf("expected Critical severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-798" {
				t.Fatalf("expected CWE-798, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected default-credential finding; got: %+v", findings)
	}
}

// TestLoginProbe_WeakPasswordAccepted verifies a Medium finding when
// the registration endpoint accepts a single-character password.
func TestLoginProbe_WeakPasswordAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "register") ||
			strings.Contains(r.URL.Path, "signup")) {
			// Accept any password — no complexity enforcement.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "weak-password") || strings.Contains(f.ID, "password-complexity") {
			found = true
			if f.CWE != "CWE-521" {
				t.Fatalf("expected CWE-521, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected weak-password finding; got: %+v", findings)
	}
}

// TestLoginProbe_LoginCSRF_Missing verifies a Medium finding when the login
// endpoint accepts a POST without a CSRF token.
func TestLoginProbe_LoginCSRF_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "login") {
			// Accept without CSRF token.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"sess123"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunLoginProbe(
		context.Background(), srv.URL,
		newLoginScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "login-csrf" {
			found = true
			if f.CWE != "CWE-352" {
				t.Fatalf("expected CWE-352, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected login-csrf finding; got: %+v", findings)
	}
}
