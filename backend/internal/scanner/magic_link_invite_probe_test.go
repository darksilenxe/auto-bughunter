package scanner

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

func newMagicLinkScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// TestMagicLinkProbe_PassiveOnly ensures the probe is a no-op in passive mode.
func TestMagicLinkProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMagicLinkProbe(
		context.Background(), srv.URL,
		newMagicLinkScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestMagicLinkProbe_TokenInResponse_LowEntropy verifies a High finding when
// the magic-link endpoint returns a short (low-entropy) token in its response body.
func TestMagicLinkProbe_TokenInResponse_LowEntropy(t *testing.T) {
	// A very short token that indicates low entropy.
	shortToken := "abc12345"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "magic") || strings.Contains(r.URL.Path, "passwordless") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"` + shortToken + `","email":"test@example.com"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMagicLinkProbe(
		context.Background(), srv.URL,
		newMagicLinkScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "magic-link-token-in-response" {
			found = true
			if f.CWE != "CWE-330" {
				t.Fatalf("expected CWE-330, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected magic-link token-entropy finding; got: %+v", findings)
	}
}

// TestMagicLinkProbe_TokenReuse_Accepted verifies a High finding when the server
// accepts a magic-link token on a second use.
func TestMagicLinkProbe_TokenReuse_Accepted(t *testing.T) {
	// Token with sufficient entropy so entropy probe doesn't fire.
	longToken := base64.StdEncoding.EncodeToString([]byte("this-is-a-sufficiently-long-magic-link-token-for-testing-reuse"))
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "magic") || strings.Contains(r.URL.Path, "passwordless") {
			if r.Method == http.MethodPost || r.Method == http.MethodGet {
				callCount++
				// Always accept — no single-use enforcement.
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"token":"` + longToken + `","session":"new_session"}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMagicLinkProbe(
		context.Background(), srv.URL,
		newMagicLinkScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "magic-link-reuse") || strings.Contains(f.ID, "token-reuse") {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-294" {
				t.Fatalf("expected CWE-294, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected magic-link-reuse finding; got: %+v", findings)
	}
}

// TestMagicLinkProbe_AccountLinkCSRF_Accepted verifies a High finding when
// the account-linking endpoint accepts a POST without a CSRF token.
func TestMagicLinkProbe_AccountLinkCSRF_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "link") ||
			strings.Contains(r.URL.Path, "connect")) {
			// Accept without CSRF token.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"linked":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMagicLinkProbe(
		context.Background(), srv.URL,
		newMagicLinkScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "******"},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "account-link-csrf" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-352" {
				t.Fatalf("expected CWE-352, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected account-link-csrf finding; got: %+v", findings)
	}
}

// TestMagicLinkProbe_InviteTokenEnumerable verifies a Medium finding when the
// server returns 200 for a sequentially guessed invite token.
func TestMagicLinkProbe_InviteTokenEnumerable(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "invite") {
			callCount++
			// Always accept — no token binding.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"valid":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunMagicLinkProbe(
		context.Background(), srv.URL,
		newMagicLinkScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "invite-token-enumerable" {
			found = true
			if f.Severity != model.SeverityMedium {
				t.Fatalf("expected Medium severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-330" {
				t.Fatalf("expected CWE-330, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected invite-token-enumerable finding; got: %+v", findings)
	}
}
