package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/scope"
)

// newOAuthSessionScope returns a ScanScope that allows everything under the given base URL.
func newOAuthSessionScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// TestOAuthSessionProbe_PassiveOnly verifies the probe is a no-op in passive mode.
func TestOAuthSessionProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make any requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestOAuthSessionProbe_AuthCodeReplay_Rejected verifies no finding when the server
// correctly returns invalid_grant on code replay.
func TestOAuthSessionProbe_AuthCodeReplay_Rejected(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	for _, f := range findings {
		if f.ID == "oauth-auth-code-replay" {
			t.Fatalf("expected no code-replay finding when server returns invalid_grant, got finding: %+v", f)
		}
	}
}

// TestOAuthSessionProbe_AuthCodeReplay_Accepted verifies a finding when the server
// accepts the same authorization code twice.
func TestOAuthSessionProbe_AuthCodeReplay_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err == nil && r.Form.Get("code") == "abh-probe-code-replay-test" {
			json.NewEncoder(w).Encode(map[string]string{"access_token": "tok123", "token_type": "bearer"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "oauth-code-replay" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-294" {
				t.Fatalf("expected CWE-294, got %s", f.CWE)
			}
			if f.EvidenceFields["preReport.verifiedBy"] == "" {
				t.Fatalf("expected verifier metadata, got %+v", f.EvidenceFields)
			}
		}
	}
	if !found {
		t.Fatalf("expected oauth-auth-code-replay finding, got findings: %+v", findings)
	}
}

// TestOAuthSessionProbe_ImplicitFlow_Accepted verifies a finding when the AS
// returns an access_token in the implicit flow response body.
func TestOAuthSessionProbe_ImplicitFlow_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "response_type=token") {
			// Return access_token in body — simulates implicit grant accepted.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"implicittoken123","token_type":"bearer"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "oauth-implicit-flow" {
			found = true
			if f.Severity != model.SeverityMedium {
				t.Fatalf("expected Medium severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected oauth-implicit-flow finding, got: %+v", findings)
	}
}

// TestOAuthSessionProbe_RefreshTokenReplay_Accepted verifies a finding when the
// server accepts the same refresh token twice.
func TestOAuthSessionProbe_RefreshTokenReplay_Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err == nil && r.Form.Get("refresh_token") == "refresh_abc" {
			json.NewEncoder(w).Encode(map[string]string{
				"access_token":  "newtok",
				"refresh_token": "oldrefresh",
				"token_type":    "bearer",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{
				"Authorization":   "******",
				"X-Refresh-Token": "refresh_abc",
			},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "oauth-refresh-token-replay" {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected oauth-refresh-token-replay finding; got: %+v", findings)
	}
}

// TestOAuthSessionProbe_TokenEndpointCORS_Wildcard verifies a finding when the
// token endpoint returns Access-Control-Allow-Origin: *.
func TestOAuthSessionProbe_TokenEndpointCORS_Wildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunOAuthSessionProbe(
		context.Background(), srv.URL,
		newOAuthSessionScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if f.ID == "oauth-token-endpoint-cors" {
			found = true
			if f.CWE != "CWE-942" {
				t.Fatalf("expected CWE-942, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected oauth-token-endpoint-cors finding; got: %+v", findings)
	}
}
