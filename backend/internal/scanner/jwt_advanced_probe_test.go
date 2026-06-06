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

func newJWTAdvancedScope(baseURL string) model.ScanScope {
	return scope.Normalize(baseURL, model.ScanScope{IncludeHosts: []string{"127.0.0.1"}})
}

// buildTestJWT builds a minimal unsigned JWT with the given header/payload
// maps so we can pre-seed auth profiles for tests.
func buildTestJWT(hdr, pay map[string]interface{}) string {
	tok, _ := buildJWT(hdr, pay, "")
	return tok
}

// TestJWTAdvancedProbe_PassiveOnly ensures the probe is a no-op in passive mode.
func TestJWTAdvancedProbe_PassiveOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("passive-only mode must not make requests")
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in passive mode, got %d", len(findings))
	}
}

// TestJWTAdvancedProbe_NoJWT_NoFindings verifies the probe is a no-op when no
// JWT is present in the auth profile.
func TestJWTAdvancedProbe_NoJWT_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			// No Authorization header containing a JWT.
			Headers: map[string]string{"X-Custom": "nojwt"},
		},
		func(model.ScanEvent) {},
	)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when no JWT present, got %d: %+v", len(findings), findings)
	}
}

// TestJWTAdvancedProbe_KIDPathTraversal_Accepted verifies a High finding when
// the server accepts a JWT with a path-traversal kid header value.
func TestJWTAdvancedProbe_KIDPathTraversal_Accepted(t *testing.T) {
	// Build a minimal but valid-looking JWT to prime the probe.
	tok := buildTestJWT(
		map[string]interface{}{"alg": "HS256", "kid": "keyid1"},
		map[string]interface{}{"sub": "1", "iss": "test", "aud": "api", "exp": 9999999999},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		// Accept any JWT — kid path traversal not detected.
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "******") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"admin"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "Bearer " + tok},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "kid") {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected kid path-traversal finding; got: %+v", findings)
	}
}

// TestJWTAdvancedProbe_ExpTampering_Accepted verifies a Medium finding when
// the server accepts a JWT with an implausibly far-future exp claim.
func TestJWTAdvancedProbe_ExpTampering_Accepted(t *testing.T) {
	tok := buildTestJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "1", "iss": "test", "aud": "api", "exp": 9999999999},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		// Accept any token — no expiry validation.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "Bearer " + tok},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "exp") || strings.Contains(f.ID, "expiry") || strings.Contains(f.ID, "lifetime") {
			found = true
			if f.CWE != "CWE-347" {
				t.Fatalf("expected CWE-347, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected exp-tampering finding; got: %+v", findings)
	}
}

// TestJWTAdvancedProbe_MissingIssAud_Accepted verifies a High finding when
// the server accepts a JWT with iss and aud removed.
func TestJWTAdvancedProbe_MissingIssAud_Accepted(t *testing.T) {
	tok := buildTestJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "1", "iss": "test-issuer", "aud": "test-audience", "exp": 9999999999},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		// Accept any token — no iss/aud validation.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "Bearer " + tok},
		},
		func(model.ScanEvent) {},
	)
	found := false
	for _, f := range findings {
		if strings.Contains(f.ID, "iss") || strings.Contains(f.ID, "aud") || strings.Contains(f.ID, "issuer") {
			found = true
			if f.Severity != model.SeverityHigh {
				t.Fatalf("expected High severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-287" {
				t.Fatalf("expected CWE-287, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Fatalf("expected missing iss/aud finding; got: %+v", findings)
	}
}

// TestJWTAdvancedProbe_RejectsModifiedToken verifies no finding when
// the server rejects a tampered JWT with 401.
func TestJWTAdvancedProbe_RejectsModifiedToken(t *testing.T) {
	tok := buildTestJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "1", "iss": "test", "aud": "api", "exp": 9999999999},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
			return
		}
		// Original token accepted; any modification rejected.
		authHdr := r.Header.Get("Authorization")
		if strings.HasSuffix(authHdr, tok) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	svc := NewService(Config{})
	findings := svc.RunJWTAdvancedProbe(
		context.Background(), srv.URL,
		newJWTAdvancedScope(srv.URL),
		model.ScanOptions{},
		model.ScanAuthProfile{
			Headers: map[string]string{"Authorization": "Bearer " + tok},
		},
		func(model.ScanEvent) {},
	)
	for _, f := range findings {
		// kid and jku probes fire even with rejection; only check claims tampering findings.
		if strings.Contains(f.ID, "exp") || strings.Contains(f.ID, "iss") || strings.Contains(f.ID, "aud") {
			t.Fatalf("unexpected claims-tampering finding when server rejects modification: %+v", f)
		}
	}
}
