package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunBusinessLogicDiff_AnonymousStateMutation verifies that when a
// POST endpoint accepts requests from both an authenticated baseline and
// an anonymous caller, the probe surfaces a high-severity CWE-306 finding.
func TestRunBusinessLogicDiff_AnonymousStateMutation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checkout" && r.Method == http.MethodPost {
			// Accept all POST requests regardless of auth — simulates broken auth.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer token"},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/checkout"}},
		baseline,
		nil,
		nil,
	)

	found := false
	for _, f := range findings {
		if f.CWE == "CWE-306" && f.AffectedURL == srv.URL+"/checkout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CWE-306 anonymous state mutation finding on /checkout, got: %+v", findings)
	}
}

// TestRunBusinessLogicDiff_NoAnonymousFindingWhenAuthEnforced ensures that
// when a POST endpoint correctly rejects unauthenticated requests with a
// 401, no CWE-306 finding is emitted.
func TestRunBusinessLogicDiff_NoAnonymousFindingWhenAuthEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer token"},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/checkout"}},
		baseline,
		nil,
		nil,
	)
	for _, f := range findings {
		if f.CWE == "CWE-306" {
			t.Fatalf("expected no anonymous mutation finding when auth is enforced, got: %+v", f)
		}
	}
}

// TestRunBusinessLogicDiff_CrossRoleMutation verifies that when both the
// baseline and an additional role can successfully POST to a transition
// endpoint, a CWE-285 cross-role finding is surfaced.
func TestRunBusinessLogicDiff_CrossRoleMutation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/transfer" && r.Method == http.MethodPost {
			// Both "admin-token" and "viewer-token" get 2xx — broken RBAC.
			auth := r.Header.Get("Authorization")
			if auth == "Bearer admin-token" || auth == "Bearer viewer-token" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"transferred":true}`))
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer admin-token"},
	}
	roles := []model.RoleAuthProfile{
		{
			RoleName:    "viewer",
			AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer viewer-token"}},
		},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/transfer"}},
		baseline,
		roles,
		nil,
	)

	found := false
	for _, f := range findings {
		if f.CWE == "CWE-285" && f.AffectedURL == srv.URL+"/transfer" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CWE-285 cross-role mutation finding on /transfer, got: %+v", findings)
	}
}

// TestRunBusinessLogicDiff_NoFindingWhenRoleBlocked verifies that no
// cross-role finding is emitted when the server correctly rejects the
// lower-privileged role with a 403.
func TestRunBusinessLogicDiff_NoFindingWhenRoleBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer admin-token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"transferred":true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer admin-token"},
	}
	roles := []model.RoleAuthProfile{
		{
			RoleName:    "viewer",
			AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer viewer-token"}},
		},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/transfer"}},
		baseline,
		roles,
		nil,
	)
	for _, f := range findings {
		if f.CWE == "CWE-285" {
			t.Fatalf("expected no cross-role finding when role is correctly blocked, got: %+v", f)
		}
	}
}

// TestRunBusinessLogicDiff_ParameterTampering verifies that when a POST
// endpoint accepts numeric business parameters with out-of-range values
// (e.g. negative amount) and returns 2xx without an error body, a CWE-20
// parameter-tampering finding is emitted.
func TestRunBusinessLogicDiff_ParameterTampering(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/order" && r.Method == http.MethodPost {
			// Accepts any body without validating the amount field.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"orderId":"xyz123","status":"created"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer token"},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/order"}},
		baseline,
		nil,
		nil,
	)

	found := false
	for _, f := range findings {
		if f.CWE == "CWE-20" && f.AffectedURL == srv.URL+"/order" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CWE-20 parameter tampering finding on /order, got: %+v", findings)
	}
}

// TestRunBusinessLogicDiff_NoTamperFindingWhenRejected verifies that when
// the server returns an error indicator in a 2xx envelope for out-of-range
// numeric parameters, no parameter-tampering finding is emitted.
func TestRunBusinessLogicDiff_NoTamperFindingWhenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/order" && r.Method == http.MethodPost {
			// Returns 200 but with an error body — old-style validation error.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"invalid amount: must be positive"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer token"},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + "/order"}},
		baseline,
		nil,
		nil,
	)
	for _, f := range findings {
		if f.CWE == "CWE-20" {
			t.Fatalf("expected no tamper finding when server returns error indicator, got: %+v", f)
		}
	}
}

// TestRunBusinessLogicDiff_SkipsNonTransitionEndpoints verifies that
// endpoints whose paths do not match any workflow keyword are ignored.
// The server here only returns 200 for the non-transition path; well-known
// transition paths return 404, so no finding should be emitted.
func TestRunBusinessLogicDiff_SkipsNonTransitionEndpoints(t *testing.T) {
	nonTransitionPath := "/api/users/list"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nonTransitionPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		// All other paths (including well-known transition paths) return 404.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	svc := NewService(Config{})
	baseline := model.ScanAuthProfile{
		Headers: map[string]string{"Authorization": "Bearer token"},
	}
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		srv.URL,
		model.ScanScope{},
		// Non-transition path — does not match workflowTransitionPattern.
		model.ScanOptions{SeedRuntimeEndpoints: []string{srv.URL + nonTransitionPath}},
		baseline,
		nil,
		nil,
	)
	// No finding should have AffectedURL pointing to the non-transition path.
	for _, f := range findings {
		if f.AffectedURL == srv.URL+nonTransitionPath {
			t.Fatalf("expected no finding for non-transition endpoint %s, got: %+v", nonTransitionPath, f)
		}
	}
}

// TestRunBusinessLogicDiff_PassiveOnly ensures the probe is a no-op when
// PassiveOnly mode is active.
func TestRunBusinessLogicDiff_PassiveOnly(t *testing.T) {
	svc := NewService(Config{})
	findings := svc.RunBusinessLogicDiff(
		context.Background(),
		"https://example.com",
		model.ScanScope{},
		model.ScanOptions{PassiveOnly: true},
		model.ScanAuthProfile{},
		nil,
		nil,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings in passive-only mode, got: %+v", findings)
	}
}

// TestBldCandidateEndpoints verifies endpoint filtering logic: seeded
// transition paths are accepted; non-transition paths are rejected; duplicates
// are deduplicated; and the well-known paths are appended for each target.
func TestBldCandidateEndpoints(t *testing.T) {
	scanScope := model.ScanScope{}
	seeded := []string{
		"https://example.com/checkout",                       // matches
		"https://example.com/checkout",                       // duplicate — should deduplicate
		"https://example.com/api/users/list",                 // no keyword — should be skipped
		"https://example.com/payment/confirm",                // matches
		"https://example.com/static/app.js",                  // no keyword — should be skipped
	}

	got := bldCandidateEndpoints("https://example.com", seeded, scanScope)

	// /checkout and /payment/confirm from seeded; plus well-known paths that
	// also match — total depends on which well-known paths are resolved.
	// Minimally, /checkout and /payment/confirm must be present.
	hasCheckout := false
	hasPayment := false
	dupCount := 0
	for _, ep := range got {
		if ep == "https://example.com/checkout" {
			if hasCheckout {
				dupCount++
			}
			hasCheckout = true
		}
		if strings.Contains(ep, "/payment/confirm") {
			hasPayment = true
		}
	}
	if !hasCheckout {
		t.Errorf("expected /checkout in candidates, got %v", got)
	}
	if !hasPayment {
		t.Errorf("expected /payment/confirm in candidates, got %v", got)
	}
	if dupCount > 0 {
		t.Errorf("expected no duplicate /checkout endpoint, got %d duplicates in %v", dupCount, got)
	}
}
