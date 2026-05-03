package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestRunIDORRoleDiff_FindsAnonymousAccess simulates an endpoint that
// returns the same payload regardless of credentials (broken auth on an
// ID-bearing path). The probe must surface a high-severity finding
// because anonymous reaches an authenticated resource.
func TestRunIDORRoleDiff_FindsAnonymousAccess(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same body for every request — no access control.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":12345,"email":"victim@example.com","balance":42}`))
	}))
	defer target.Close()

	svc := NewService(Config{})
	endpoint := target.URL + "/api/users/12345"

	roles := []model.RoleAuthProfile{
		{
			RoleName:    "admin",
			AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer admin-token"}},
		},
	}
	findings := svc.RunIDORRoleDiff(
		context.Background(),
		endpoint,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{endpoint}},
		model.ScanAuthProfile{}, // no baseline auth
		roles,
		nil,
	)

	if len(findings) == 0 {
		t.Fatalf("expected at least one IDOR finding, got 0")
	}
	hasAnon := false
	for _, f := range findings {
		if f.Severity == model.SeverityHigh && f.CWE == "CWE-639" {
			hasAnon = true
		}
	}
	if !hasAnon {
		t.Fatalf("expected a high-severity anonymous-vs-role finding, got: %+v", findings)
	}
}

// TestRunIDORRoleDiff_NoFindingWhenAccessControlEnforced ensures no
// finding is emitted when the server returns 401/403 for unauthorized
// callers.
func TestRunIDORRoleDiff_NoFindingWhenAccessControlEnforced(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer admin-token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":12345}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer target.Close()

	svc := NewService(Config{})
	endpoint := target.URL + "/api/users/12345"

	roles := []model.RoleAuthProfile{
		{
			RoleName:    "admin",
			AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "Bearer admin-token"}},
		},
	}
	findings := svc.RunIDORRoleDiff(
		context.Background(),
		endpoint,
		model.ScanScope{},
		model.ScanOptions{SeedRuntimeEndpoints: []string{endpoint}},
		model.ScanAuthProfile{},
		roles,
		nil,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when access control is enforced, got %+v", findings)
	}
}

// TestRunIDORRoleDiff_SkipsNonIDEndpoints verifies the candidate filter
// drops endpoints that don't have an ID-shaped path segment (e.g. "/").
func TestRunIDORRoleDiff_SkipsNonIDEndpoints(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	svc := NewService(Config{})
	roles := []model.RoleAuthProfile{
		{RoleName: "admin", AuthProfile: model.ScanAuthProfile{Headers: map[string]string{"Authorization": "x"}}},
	}
	findings := svc.RunIDORRoleDiff(
		context.Background(),
		target.URL,
		model.ScanScope{},
		model.ScanOptions{},
		model.ScanAuthProfile{},
		roles,
		nil,
	)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when no ID-bearing endpoint is supplied, got %+v", findings)
	}
}

func TestIDORCandidateEndpoints(t *testing.T) {
	scope := model.ScanScope{}
	got := idorCandidateEndpoints(
		"https://1.1.1.1/",
		[]string{
			"https://1.1.1.1/api/users/12345",
			"https://1.1.1.1/api/users/12345", // duplicate
			"https://1.1.1.1/static/app.js",   // non-ID
			"https://1.1.1.1/orders/550e8400-e29b-41d4-a716-446655440000",
		},
		scope,
	)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates (numeric + uuid), got %d: %v", len(got), got)
	}
}

func TestSlugRolePair(t *testing.T) {
	if got := slugRolePair("Admin", "anonymous"); got != "admin-vs-anonymous" {
		t.Fatalf("unexpected slug: %q", got)
	}
	if got := slugRolePair("Read Only", "Admin"); got != "admin-vs-read-only" {
		t.Fatalf("unexpected slug: %q", got)
	}
}
