package api

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestBuildRoleDiffFindings_AddsRoleSpecificAndSummary(t *testing.T) {
	baseline := []model.Finding{
		{ID: "a", Category: "headers", Title: "Missing CSP"},
	}
	perRole := map[string][]model.Finding{
		"admin": {
			{ID: "b", Category: "access-control", Title: "Admin panel exposed"},
			{ID: "c", Category: "headers", Title: "Missing CSP"},
		},
	}
	out := buildRoleDiffFindings(baseline, perRole)
	if len(out) < 2 {
		t.Fatalf("expected role finding and summary, got %d", len(out))
	}
	hasRole := false
	hasSummary := false
	for _, f := range out {
		if f.ID == "role-diff-admin" {
			hasRole = true
		}
		if f.ID == "role-diff-summary" {
			hasSummary = true
		}
	}
	if !hasRole || !hasSummary {
		t.Fatalf("expected role diff and summary findings, got %#v", out)
	}
}
