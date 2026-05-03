package knowledge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestRetrieveForJob(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req["stage"] != "ai-summary" {
			t.Fatalf("unexpected stage: %#v", req["stage"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"query":            "target=https://example.com",
			"stage":            "ai-summary",
			"curationMode":     "manual-short-notes",
			"licenseNotice":    "source-url-only",
			"suggestedActions": []string{"Review PortSwigger guidance."},
			"references": []map[string]any{
				{
					"id":                 "ref-1",
					"title":              "PortSwigger SQL injection",
					"url":                "https://portswigger.net/web-security/sql-injection",
					"sourceType":         "portswigger",
					"license":            "source-url-only",
					"topic":              "injection",
					"vulnerabilityClass": "sql injection",
					"technique":          "parameterized queries",
					"passage":            "Curated note.",
					"score":              1.2,
				},
			},
		})
	}))
	defer ts.Close()

	client := NewClient(Config{ExternalURL: ts.URL, AuthToken: "secret"})
	ctx := context.Background()
	job := &model.ScanJob{
		Target: "https://example.com",
		Findings: []model.Finding{
			{Category: "injection", Severity: model.SeverityHigh, Title: "SQL injection", Description: "Database error", Recommendation: "Use parameterized queries"},
		},
		Dashboard: &model.DecisionDashboard{TopAttackPaths: []string{"input validation -> database compromise"}},
	}

	got := client.RetrieveForJob(ctx, "ai-summary", job, 4)
	if got == nil {
		t.Fatalf("expected knowledge context")
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("expected bearer auth, got %q", gotAuth)
	}
	if got.Stage != "ai-summary" {
		t.Fatalf("unexpected stage: %q", got.Stage)
	}
	if len(got.References) != 1 {
		t.Fatalf("expected 1 reference, got %d", len(got.References))
	}
	if got.References[0].SourceType != "portswigger" {
		t.Fatalf("unexpected source type: %q", got.References[0].SourceType)
	}
}
