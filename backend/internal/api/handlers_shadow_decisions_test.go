package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"auto-bughunter/backend/internal/ml"
	"auto-bughunter/backend/internal/model"
	"auto-bughunter/backend/internal/storage"
)

func TestHandleFindingVerificationPersistsShadowDecision(t *testing.T) {
	repo := storage.NewMemoryStore()
	job := &model.ScanJob{
		ID:          "scan-1",
		WorkspaceID: "default",
		Status:      "completed",
		Findings: []model.Finding{
			{
				ID:          "f-1",
				Category:    "information_disclosure",
				Severity:    model.SeverityInfo,
				Title:       "Possible disclosure",
				Description: "This may indicate exposed data.",
				Confidence:  0.2,
			},
		},
	}
	if err := repo.CreateJob(context.Background(), job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	srv := &Server{
		repo:      repo,
		mlService: ml.NewService(ml.Config{PseudonymSalt: "unit-test"}),
	}
	body := bytes.NewBufferString(`{"scanId":"scan-1","findingId":"f-1","status":"rejected","owner":"triage"}`)
	req := authRequest("POST", "/api/finding-verification", bytes.NewReader(body.Bytes()))
	rec := httptest.NewRecorder()

	srv.handleFindingVerification(rec, req)
	if rec.Code != 202 {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}

	items, err := repo.ListShadowDecisions(context.Background(), time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("list shadow decisions: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 shadow decision, got %d", len(items))
	}
	if items[0].ScanID != "scan-1" || items[0].FindingID != "f-1" {
		t.Fatalf("unexpected shadow decision identity: %+v", items[0])
	}
	if items[0].ModelDecision == "" {
		t.Fatalf("expected model decision to be populated")
	}
}

func TestAutomationMetricsIncludeCategoryAndShadowBreakdown(t *testing.T) {
	repo := storage.NewMemoryStore()
	now := time.Now().UTC()
	job := &model.ScanJob{
		ID:          "scan-1",
		WorkspaceID: "default",
		Status:      "completed",
		CompletedAt: &now,
		Findings: []model.Finding{
			{ID: "f-xss", Category: "xss", Severity: model.SeverityMedium, Confidence: 0.5},
			{ID: "f-sqli", Category: "sqli", Severity: model.SeverityMedium, Confidence: 0.9},
		},
	}
	if err := repo.CreateJob(context.Background(), job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if err := repo.SaveFindingVerification(context.Background(), model.FindingVerification{
		ID: "v-1", ScanID: "scan-1", FindingID: "f-xss", Status: "rejected", CreatedAt: now,
	}); err != nil {
		t.Fatalf("save verification xss: %v", err)
	}
	if err := repo.SaveFindingVerification(context.Background(), model.FindingVerification{
		ID: "v-2", ScanID: "scan-1", FindingID: "f-sqli", Status: "accepted", Owner: "triager", CreatedAt: now,
	}); err != nil {
		t.Fatalf("save verification sqli: %v", err)
	}
	_ = repo.SaveShadowDecision(context.Background(), model.ShadowDecision{
		ID: "sd-1", ScanID: "scan-1", FindingID: "f-xss", Category: "xss", Aligned: true, CreatedAt: now,
	})
	_ = repo.SaveShadowDecision(context.Background(), model.ShadowDecision{
		ID: "sd-2", ScanID: "scan-1", FindingID: "f-sqli", Category: "sqli", Aligned: false, CreatedAt: now,
	})

	srv := &Server{repo: repo}
	req := authRequest("GET", "/api/automation/metrics", nil)
	rec := httptest.NewRecorder()
	srv.handleAutomationMetrics(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var out model.AutomationMetrics
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.FalsePositiveRateByCategory["xss"] != 1 {
		t.Fatalf("expected xss false-positive rate 1, got %+v", out.FalsePositiveRateByCategory)
	}
	if out.FalsePositiveRateByCategory["sqli"] != 0 {
		t.Fatalf("expected sqli false-positive rate 0, got %+v", out.FalsePositiveRateByCategory)
	}
	if out.ShadowAlignmentRate != 0.5 {
		t.Fatalf("expected shadow alignment rate 0.5, got %.2f", out.ShadowAlignmentRate)
	}
	if out.ShadowAlignmentByCategory["xss"] != 1 || out.ShadowAlignmentByCategory["sqli"] != 0 {
		t.Fatalf("unexpected per-category shadow alignment: %+v", out.ShadowAlignmentByCategory)
	}
}

