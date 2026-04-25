package ml

import (
	"context"
	"strings"
	"testing"

	"auto-bughunter/backend/internal/model"
)

type datasetTestRepo struct {
	jobs     []*model.ScanJob
	feedback []model.ReportFeedback
}

func (r *datasetTestRepo) ListCompletedJobs(_ context.Context, _ int) ([]*model.ScanJob, error) {
	return r.jobs, nil
}

func (r *datasetTestRepo) GetAssetsByScanID(_ context.Context, _ string) ([]model.ScanAsset, error) {
	return nil, nil
}

func (r *datasetTestRepo) ListAuditEvents(_ context.Context, _ string) ([]model.ScanAuditEvent, error) {
	return nil, nil
}

func (r *datasetTestRepo) ListFeedback(_ context.Context, _ int) ([]model.ReportFeedback, error) {
	return r.feedback, nil
}

func TestBuildTrainingDatasetIncludesSanitizedFeedback(t *testing.T) {
	repo := &datasetTestRepo{
		jobs: []*model.ScanJob{
			{
				ID:     "scan-1",
				Target: "https://example.com",
				Findings: []model.Finding{
					{ID: "f-1", Category: "api_security", Severity: model.SeverityHigh, Title: "Token leak"},
				},
			},
		},
		feedback: []model.ReportFeedback{
			{
				ID:        "fb-1",
				ScanID:    "scan-1",
				FindingID: "f-1",
				Category:  "api_security",
				Title:     "Token leak",
				Outcome:   "Accepted",
				Notes:     "Authorization: Bearer super-secret-token",
			},
		},
	}
	svc := NewService(Config{PseudonymSalt: "unit-test"})

	ds, err := svc.BuildTrainingDataset(context.Background(), repo, nil, 10)
	if err != nil {
		t.Fatalf("BuildTrainingDataset returned error: %v", err)
	}
	if len(ds.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(ds.Records))
	}
	record := ds.Records[0]
	if len(record.Feedback) != 1 {
		t.Fatalf("expected 1 feedback item, got %d", len(record.Feedback))
	}
	item := record.Feedback[0]
	if item.Outcome != "accepted" {
		t.Fatalf("feedback outcome should be normalized to lowercase, got %q", item.Outcome)
	}
	if strings.Contains(strings.ToLower(item.Notes), "super-secret-token") {
		t.Fatalf("feedback note should be redacted, got %q", item.Notes)
	}
}
