package ml

import (
	"context"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

type datasetTestRepo struct {
	jobs     []*model.ScanJob
	feedback []model.ReportFeedback
	probes   map[string][]model.ProbeRecord
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

func (r *datasetTestRepo) ListProbeRecordsByCategory(_ context.Context, category string, _ time.Time, _ int) ([]model.ProbeRecord, error) {
	if r.probes == nil {
		return nil, nil
	}
	return r.probes[strings.ToLower(strings.TrimSpace(category))], nil
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
				Notes:     "Authorization: ******",
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

func TestBuildTrainingDatasetIncludesProbeNegatives(t *testing.T) {
	repo := &datasetTestRepo{
		jobs: []*model.ScanJob{
			{
				ID:     "scan-1",
				Target: "https://example.com",
				Findings: []model.Finding{
					{ID: "f-1", Category: "xss", Severity: model.SeverityMedium, Title: "Potential XSS"},
				},
			},
		},
		probes: map[string][]model.ProbeRecord{
			"xss": {
				{Outcome: model.ProbeNoSignal, Confirmed: false, CreatedAt: time.Now().Add(-time.Minute)},
				{Outcome: model.ProbeNoSignal, Confirmed: false, CreatedAt: time.Now()},
				{Outcome: model.ProbeNearMiss, Confirmed: false, CreatedAt: time.Now()},
				{Outcome: model.ProbeConfirmed, Confirmed: true, CreatedAt: time.Now()},
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
	neg := ds.Records[0].ProbeNegatives
	if len(neg) != 2 {
		t.Fatalf("expected 2 negative probe buckets, got %d", len(neg))
	}
	if neg[0].Category != "xss" || neg[0].Outcome != model.ProbeNearMiss || neg[0].Count != 1 {
		t.Fatalf("unexpected first bucket: %+v", neg[0])
	}
	if neg[1].Category != "xss" || neg[1].Outcome != model.ProbeNoSignal || neg[1].Count != 2 {
		t.Fatalf("unexpected second bucket: %+v", neg[1])
	}
}

func (r *datasetTestRepo) SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error { return nil }
func (r *datasetTestRepo) ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error) { return nil, nil }
