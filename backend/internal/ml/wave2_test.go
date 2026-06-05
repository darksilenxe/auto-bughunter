package ml

import (
	"context"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

// fakeRepo implements just enough of Repository to drive payoutSignals.
type fakeRepo struct {
	feedback []model.ReportFeedback
}

func (f *fakeRepo) ListCompletedJobs(_ context.Context, _ int) ([]*model.ScanJob, error) {
	return nil, nil
}
func (f *fakeRepo) GetAssetsByScanID(_ context.Context, _ string) ([]model.ScanAsset, error) {
	return nil, nil
}
func (f *fakeRepo) ListAuditEvents(_ context.Context, _ string) ([]model.ScanAuditEvent, error) {
	return nil, nil
}
func (f *fakeRepo) ListFeedback(_ context.Context, _ int) ([]model.ReportFeedback, error) {
	return f.feedback, nil
}
func (f *fakeRepo) ListProbeRecordsByCategory(_ context.Context, _ string, _ time.Time, _ int) ([]model.ProbeRecord, error) {
	return nil, nil
}

func TestPrioritizeFindingsExposesRationale(t *testing.T) {
	out := prioritizeFindings([]model.Finding{{
		ID:         "f1",
		Title:      "Reflected XSS",
		Severity:   model.SeverityHigh,
		Confidence: 0.8,
		Exploitability: &model.Exploitability{Reachable: true},
		DriftStatus: "new",
	}}, nil, nil)
	if len(out) != 1 {
		t.Fatalf("expected 1 prioritized finding, got %d", len(out))
	}
	r := out[0].Rationale
	if r == nil {
		t.Fatal("expected Rationale to be populated")
	}
	for _, key := range []string{"severity", "confidence", "exploitability", "drift", "score"} {
		if _, ok := r[key]; !ok {
			t.Errorf("rationale missing key %q (have %+v)", key, r)
		}
	}
	if out[0].Score <= 0 {
		t.Errorf("expected positive score, got %v", out[0].Score)
	}
}

func TestPayoutSignalsBoostMatchingProgram(t *testing.T) {
	repo := &fakeRepo{feedback: []model.ReportFeedback{
		{Category: "xss", ProgramName: "acme", Outcome: "accepted", PayoutUSD: 800, CreatedAt: time.Now()},
		{Category: "xss", ProgramName: "acme", Outcome: "accepted", PayoutUSD: 600, CreatedAt: time.Now()},
		{Category: "xss", ProgramName: "other", Outcome: "rejected", CreatedAt: time.Now()},
	}}
	s := &Service{}
	signals := s.payoutSignals(context.Background(), repo, "acme")
	if v := signals["xss"]; v <= 0 {
		t.Fatalf("expected positive payout boost for acme/xss, got %v (signals=%+v)", v, signals)
	}

	// Other-program findings should not produce a positive boost for acme.
	signalsOther := s.payoutSignals(context.Background(), repo, "ghost-program")
	if len(signalsOther) != 0 {
		t.Fatalf("expected no signals for unknown program, got %+v", signalsOther)
	}
}

func TestPrioritizeFindingsAppliesPayoutBoost(t *testing.T) {
	finding := model.Finding{ID: "f1", Title: "XSS", Category: "xss", Severity: model.SeverityMedium, Confidence: 0.5}
	baseline := prioritizeFindings([]model.Finding{finding}, nil, nil)
	boosted := prioritizeFindings([]model.Finding{finding}, nil, map[string]float64{"xss": 0.1})
	if len(baseline) != 1 || len(boosted) != 1 {
		t.Fatalf("expected single finding outputs")
	}
	if boosted[0].Score <= baseline[0].Score {
		t.Errorf("expected payout boost to raise score: baseline=%v boosted=%v", baseline[0].Score, boosted[0].Score)
	}
	if v, ok := boosted[0].Rationale["payout_boost"]; !ok || v <= 0 {
		t.Errorf("expected payout_boost in rationale > 0, got %v ok=%v", v, ok)
	}
}

func (r *fakeRepo) SaveAgentEvent(ctx context.Context, scanID string, event model.ScanEvent) error { return nil }
func (r *fakeRepo) ListAgentEvents(ctx context.Context, scanID string) ([]model.ScanEvent, error) { return nil, nil }
