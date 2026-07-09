package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestExceedsControlVariance(t *testing.T) {
	cases := []struct {
		observed, control float64
		want              bool
	}{
		{observed: 0, control: 0, want: false},
		{observed: 5, control: 0, want: false}, // below floor
		{observed: 100, control: 0, want: true},
		{observed: 50, control: 30, want: false}, // 50 < 2*30
		{observed: 100, control: 30, want: true}, // 100 > 60
	}
	for _, tc := range cases {
		got := ExceedsControlVariance(tc.observed, tc.control)
		if got != tc.want {
			t.Errorf("ExceedsControlVariance(%v,%v)=%v want %v", tc.observed, tc.control, got, tc.want)
		}
	}
}

func TestCaptureTwoControlBaselines(t *testing.T) {
	calls := 0
	fetch := func(ctx context.Context) (BaselineSample, error) {
		calls++
		return BaselineSample{
			Status:   200,
			Body:     "hello 550e8400-e29b-41d4-a716-446655440000 world",
			Duration: 100 * time.Millisecond,
		}, nil
	}
	bc, err := CaptureTwoControlBaselines(context.Background(), fetch)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 fetches, got %d", calls)
	}
	if !bc.StatusStable {
		t.Errorf("expected stable status")
	}
	if bc.BodyByteVariance != 0 {
		t.Errorf("bodies with only UUID differences should normalize to zero variance; got %d", bc.BodyByteVariance)
	}
	// The normalized body should not contain the UUID.
	if strings.Contains(bc.First.Body, "550e8400-") {
		t.Errorf("expected body to be normalized")
	}
}

func TestCaptureTwoControlBaselines_NilFetcher(t *testing.T) {
	if _, err := CaptureTwoControlBaselines(context.Background(), nil); err == nil {
		t.Error("expected error for nil fetcher")
	}
}

func TestSubmitVerifiedFinding_Suppress_MissingProofAndPoC(t *testing.T) {
	ResetVerificationMetrics()
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:       "sqli-1",
			Category: "sqli",
			Title:    "possible sqli",
			Severity: model.Severity("High"),
		},
		Signals:   []EvidenceSignal{EvidenceStatusDelta},
		ProbeName: "test-sqli",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if !out.Suppressed {
		t.Errorf("expected suppression for SQLi without PoC; got %+v", out)
	}
	metrics := GetVerificationMetrics()
	if metrics.Suppressed == 0 || metrics.Total == 0 {
		t.Errorf("expected metrics to record suppression; got %+v", metrics)
	}
}

func TestSubmitVerifiedFinding_Verify_PoCReplaySucceeds(t *testing.T) {
	ResetVerificationMetrics()
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:                "sqli-2",
			Category:          "sqli",
			Title:             "SQL injection in id",
			AffectedURL:       "https://target/api/user",
			AffectedParameter: "id",
			Evidence:          "SQL syntax error and time-based delay observed",
			Severity:          model.Severity("High"),
			PoC:               "curl 'https://target/api/user?id=1%20AND%20SLEEP(3)'",
			EvidenceFields:    map[string]string{"timingDifferentialMs": "3100"},
		},
		Signals: []EvidenceSignal{EvidenceTimingDelta, EvidenceErrorSignal, EvidenceStatusDelta},
		PoCReplay: func(ctx context.Context) (bool, string, error) {
			return true, "GET /api/user?id=1%20AND%20SLEEP(3) → 200 in 3120ms", nil
		},
		ProbeName: "test-sqli",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if !out.Verified {
		t.Errorf("expected verified; got %+v", out)
	}
	if !out.PoCReplayed || !out.PoCSuccess {
		t.Errorf("expected PoC replay success recorded")
	}
	if out.EmittedFinding.EvidenceFields["preReport.pocTranscript"] == "" {
		t.Errorf("expected PoC transcript on emitted finding")
	}
	if !strings.Contains(out.EmittedFinding.Evidence, "PoC replay:") {
		t.Errorf("expected PoC replay note in evidence; got %q", out.EmittedFinding.Evidence)
	}
	if len(out.EmittedFinding.ProofArtifacts) == 0 {
		t.Errorf("expected proof artifact attached")
	}
}

func TestSubmitVerifiedFinding_Suppress_PoCReplayFails(t *testing.T) {
	ResetVerificationMetrics()
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:       "xss-1",
			Category: "xss",
			Title:    "reflected xss",
			Severity: model.Severity("Medium"),
		},
		Signals: []EvidenceSignal{EvidenceReflection, EvidenceSinkObserved},
		PoCReplay: func(ctx context.Context) (bool, string, error) {
			return false, "marker not reflected", nil
		},
		ProbeName: "test-xss",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if !out.Suppressed {
		t.Errorf("expected suppression on failed PoC replay; got %+v", out)
	}
	if out.Reason != "poc-replay-failed" {
		t.Errorf("expected reason poc-replay-failed; got %q", out.Reason)
	}
}

func TestSubmitVerifiedFinding_Downgrade_PartialEvidence(t *testing.T) {
	ResetVerificationMetrics()
	// XSS with a full proof-policy hit but only 1 evidence signal (min is 2)
	// and no PoC replay hook → downgraded.
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:                "xss-2",
			Category:          "xss",
			Title:             "possible reflected xss",
			AffectedURL:       "https://t/page",
			AffectedParameter: "q",
			Evidence:          "payload reflected unsanitized into script context",
			PoC:               "https://t/page?q=<svg/onload=alert(1)>",
			Severity:          model.Severity("High"),
		},
		Signals:               []EvidenceSignal{EvidenceReflection},
		AllowNoReplayEmission: true,
		ProbeName:             "test-xss",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if !out.Downgraded {
		t.Errorf("expected downgrade for partial evidence; got %+v", out)
	}
	if out.EmittedFinding.Severity == model.Severity("High") {
		t.Errorf("severity should have been lowered from High; got %q", out.EmittedFinding.Severity)
	}
}

func TestSubmitVerifiedFinding_BaselineVarianceGuard(t *testing.T) {
	ResetVerificationMetrics()
	// Body delta below baseline variance should be discounted, dropping
	// evidence hit count below the minimum → suppression.
	cand := VerifyCandidate{
		Finding: model.Finding{
			ID:       "xss-3",
			Category: "xss",
			Title:    "reflected candidate",
			Severity: model.Severity("Low"),
		},
		Signals:          []EvidenceSignal{EvidenceBodyDelta, EvidenceTimingDelta},
		BaselineVariance: 100,
		ObservedDelta:    50, // below 2x variance
		ProbeName:        "test-xss",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if out.EvidenceHits != 0 {
		t.Errorf("expected all baseline-guarded signals to be dropped; hits=%d", out.EvidenceHits)
	}
	if !out.Suppressed {
		t.Errorf("expected suppression; got %+v", out)
	}
}

func TestSubmitVerifiedFinding_MetricsIncrement(t *testing.T) {
	ResetVerificationMetrics()
	for i := 0; i < 3; i++ {
		SubmitVerifiedFinding(context.Background(), VerifyCandidate{
			Finding:   model.Finding{ID: "x", Category: "sqli"},
			ProbeName: "p1",
		})
	}
	m := GetVerificationMetrics()
	if m.Total != 3 {
		t.Errorf("expected 3 total; got %d", m.Total)
	}
	if m.ByProbe["p1"].Total != 3 {
		t.Errorf("expected per-probe total 3; got %+v", m.ByProbe)
	}
	if m.ByCategory["sqli"].Total != 3 {
		t.Errorf("expected per-category total 3; got %+v", m.ByCategory)
	}
}

func TestSubmitVerifiedFinding_PoCReplayError_TreatedAsFailure(t *testing.T) {
	ResetVerificationMetrics()
	cand := VerifyCandidate{
		Finding: model.Finding{ID: "xxe-1", Category: "xxe", Title: "xxe"},
		PoCReplay: func(ctx context.Context) (bool, string, error) {
			return false, "", errors.New("network unreachable")
		},
		ProbeName: "test-xxe",
	}
	out := SubmitVerifiedFinding(context.Background(), cand)
	if out.PoCSuccess {
		t.Errorf("errored replay must not count as success")
	}
	if !out.Suppressed {
		t.Errorf("expected suppression on errored replay for strict category")
	}
}

func TestDowngradeSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "High",
		"high":     "Medium",
		"medium":   "Low",
		"low":      "Info",
		"info":     "info",
	}
	for in, want := range cases {
		got := string(downgradeSeverity(model.Severity(in)))
		if got != want {
			t.Errorf("downgradeSeverity(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRandomMarker_UniqueAndPrefixed(t *testing.T) {
	a := RandomMarker()
	b := RandomMarker()
	if a == b {
		t.Errorf("expected different markers; both were %q", a)
	}
	if !strings.HasPrefix(a, "abh_") {
		t.Errorf("expected abh_ prefix; got %q", a)
	}
	if len(a) < 8 {
		t.Errorf("marker too short: %q", a)
	}
}
