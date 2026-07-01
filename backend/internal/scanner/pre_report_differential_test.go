package scanner

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"auto-bughunter/backend/internal/model"
)

func fakeResp() *http.Response {
	return &http.Response{StatusCode: 200}
}

func TestDifferentialReVerify_Confirmed(t *testing.T) {
	ResetDifferentialMetrics()
	execCalls := 0
	out := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		ProbeName:       "xss",
		OriginalPayload: "<script>alert(1)</script>",
		SafePayload:     "hello",
		Exec: func(ctx context.Context, payload string) (*http.Response, []byte, error) {
			execCalls++
			return fakeResp(), []byte("no signal here " + payload), nil
		},
		Oracle: func(ctx context.Context, variant string, resp *http.Response, body []byte) (bool, error) {
			return false, nil // neither control shows the signal
		},
	})
	if !out.Confirmed || !out.Ran {
		t.Fatalf("expected Confirmed+Ran, got %+v", out)
	}
	if execCalls != 2 {
		t.Fatalf("expected two exec calls (stripped + benign), got %d", execCalls)
	}
	m := GetDifferentialMetrics()
	if m.Total != 1 || m.Confirmed != 1 {
		t.Fatalf("metrics wrong: %+v", m)
	}
}

func TestDifferentialReVerify_StrippedShowsSignal(t *testing.T) {
	ResetDifferentialMetrics()
	out := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		Exec: func(ctx context.Context, payload string) (*http.Response, []byte, error) {
			return fakeResp(), []byte("always"), nil
		},
		Oracle: func(ctx context.Context, variant string, resp *http.Response, body []byte) (bool, error) {
			return true, nil // stripped control also shows signal -> FP
		},
	})
	if out.Confirmed {
		t.Fatal("must not confirm when stripped control reproduces signal")
	}
	if !out.PayloadStrippedSignal || out.Reason != "signal-in-stripped-control" {
		t.Fatalf("wrong outcome: %+v", out)
	}
	m := GetDifferentialMetrics()
	if m.FPStripped != 1 {
		t.Fatalf("expected FPStripped=1, got %+v", m)
	}
}

func TestDifferentialReVerify_BenignShowsSignal(t *testing.T) {
	ResetDifferentialMetrics()
	call := 0
	out := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		Exec: func(ctx context.Context, payload string) (*http.Response, []byte, error) {
			call++
			return fakeResp(), []byte(payload), nil
		},
		Oracle: func(ctx context.Context, variant string, resp *http.Response, body []byte) (bool, error) {
			// Stripped: no signal. Benign: yes signal (target reflects anything).
			return variant == "benign-random", nil
		},
	})
	if out.Confirmed {
		t.Fatal("must not confirm when benign control reproduces signal")
	}
	if !out.BenignRandomSignal || out.Reason != "signal-in-benign-control" {
		t.Fatalf("wrong outcome: %+v", out)
	}
	m := GetDifferentialMetrics()
	if m.FPBenign != 1 {
		t.Fatalf("expected FPBenign=1, got %+v", m)
	}
}

func TestDifferentialReVerify_ExecError(t *testing.T) {
	ResetDifferentialMetrics()
	out := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{
		Exec: func(ctx context.Context, payload string) (*http.Response, []byte, error) {
			return nil, nil, errors.New("boom")
		},
		Oracle: func(ctx context.Context, variant string, resp *http.Response, body []byte) (bool, error) {
			return false, nil
		},
	})
	if out.Confirmed || out.Reason != "exec-error" {
		t.Fatalf("expected exec-error, got %+v", out)
	}
	if GetDifferentialMetrics().ExecErrors != 1 {
		t.Fatal("expected ExecErrors=1")
	}
}

func TestDifferentialReVerify_NoOpWhenExecMissing(t *testing.T) {
	ResetDifferentialMetrics()
	out := DifferentialReVerify(context.Background(), DifferentialReVerifyInput{})
	if out.Ran || out.Confirmed {
		t.Fatalf("expected no-op, got %+v", out)
	}
	if GetDifferentialMetrics().Total != 0 {
		t.Fatal("expected no metrics recorded")
	}
}

func TestRequiresUnconditionalVerification(t *testing.T) {
	cases := map[model.Severity]bool{
		model.SeverityCritical: true,
		model.SeverityHigh:     true,
		model.SeverityMedium:   false,
		model.SeverityLow:      false,
		model.SeverityInfo:     false,
		"":                     false,
	}
	for s, want := range cases {
		if got := RequiresUnconditionalVerification(s); got != want {
			t.Fatalf("RequiresUnconditionalVerification(%q)=%v want %v", s, got, want)
		}
	}
}

func TestAttachDifferentialEvidence(t *testing.T) {
	f := &model.Finding{}
	AttachDifferentialEvidence(f, DifferentialReVerifyOutcome{Ran: true, Confirmed: true, Reason: "confirmed"})
	if f.EvidenceFields["differentialConfirmed"] != "true" {
		t.Fatalf("expected differentialConfirmed=true, got %+v", f.EvidenceFields)
	}
	if f.EvidenceFields["differentialReVerify"] != "confirmed" {
		t.Fatal("reason not attached")
	}
	// No-op when not ran
	f2 := &model.Finding{}
	AttachDifferentialEvidence(f2, DifferentialReVerifyOutcome{})
	if len(f2.EvidenceFields) != 0 {
		t.Fatal("must not attach when Ran is false")
	}
	// Nil-safe
	AttachDifferentialEvidence(nil, DifferentialReVerifyOutcome{Ran: true})
}
