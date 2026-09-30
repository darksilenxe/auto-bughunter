package scanner

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

// TestSafeProbeCallRecoversPanic verifies safeProbeCall converts a panic
// raised by a probe into a nil result (the probe is skipped) instead of
// letting it unwind past Scan and abort every other probe still queued
// behind it, as well as discard the findings already collected for the
// target. See the safeProbeCall doc comment in scanner.go.
func TestSafeProbeCallRecoversPanic(t *testing.T) {
	s := &Service{}

	got := s.safeProbeCall("panickyProbe", func() []model.Finding {
		panic("simulated probe bug")
	})
	if got != nil {
		t.Fatalf("expected nil findings from a panicking probe, got %+v", got)
	}
}

// TestSafeProbeCallPassesThroughNormalResults verifies safeProbeCall does
// not alter the result of a probe that completes normally.
func TestSafeProbeCallPassesThroughNormalResults(t *testing.T) {
	s := &Service{}
	want := []model.Finding{{ID: "f1", Category: "x", Severity: model.SeverityLow, Title: "t", Evidence: "e"}}

	got := s.safeProbeCall("normalProbe", func() []model.Finding {
		return want
	})
	if len(got) != 1 || got[0].ID != "f1" {
		t.Fatalf("expected safeProbeCall to pass through the probe's findings unchanged, got %+v", got)
	}
}

// TestSafeProbeCallPanicWithNonStringValue verifies safeProbeCall also
// recovers panics whose value is not a string (e.g. a nil-pointer
// dereference reported as a runtime.Error).
func TestSafeProbeCallPanicWithNonStringValue(t *testing.T) {
	s := &Service{}
	var bad *Service

	got := s.safeProbeCall("nilDerefProbe", func() []model.Finding {
		_ = bad.httpClient.Timeout // triggers a nil pointer dereference panic
		return nil
	})
	if got != nil {
		t.Fatalf("expected nil findings after recovering a nil-pointer panic, got %+v", got)
	}
}
