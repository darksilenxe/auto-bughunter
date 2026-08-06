package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"auto-bughunter/backend/internal/scanner"
)

func TestHandleProbeHealth_GetAll(t *testing.T) {
	t.Parallel()
	// Populate the global ledger with some test data.
	old := scanner.GlobalProbeOutcomeLedger()
	testLedger := scanner.NewProbeOutcomeLedger()
	testLedger.ThrottleMinSamples = 5
	testLedger.ThrottleFPThreshold = 0.30
	testLedger.ThrottleWindowSize = 50
	// We can't swap the singleton in tests without test-exported helpers, so
	// just exercise the handler against the real (possibly empty) ledger.
	_ = old

	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/probe-health", nil)
	srv.handleProbeHealth(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON, got: %s", rec.Body.String())
	}
	if _, ok := body["probes"]; !ok {
		t.Errorf("expected 'probes' key in response, got: %v", body)
	}
	if _, ok := body["thresholds"]; !ok {
		t.Errorf("expected 'thresholds' key in response, got: %v", body)
	}
}

func TestHandleProbeHealth_GetSingleProbeNotFound(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/probe-health?probe=does_not_exist_xyz", nil)
	srv.handleProbeHealth(rec, req)
	if rec.Code != 404 {
		t.Fatalf("expected 404 for unknown probe, got %d", rec.Code)
	}
}

func TestHandleProbeHealth_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	srv := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/probe-health", nil)
	srv.handleProbeHealth(rec, req)
	if rec.Code != 405 {
		t.Fatalf("expected 405 for POST, got %d", rec.Code)
	}
}
