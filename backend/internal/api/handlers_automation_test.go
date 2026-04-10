package api

import (
	"testing"

	"auto-bughunter/backend/internal/model"
)

func TestEvaluatePolicyGateBlocksOnThresholds(t *testing.T) {
	s := &Server{gateHighBlock: 1, gateMedBlock: 3}
	result := s.evaluatePolicyGate([]model.Finding{
		{Title: "Critical auth bypass", Severity: model.SeverityHigh},
	})
	if result.Status != "blocked" {
		t.Fatalf("expected blocked gate status, got %s", result.Status)
	}
}

func TestTuneScanOptionsDisablesFlakyIntegrationsOnInstability(t *testing.T) {
	s := &Server{}
	options := model.ScanOptions{
		UseNucleiIntegration: true,
		UseSQLMapIntegration: true,
		UseFFUFIntegration:   true,
	}
	tuned := s.tuneScanOptions(options, &model.PersistentScanState{SessionInstability: 3}, nil)
	if tuned.UseNucleiIntegration || tuned.UseSQLMapIntegration || tuned.UseFFUFIntegration {
		t.Fatalf("expected flaky integrations to be disabled, got %+v", tuned)
	}
}
