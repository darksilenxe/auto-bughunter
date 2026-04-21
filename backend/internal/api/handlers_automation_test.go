package api

import (
	"testing"
	"time"

	"auto-bughunter/backend/internal/model"
)

func TestEvaluatePolicyGateBlocksOnThresholds(t *testing.T) {
	s := &Server{gateHighBlock: 1, gateMedBlock: 3}
	result := s.evaluatePolicyGate([]model.Finding{
		{Title: "Critical auth bypass", Severity: model.SeverityHigh},
	}, "internal")
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

func TestComputeNextCampaignRun_CronTimezone(t *testing.T) {
	now := time.Date(2026, 4, 21, 1, 59, 0, 0, time.UTC)
	next := computeNextCampaignRun(now, model.AutomationCampaignUpsertRequest{
		IntervalMin:   60,
		ScheduleType:  "cron",
		ScheduleValue: "America/New_York|0 2 * * *",
	})
	expected := time.Date(2026, 4, 21, 6, 0, 0, 0, time.UTC) // 02:00 EDT
	if !next.Equal(expected) {
		t.Fatalf("expected %s, got %s", expected.Format(time.RFC3339), next.Format(time.RFC3339))
	}
}

func TestResolveCampaignNextRunAfterDispatch_MisfirePolicy(t *testing.T) {
	now := time.Date(2026, 4, 21, 2, 3, 0, 0, time.UTC)
	campaign := model.AutomationCampaign{
		IntervalMin:   5,
		ScheduleType:  "interval",
		NextRunAt:     time.Date(2026, 4, 21, 1, 50, 0, 0, time.UTC),
		ScheduleValue: "",
	}

	t.Setenv("AUTOMATION_MISFIRE_POLICY", "skip")
	nextSkip := resolveCampaignNextRunAfterDispatch(now, campaign)
	if !nextSkip.After(now) {
		t.Fatalf("skip policy should schedule in the future, got %s", nextSkip.Format(time.RFC3339))
	}

	t.Setenv("AUTOMATION_MISFIRE_POLICY", "catch-up")
	nextCatch := resolveCampaignNextRunAfterDispatch(now, campaign)
	if !nextCatch.After(now) {
		t.Fatalf("catch-up policy should advance to next future slot, got %s", nextCatch.Format(time.RFC3339))
	}
	if !nextCatch.Before(nextSkip) {
		t.Fatalf("expected catch-up next run (%s) to be earlier than skip (%s)", nextCatch.Format(time.RFC3339), nextSkip.Format(time.RFC3339))
	}
}

func TestValidateCampaignSchedule_StrictValidation(t *testing.T) {
	if err := validateCampaignSchedule("cron", "UTC|*/15 * * * *", "00:00-23:59", []string{"02:00-02:30"}); err != nil {
		t.Fatalf("expected valid cron schedule, got error: %v", err)
	}
	if err := validateCampaignSchedule("cron", "UTC|bad expr", "", nil); err == nil {
		t.Fatal("expected invalid cron expression to fail")
	}
	if err := validateCampaignSchedule("daily", "No/Such|02:30", "", nil); err == nil {
		t.Fatal("expected invalid timezone to fail")
	}
}

func TestAutomationMisfirePolicy_DefaultAndCatchUp(t *testing.T) {
	t.Setenv("AUTOMATION_MISFIRE_POLICY", "")
	if got := automationMisfirePolicy(); got != "skip" {
		t.Fatalf("expected default misfire policy skip, got %s", got)
	}
	t.Setenv("AUTOMATION_MISFIRE_POLICY", "catch-up")
	if got := automationMisfirePolicy(); got != "catch-up" {
		t.Fatalf("expected catch-up misfire policy, got %s", got)
	}
}

func TestNormalizePolicyPackName(t *testing.T) {
	if got := normalizePolicyPackName("  "); got != "internal" {
		t.Fatalf("expected default policy pack internal, got %s", got)
	}
	if got := normalizePolicyPackName("  CUSTOM-Pack "); got != "custom-pack" {
		t.Fatalf("expected normalized policy pack custom-pack, got %s", got)
	}
}

func TestMaxDuration(t *testing.T) {
	if got := maxDuration(5*time.Second, 2*time.Second); got != 5*time.Second {
		t.Fatalf("expected 5s, got %s", got)
	}
	if got := maxDuration(1*time.Second, 3*time.Second); got != 3*time.Second {
		t.Fatalf("expected 3s, got %s", got)
	}
}
