package api

import (
	"strings"
	"testing"
	"time"

	"auto-bughunter/backend/internal/agent"
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

func TestValidateCampaignAuthorization_RequiresSignedApprovalOnActiveCampaign(t *testing.T) {
	err := validateCampaignAuthorization(model.AutomationCampaignUpsertRequest{
		Active: true,
		AuthorizationApproval: model.AuthorizationApproval{
			ApprovedBy:   "analyst@example.com",
			ApproverRole: "security-lead",
		},
		AuthorizationEvidence: []model.AuthorizationEvidence{
			{Type: "program_scope", Label: "scope page", URI: "https://program.example/scope"},
		},
	}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature validation error, got %v", err)
	}
}

func TestValidateCampaignAuthorization_AcceptsSignedApprovalEvidence(t *testing.T) {
	now := time.Now().UTC()
	err := validateCampaignAuthorization(model.AutomationCampaignUpsertRequest{
		Active: true,
		AuthorizationApproval: model.AuthorizationApproval{
			ApprovedBy:   "analyst@example.com",
			ApproverRole: "security-lead",
			Signature:    "signed-attestation",
			ApprovedAt:   now,
		},
		AuthorizationEvidence: []model.AuthorizationEvidence{
			{
				Type:   "program_scope",
				Label:  "scope page",
				URI:    "https://program.example/scope",
				SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}, now)
	if err != nil {
		t.Fatalf("expected valid authorization payload, got %v", err)
	}
}

func TestCampaignAuthorizationDigest_DeterministicAcrossEvidenceOrder(t *testing.T) {
	base := model.AutomationCampaign{
		ID:            "cmp-1",
		WorkspaceID:   "default",
		Target:        "https://example.com",
		PolicyPack:    "internal",
		PolicyVersion: 1,
		AuthorizationApproval: model.AuthorizationApproval{
			ApprovedBy:   "analyst@example.com",
			ApproverRole: "security-lead",
			Signature:    "signed-attestation",
			ApprovedAt:   time.Date(2026, 4, 21, 12, 0, 0, 0, time.UTC),
		},
		AuthorizationEvidence: []model.AuthorizationEvidence{
			{Type: "email", Label: "approval-email", URI: "https://mail.example/1"},
			{Type: "program_scope", Label: "scope-page", URI: "https://program.example/scope"},
		},
	}
	reordered := base
	reordered.AuthorizationEvidence = []model.AuthorizationEvidence{
		base.AuthorizationEvidence[1],
		base.AuthorizationEvidence[0],
	}
	if campaignAuthorizationDigest(base) != campaignAuthorizationDigest(reordered) {
		t.Fatal("expected digest to be deterministic regardless of evidence order")
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

func TestValidateGovernanceProfile_RejectsInvalidThresholds(t *testing.T) {
	err := validateGovernanceProfile(model.AutonomyGovernanceProfile{
		SuccessCriteria: map[string]model.AutonomySuccessCriteria{
			"prod": {FalsePositiveRateMax: 1.2},
		},
	})
	if err == nil {
		t.Fatal("expected governance profile validation error")
	}
}

func TestApplyGovernancePolicy_MapsFailureHandlingAndCanaryStage(t *testing.T) {
	t.Setenv("AUTOMATION_ENV_STAGE", "staging")
	options := model.ScanOptions{}
	got := applyGovernancePolicy(options, model.AutonomyGovernanceProfile{
		SuccessCriteria: map[string]model.AutonomySuccessCriteria{
			"staging": {
				NovelFindingsRateMin: 0.4,
				FalsePositiveRateMax: 0.2,
			},
		},
		FailureHandling: model.AutonomyFailureHandlingPolicy{
			MaxNoNoveltyRounds:          4,
			MaxConsecutiveFailureRounds: 3,
			BackoffMillis:               700,
			AutoRetryOnFailure:          true,
		},
		MemoryPolicy: model.AutonomyMemoryPolicy{
			RetentionDays: 45,
		},
		RolloutControl: model.AutonomyRolloutControl{
			CanaryPercentByStage: map[string]int{"staging": 0},
		},
		OperatorOverride: model.AutonomyOperatorOverridePolicy{
			AllowFallbackRerun: true,
		},
	})
	if got.AutonomyMaxNoNoveltyRounds != 4 || got.AutonomyMaxConsecutiveFailRounds != 3 {
		t.Fatalf("expected failure thresholds to be applied, got %+v", got)
	}
	if got.BackoffMillis != 700 {
		t.Fatalf("expected backoff millis 700, got %d", got.BackoffMillis)
	}
	if !got.AutonomyFallbackRerun {
		t.Fatal("expected fallback rerun to be enabled")
	}
	if got.MaxAutomationConcurrency != 1 {
		t.Fatalf("expected max automation concurrency to be capped to 1 on 0%% canary, got %d", got.MaxAutomationConcurrency)
	}
	if got.AutonomyMemoryRetentionDays != 45 {
		t.Fatalf("expected memory retention days to be mapped, got %d", got.AutonomyMemoryRetentionDays)
	}
	if got.AutonomyMinMarginalScore <= 0 {
		t.Fatalf("expected autonomy marginal score threshold to be set, got %f", got.AutonomyMinMarginalScore)
	}
	if got.AutonomyExplorationBudgetPercent != 0 {
		t.Fatalf("expected exploration budget disabled on 0%% canary, got %d", got.AutonomyExplorationBudgetPercent)
	}
}

func TestAllAgentRunsFailed(t *testing.T) {
	if allAgentRunsFailed(nil) {
		t.Fatal("empty outputs should not be treated as all failed")
	}
	if !allAgentRunsFailed([]agent.AgentOutput{{Status: "error"}, {Status: "error", TimedOut: true}}) {
		t.Fatal("expected all failed outputs to return true")
	}
	if allAgentRunsFailed([]agent.AgentOutput{{Status: "completed"}}) {
		t.Fatal("expected completed run to return false")
	}
}

func TestNormalizeAutomationMode_AcceptsCanary(t *testing.T) {
	if got := normalizeAutomationMode("canary"); got != "canary" {
		t.Fatalf("expected canary automation mode, got %s", got)
	}
}

func TestShouldEnableCanaryAutonomy_BoundsAndDeterministic(t *testing.T) {
	if shouldEnableCanaryAutonomy("https://example.com", 0) {
		t.Fatal("expected 0% canary to disable autonomy")
	}
	if !shouldEnableCanaryAutonomy("https://example.com", 100) {
		t.Fatal("expected 100% canary to enable autonomy")
	}
	a := shouldEnableCanaryAutonomy("https://example.com", 25)
	b := shouldEnableCanaryAutonomy("https://example.com", 25)
	if a != b {
		t.Fatal("expected canary autonomy selection to be deterministic per target")
	}
}

func TestApplyGovernancePolicy_CapsAutonomyCanaryPercentByStage(t *testing.T) {
	t.Setenv("AUTOMATION_ENV_STAGE", "staging")
	got := applyGovernancePolicy(model.ScanOptions{
		AutonomyCanaryPercent: 60,
	}, model.AutonomyGovernanceProfile{
		RolloutControl: model.AutonomyRolloutControl{
			CanaryPercentByStage: map[string]int{"staging": 10},
		},
	})
	if got.AutonomyCanaryPercent != 10 {
		t.Fatalf("expected stage canary percent cap to be applied, got %d", got.AutonomyCanaryPercent)
	}
}

func TestApplyGovernancePolicy_AppliesTenantRiskBudgetAndCostControls(t *testing.T) {
	got := applyGovernancePolicy(model.ScanOptions{
		AutonomyTenantTier:      "gold",
		MaxExploitAttempts:      3,
		MaxPerTargetConcurrency: 4,
	}, model.AutonomyGovernanceProfile{
		TenantRiskBudgets: map[string]model.AutonomyTenantRiskBudget{
			"gold": {
				MaxExploitAttempts:       1,
				MaxPerTargetConcurrency:  2,
				MaxAutomationConcurrency: 2,
				DailyScanLimit:           10,
			},
		},
		CostControls: model.AutonomyCostControls{
			MaxRoundCostUnits: 8,
			CostWeight:        0.4,
		},
	})
	if got.MaxExploitAttempts != 1 {
		t.Fatalf("expected tenant max exploit attempts=1, got %d", got.MaxExploitAttempts)
	}
	if got.MaxPerTargetConcurrency != 2 {
		t.Fatalf("expected tenant per-target concurrency=2, got %d", got.MaxPerTargetConcurrency)
	}
	if got.AutonomyMaxRoundCostUnits != 8 {
		t.Fatalf("expected max round cost units=8, got %d", got.AutonomyMaxRoundCostUnits)
	}
	if got.AutonomyCostWeight != 0.4 {
		t.Fatalf("expected cost weight=0.4, got %.2f", got.AutonomyCostWeight)
	}
}

func TestDeduplicateFindingsCrossAgent_NormalizedClustering(t *testing.T) {
	in := []model.Finding{
		{
			Category:   "Input-Validation",
			Title:      "Reflected XSS on search",
			Evidence:   "Payload reflected in q parameter at /search with script marker",
			Severity:   model.SeverityHigh,
			Confidence: 0.7,
			Sources:    []string{"scanner"},
		},
		{
			Category:   "input validation",
			Title:      "reflected xss on search",
			Evidence:   "PAYLOAD reflected in q parameter at /search with script marker",
			Severity:   model.SeverityHigh,
			Confidence: 0.9,
			Sources:    []string{"burp"},
		},
	}
	out, suppressed := deduplicateFindingsCrossAgent(in)
	if suppressed != 1 {
		t.Fatalf("expected 1 duplicate suppressed, got %d", suppressed)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 clustered finding, got %d", len(out))
	}
	if out[0].Confidence < 0.89 {
		t.Fatalf("expected highest-confidence representative, got %.2f", out[0].Confidence)
	}
	if !strings.Contains(out[0].EvidenceFields["duplicateClusterSize"], "2") {
		t.Fatalf("expected duplicate cluster size annotation, got %+v", out[0].EvidenceFields)
	}
}

func TestApplyEvidenceQualityTiers_AssignsTierAndAdjustsConfidence(t *testing.T) {
	out := applyEvidenceQualityTiers([]model.Finding{
		{
			Severity:          model.SeverityHigh,
			Confidence:        0.6,
			Evidence:          strings.Repeat("e", 140),
			ReproductionSteps: []string{"step1", "step2"},
			PoC:               "curl ...",
			AffectedURL:       "https://example.com",
		},
		{
			Severity:   model.SeverityLow,
			Confidence: 0.65,
			Evidence:   "short",
		},
	})
	if out[0].EvidenceQualityTier != "strong" {
		t.Fatalf("expected strong evidence tier, got %s", out[0].EvidenceQualityTier)
	}
	if out[0].Confidence < 0.8 {
		t.Fatalf("expected boosted confidence for strong evidence, got %.2f", out[0].Confidence)
	}
	if out[1].EvidenceQualityTier != "weak" {
		t.Fatalf("expected weak evidence tier, got %s", out[1].EvidenceQualityTier)
	}
	if out[1].Confidence >= 0.65 {
		t.Fatalf("expected reduced confidence for weak evidence, got %.2f", out[1].Confidence)
	}
}

func TestAdaptOptionsFromDrift_EnablesAdaptiveStrategy(t *testing.T) {
	options := model.ScanOptions{
		RescanIntervalMinutes:            60,
		AutonomyExplorationBudgetPercent: 5,
		MaxPerTargetConcurrency:          3,
	}
	adapted, note := adaptOptionsFromDrift([]model.Finding{
		{DriftStatus: "new", Severity: model.SeverityHigh},
		{DriftStatus: "changed", Severity: model.SeverityHigh},
	}, options)
	if note == "" {
		t.Fatal("expected adaptation note")
	}
	if !adapted.DeepScanOnHighSignal {
		t.Fatal("expected deep scan to be enabled")
	}
	if adapted.AutonomyExplorationBudgetPercent < 20 {
		t.Fatalf("expected exploration budget boost, got %d", adapted.AutonomyExplorationBudgetPercent)
	}
	if adapted.MaxPerTargetConcurrency != 1 {
		t.Fatalf("expected conservative per-target concurrency, got %d", adapted.MaxPerTargetConcurrency)
	}
}
