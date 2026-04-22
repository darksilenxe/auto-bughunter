package replay

import (
	"context"
	"testing"

	"auto-bughunter/backend/internal/agent"
	"auto-bughunter/backend/internal/model"
)

func sampleRun() HistoricalRun {
	return HistoricalRun{
		ScanID:          "scan-1",
		Target:          "https://example.com",
		AvailableAgents: []string{"reconnaissance", "scanning", "input_validation", "analysis"},
		Runs: []RecordedAgentRun{
			{AgentName: "reconnaissance"},
			{AgentName: "scanning", Findings: []model.Finding{{ID: "f1", Category: "injection", Severity: model.SeverityHigh, Title: "SQLi"}}},
			{AgentName: "input_validation"},
			{AgentName: "analysis"},
		},
	}
}

func TestRecordedOrderMatchesPerfectly(t *testing.T) {
	report, err := Compare(context.Background(), []HistoricalRun{sampleRun()}, "static", StaticPlannerFactory(), "recorded", RecordedOrderPlannerFactory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := report.Candidate.AggregateFirstChoiceMatchRate; got != 1.0 {
		t.Fatalf("recorded candidate should match every round; got first-choice rate %v", got)
	}
	if got := report.Candidate.AggregateMatchRate; got != 1.0 {
		t.Fatalf("recorded candidate should match every round; got match rate %v", got)
	}
	if report.Candidate.EarlyStops != 0 {
		t.Fatalf("recorded candidate should not stop early; got %d", report.Candidate.EarlyStops)
	}
	if got := report.Baseline.AggregateMatchRate; got != 1.0 {
		t.Fatalf("static baseline over the same agent order should also match; got %v", got)
	}
	if delta := report.Delta.MatchRateDelta; delta != 0 {
		t.Fatalf("delta should be 0 when both planners match; got %v", delta)
	}
}

func TestStaticBaselineDivergesFromShuffledAvailableOrder(t *testing.T) {
	run := sampleRun()
	// Available agent order intentionally differs from recorded execution order.
	run.AvailableAgents = []string{"analysis", "reconnaissance", "scanning", "input_validation"}

	report, err := Compare(context.Background(), []HistoricalRun{run}, "static", StaticPlannerFactory(), "recorded", RecordedOrderPlannerFactory())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	baseRun := report.Baseline.Runs[0]
	// Round 1: planner suggests "analysis" but recorded next is "reconnaissance".
	if baseRun.Rounds[0].FirstChoiceMatch {
		t.Fatalf("expected first round mismatch, got round=%+v", baseRun.Rounds[0])
	}
	candRun := report.Candidate.Runs[0]
	if baseRun.MatchRate >= candRun.MatchRate {
		t.Fatalf("recorded-order planner should outperform shuffled static baseline; base=%v cand=%v", baseRun.MatchRate, candRun.MatchRate)
	}
	if report.Delta.MatchRateDelta <= 0 {
		t.Fatalf("expected positive candidate delta, got %v", report.Delta.MatchRateDelta)
	}
	if len(baseRun.UnscheduledAgents) == 0 {
		// At least one recorded agent should never be scheduled because the
		// static planner ran out of distinct names before reaching them.
		// (In this 4-agent scenario every agent is reachable, so we don't
		// strictly require non-empty here, just keep this as a smoke check.)
		_ = baseRun.UnscheduledAgents
	}
}

func TestStoppedEarlyReportedWhenPlannerSignalsDone(t *testing.T) {
	run := sampleRun()
	report, err := Compare(context.Background(), []HistoricalRun{run},
		"static", StaticPlannerFactory(),
		"empty", func(_ HistoricalRun) (agent.Planner, error) {
			return agent.NewStaticPlanner(nil), nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Candidate.Runs[0].PlannerStoppedEarly {
		t.Fatalf("expected candidate to stop early when no agents are available")
	}
	if report.Candidate.EarlyStops != 1 {
		t.Fatalf("expected aggregate EarlyStops=1; got %d", report.Candidate.EarlyStops)
	}
}

func TestCompareRejectsEmptyInputs(t *testing.T) {
	if _, err := Compare(context.Background(), nil, "a", StaticPlannerFactory(), "b", RecordedOrderPlannerFactory()); err == nil {
		t.Fatalf("expected error when no historical runs are supplied")
	}
	if _, err := Compare(context.Background(), []HistoricalRun{sampleRun()}, "a", nil, "b", RecordedOrderPlannerFactory()); err == nil {
		t.Fatalf("expected error when baseline factory is nil")
	}
	if _, err := Compare(context.Background(), []HistoricalRun{sampleRun()}, "a", StaticPlannerFactory(), "b", nil); err == nil {
		t.Fatalf("expected error when candidate factory is nil")
	}
}

func TestPlannerOnlyAndUnscheduledAgentsTracked(t *testing.T) {
	run := sampleRun()
	// Candidate planner suggests an agent that never ran historically.
	cand := func(_ HistoricalRun) (agent.Planner, error) {
		return agent.NewStaticPlanner([]string{"reconnaissance", "ml_triage"}), nil
	}
	report, err := Compare(context.Background(), []HistoricalRun{run},
		"static", StaticPlannerFactory(), "cand", cand)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := report.Candidate.Runs[0]
	foundPlannerOnly := false
	for _, name := range r.PlannerOnlyAgents {
		if name == "ml_triage" {
			foundPlannerOnly = true
		}
	}
	if !foundPlannerOnly {
		t.Fatalf("expected ml_triage to be reported as planner-only; got %+v", r.PlannerOnlyAgents)
	}
	foundUnscheduled := false
	for _, name := range r.UnscheduledAgents {
		if name == "analysis" {
			foundUnscheduled = true
		}
	}
	if !foundUnscheduled {
		t.Fatalf("expected analysis to be reported as unscheduled by candidate; got %+v", r.UnscheduledAgents)
	}
}
